import logging
import zlib
from itertools import groupby
from urllib.request import urlopen, Request
import os

from celery import shared_task
import redis

from device_registry.models import Vulnerability, DebPackage, DEBIAN_SUITES

logger = logging.getLogger('django')


# Should live 10m max and throw and exception to Sentry when killed.
@shared_task(soft_time_limit=60 * 10, time_limit=60 * 10 + 5)  # Should live 10m max.
def fetch_vulnerabilities():
    """
    Download vulnerability index from Debian Security Tracker, parse it and store in db.
    """
    redis_conn = redis.Redis(host=os.getenv('REDIS_HOST', 'redis'), port=int(os.getenv('REDIS_PORT', '6379')),
                             password=os.getenv('REDIS_PASSWORD'))
    # Try to acquire the lock.
    # Spend trying 6m max.
    # In case of success set the lock's timeout to 5m.
    with redis_conn.lock('vulns_lock', timeout=60 * 5, blocking_timeout=60 * 6):
        vulnerabilities = []
        for suite in DEBIAN_SUITES:  # Only Debian actual suites currently supported.
            logger.info('fetching data for "%s".' % suite)
            url = "https://security-tracker.debian.org/tracker/debsecan/release/1/" + suite
            response = urlopen(Request(url))
            compressed_data = response.read()
            data = zlib.decompress(compressed_data).decode()

            lines = data.split('\n')
            lines_split = groupby(lines, lambda e: e.strip() == '')
            lists = [list(group) for k, group in lines_split if not k]

            vuln_name_list, packages_list = lists[:2]
            if vuln_name_list.pop(0) != 'VERSION 1':
                logger.error('ERROR')
            vuln_names = [(name, desc) for (name, flags, desc) in map(lambda x: x.split(',', 2), vuln_name_list)]

            logger.info('parsing data..')
            for package_desc in packages_list:
                package, vnum, flags, unstable_version, other_versions = package_desc.split(',', 4)

                other_versions = other_versions.split(' ')
                if other_versions == ['']:
                    other_versions = []
                v = Vulnerability(name=vuln_names[int(vnum)][0],
                                  package=package,
                                  unstable_version=unstable_version,
                                  other_versions=other_versions,
                                  is_binary=flags[0] == 'B',
                                  urgency={' ': Vulnerability.Urgency.NONE,
                                           'L': Vulnerability.Urgency.LOW,
                                           'M': Vulnerability.Urgency.MEDIUM,
                                           'H': Vulnerability.Urgency.HIGH
                                           }[flags[1]],
                                  remote={'?': None,
                                          'R': True,
                                          ' ': False
                                          }[flags[2]],
                                  fix_available=flags[3] == 'F',
                                  os_release_codename=suite)
                vulnerabilities.append(v)

        logger.info('saving data...')
        # with transaction.atomic():
        Vulnerability.objects.all().delete()
        Vulnerability.objects.bulk_create(vulnerabilities, batch_size=10000)
        DebPackage.objects.update(processed=False)
