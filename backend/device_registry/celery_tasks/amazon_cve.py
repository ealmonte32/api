import logging
import gzip
import time
import xml.dom.minidom
from urllib.request import urlopen, Request

from django.conf import settings

import redis

from device_registry.models import DebPackage, Vulnerability

logger = logging.getLogger('django')


def fetch_vulnerabilities():
    logger.info('started.')
    vulnerabilities = {}
    mirror_url = 'https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list'
    response = urlopen(Request(mirror_url))
    mirror_list = response.read()
    for mirror in mirror_list.decode().splitlines():
        url = mirror + '/repodata/updateinfo.xml.gz'
        logger.info('fetching data...')
        response = urlopen(Request(url))
        compressed_data = response.read()
        data = gzip.decompress(compressed_data).decode()
        xmldoc = xml.dom.minidom.parseString(data)
        logger.info('parsing data...')
        for update in xmldoc.getElementsByTagName('update'):
            severity = update.getElementsByTagName('severity')[0].firstChild.data
            alas = update.getElementsByTagName('id')[0].firstChild.data
            for ref in update.getElementsByTagName('reference'):
                for pkg in update.getElementsByTagName('package'):
                    cve = ref.getAttribute('id')
                    pkg_name = pkg.getAttribute('name')
                    pkg_epoch = pkg.getAttribute('epoch')
                    pkg_version = pkg.getAttribute('version')
                    pkg_release = pkg.getAttribute('release')
                    pkg_severity = {'low': Vulnerability.Urgency.LOW,
                                    'medium': Vulnerability.Urgency.MEDIUM,
                                    'important': Vulnerability.Urgency.HIGH,
                                    'critical': Vulnerability.Urgency.HIGH}[severity]
                    full_version = f'{pkg_epoch}:{pkg_version}-{pkg_release}'
                    print((cve, severity, pkg_name, pkg_epoch, pkg_version, pkg_release))
                    key = (cve, pkg_name)
                    if key in vulnerabilities:
                        v = vulnerabilities[key]
                        if v.urgency < pkg_severity:
                            v.urgency = pkg_severity
                        if Vulnerability.RpmVersion(v.unstable_version) < Vulnerability.RpmVersion(full_version):
                            logger.error(f'{alas} {pkg_name}: {v.unstable_version} < {full_version}')
                            v.unstable_version = full_version
                    else:
                        vulnerabilities[key] = Vulnerability(
                            name=cve,
                            package=pkg_name,
                            unstable_version=full_version,
                            other_versions=[],
                            is_binary=False,
                            urgency=pkg_severity,
                            fix_available=True,
                            os_release_codename='amzn2'
                        )
        logger.info('saving data...')
        redis_conn = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD)
        with redis_conn.lock('vulns_lock', timeout=60 * 15, blocking_timeout=60 * 5):
            logger.info('lock acquired.')
            time.sleep(60 * 3)  # Sleep 3m to allow all running `update_packages_vulnerabilities` tasks finish.
            logger.info('sleep ended.')
            Vulnerability.objects.filter(os_release_codename='amzn2').delete()
            Vulnerability.objects.bulk_create(vulnerabilities.values())
            DebPackage.objects.filter(os_release_codename='amzn2').update(processed=False)
        logger.info('finished.')
        return len(vulnerabilities)