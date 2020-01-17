import logging
import os
import sys
from pathlib import Path
from itertools import chain
import time

from django.conf import settings

import dateutil.parser
import redis
from git import Repo

from device_registry.models import Vulnerability, DebPackage, UBUNTU_SUITES

logger = logging.getLogger('django')

supported_releases = list(UBUNTU_SUITES)

# All EOL, ppa overlays, and ESM releases
ignored_releases = [
    'dapper', 'edgy', 'feisty', 'gutsy', 'hardy', 'intrepid', 'jaunty',
    'karmic', 'maverick', 'natty', 'oneiric', 'precise', 'precise/esm',
    'quantal', 'lucid', 'raring', 'saucy', 'trusty', 'trusty/esm', 'utopic',
    'vivid', 'vivid/stable-phone-overlay', 'vivid/ubuntu-core', 'wily',
    'yakkety', 'zesty', 'artful', 'cosmic', 'disco', 'eoan'
]

all_releases = supported_releases + ignored_releases
ignored_package_fields = [
    'Patches', 'devel', 'upstream', 'Assigned-to', 'product', 'snap', 'Priority', 'Tags'
]


def get_cve_url(filepath):
    """ returns a url to CVE data from a filepath """
    path = os.path.realpath(filepath).split(os.sep)
    url = "http://people.canonical.com/~ubuntu-security/cve"
    cve = path[-1]
    year = cve.split('-')[1]
    return "%s/%s/%s.html" % (url, year, cve)


# Taken from ubuntu-cve-tracker/scripts/generate-oval.py
def parse_cve_file(filepath):
    """ parse CVE data file into a dictionary """
    from cve_lib import (meta_kernels, kernel_srcs, kernel_package_abi, kernel_package_version)
    debug_level = 0

    cve_header_data = {
        'Candidate': '',
        'CRD': '',
        'PublicDate': '',
        'PublicDateAtUSN': '',
        'References': [get_cve_url(filepath)],
        'Description': '',
        'Ubuntu-Description': '',
        'Notes': '',
        'Mitigation': '',
        'Bugs': [],
        'Priority': '',
        'Discovered-by': '',
        'Assigned-to': '',
        'Unknown-Fields': [],
        'Source-note': filepath
    }

    key = ''
    values = []
    in_header = True
    packages = {}
    current_package = ''
    packages_section_keys = all_releases + ['Patches', 'Tags', 'upstream']

    with open(filepath) as f:
        for line in f:
            if line.strip().startswith('#') or line.strip().startswith('--'):
                continue

            if in_header and line.split('_', 1)[0] in packages_section_keys:
                in_header = False

            # Note: some older cves include Priority_package in header section
            if in_header and not line.startswith('Priority_'):
                if line.startswith(' '):
                    values.append(line.strip())
                else:
                    if key and key in cve_header_data and \
                            isinstance(cve_header_data[key], str):
                        if cve_header_data[key]:
                            cve_header_data[key] = cve_header_data[key] + ' ' + \
                                                   ' '.join(values)
                        else:
                            cve_header_data[key] = ' '.join(values)
                    elif key and key in cve_header_data and \
                            isinstance(cve_header_data[key], list):
                        cve_header_data[key] = cve_header_data[key] + values
                    elif key:
                        print('Unknown header field "{0}" found in {1} '.format(key, filepath))
                        cve_header_data['Unknown-Fields'].append(
                            {key: ' '.join(values)})

                    if line.strip() == '':
                        continue

                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    values = [value] if value else []

            else:
                # we're in the packages section
                if line.startswith(' '):
                    continue

                line = line.strip()
                if not line:
                    current_package = ''
                    continue

                keys, value = line.split(':', 1)
                value = value.strip()
                keys = keys.split('_', 1)
                key = keys[0]
                if len(keys) == 2:
                    package = keys[1]
                    current_package = package
                else:
                    package = current_package

                if key in ignored_package_fields or key not in supported_releases:
                    # TODO: ignore -edge kernels?
                    continue

                if package not in packages:
                    packages[package] = {}

                if key in supported_releases:
                    if key in packages[package]:
                        print('Duplicate package field key "{0}" found in "{1}" package in {2}'.format(key, package,
                                                                                                       filepath))
                    package_status = parse_package_status(key, package, value, filepath)
                    if package_status['status'] not in ['not-applicable', 'not-vulnerable', 'unknown']:
                        packages[package][key] = package_status
                elif key not in ['Priority', 'Tags']:
                    print('Unknown package field "{0}" in {0}_{1} in "{2}"'.format(key, package, filepath))

    # remove packages with no supported releases
    packages = {
        name: package
        for name, package in packages.items() if package
    }

    # add supplemental packages; usually kernels only need this special case.
    for package in [name for name in packages if name in kernel_srcs]:
        for release in [
            rel for rel in packages[package]
            if packages[package][rel]['status'] not in ['not-applicable', 'not-vulnerable', 'unknown']
        ]:
            # add meta package
            meta_pkg = meta_kernels.get_meta(release, package, quiet=(debug_level < 1))
            if meta_pkg:
                if meta_pkg not in packages:
                    packages[meta_pkg] = {}
                if release not in packages[meta_pkg]:
                    kernel_status = packages[package][release]
                    # kernel meta packages have a different versioning
                    # scheme derived from the kernel version + kernel abi
                    meta_version = None
                    if 'fix-version' in kernel_status:
                        meta_version = '%s.%s' % (kernel_package_version(kernel_status['fix-version']),
                                                  kernel_package_abi(kernel_status['fix-version']))
                    packages[meta_pkg][release] = \
                        duplicate_package_status(kernel_status, override_version=meta_version)
            # add signed package
            signed_pkg = meta_kernels.get_signed(release, package, quiet=(debug_level < 1))
            if signed_pkg:
                if signed_pkg not in packages:
                    packages[signed_pkg] = {}
                if release not in packages[signed_pkg]:
                    packages[signed_pkg][release] = \
                        duplicate_package_status(packages[package][release])

    return {'header': cve_header_data, 'packages': packages}


# Taken from ubuntu-cve-tracker/scripts/generate-oval.py
def parse_package_status(release, package, status_text, filepath):
    """
    parse ubuntu package status string format:
          <status code> (<version/notes>)
    :return: dict where
          'status'        : '<not-applicable | unknown | vulnerable | fixed>',
          'fix-version'   : '<version with issue fixed, if applicable>'
    """

    # break out status code and detail
    status_sections = status_text.strip().split(' ', 1)
    code = status_sections[0].strip().lower()
    detail = status_sections[1].strip('()') if len(status_sections) > 1 else None

    status = 'unknown'
    fix_version = None

    if code == 'dne':
        status = 'not-applicable'
    elif code in ['ignored', 'pending', 'deferred', 'needed', 'needs-triage']:
        status = 'vulnerable'
    elif code == 'not-affected':
        status = 'not-vulnerable'
    elif code in ['released', 'released-esm']:
        # if there isn't a release version, then just mark
        # as vulnerable to test for package existence
        if not detail:
            status = 'vulnerable'
        else:
            status = 'fixed'
            fix_version = detail
    else:
        print('Unsupported status "{0}" in {1}_{2} in "{3}". Setting to "unknown".'
              .format(code, release, package, filepath))

    result = {'status': status}
    if fix_version is not None:
        result['fix-version'] = fix_version
    return result


def duplicate_package_status(original_status, override_version=None):
    """
    Given a status generated by parse_package_status(), duplicate it for a different source package.
    :param original_status: the status to clone
    :param override_version: the cloned package version (different)
    :return: new status (dict)
    """
    copied_status = {'status': original_status['status']}
    if override_version:
        copied_status['fix-version'] = override_version
    elif 'fix-version' in original_status:
        copied_status['fix-version'] = original_status['fix-version']

    return copied_status


def parse_cve_directory(repo_path: Path):
    return [parse_cve_file(f) for f in chain(repo_path.glob('active/CVE-*'), repo_path.glob('retired/CVE-*'))]


def clone_cve_repo(repo_path: Path):
    if repo_path.exists():
        repo = Repo(repo_path)
        if repo.head.ref.name != 'master':
            raise RuntimeError('ubuntu-cve-tracker repo is not on master branch')
    else:
        Repo.clone_from('https://git.launchpad.net/ubuntu-cve-tracker', repo_path,
                        branch='master', multi_options=['--depth=1'])


def fetch_vulnerabilities():
    logger.info('started.')
    # Try to acquire the lock.
    # Spend trying 5m max.
    # In case of success set the lock's timeout to 15m.
    redis_conn = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD)
    with redis_conn.lock('vulns_lock', timeout=60 * 15, blocking_timeout=60 * 5):
        logger.info('lock acquired.')
        time.sleep(60 * 3)  # Sleep 3m to allow all running `update_packages_vulnerabilities` tasks finish.
        logger.info('sleep ended.')
        ubuntu_cve_tracker_path = Path('/tmp/ubuntu-cve-tracker')
        # Needed by parse_cve_directory for importing cve_lib.
        sys.path.append(str(ubuntu_cve_tracker_path / 'scripts'))

        logger.info('cloning ubuntu-cve-tracker...')
        clone_cve_repo(ubuntu_cve_tracker_path)
        logger.info('parsing ubuntu-cve-tracker...')
        vulnerabilities = []
        parsed = parse_cve_directory(ubuntu_cve_tracker_path)
        for vuln in parsed:
            header, details = vuln['header'], vuln['packages']
            name = header['Candidate']
            for package, releases in details.items():
                for codename, info in releases.items():
                    status, fix_version = info['status'], info.get('fix-version', '')
                    v = Vulnerability(
                        name=name,
                        package=package,
                        unstable_version=fix_version,
                        other_versions=[],
                        is_binary=False,
                        urgency={
                            'low': Vulnerability.Urgency.LOW,
                            'medium': Vulnerability.Urgency.MEDIUM,
                            'high': Vulnerability.Urgency.HIGH,
                        }.get(header['Priority'], Vulnerability.Urgency.NONE),
                        pub_date=dateutil.parser.parse(header['PublicDate']),
                        remote=None,
                        fix_available=(status == 'fixed'),
                        os_release_codename=codename
                    )
                    vulnerabilities.append(v)

        logger.info('saving data...')
        Vulnerability.objects.filter(os_release_codename__in=UBUNTU_SUITES).delete()
        Vulnerability.objects.bulk_create(vulnerabilities, batch_size=10000)
        DebPackage.objects.filter(os_release_codename__in=UBUNTU_SUITES).update(processed=False)
        logger.info('finished.')
        return len(vulnerabilities)
