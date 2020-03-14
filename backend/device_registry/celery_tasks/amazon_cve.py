import logging
import gzip
import xml.dom.minidom
from urllib.request import urlopen, Request

from device_registry.models import DebPackage, Vulnerability

# RSS: https://alas.aws.amazon.com/AL2/alas.rss
#
# CELERY
# TODO:
# 1. Download https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list
# 2. Read first line in mirror list => repo_url
# 3. Download $repo_url/repodata/updateinfo.xml.gz
# 4. Unzip the file => updateinfo.xml
# 5. In updateinfo.xml:
#   for every updates.update[i].references.reference[j]:
#       for every updates.update[i].pkglist.collection.package[k] as p:
#           create Vulnerability(name=p.name, version={p.epoch}:{p.version}-{p.release})
#
# MODEL
# get stringToVersion from https://github.com/rpm-software-management/yum/blob/master/rpmUtils/miscutils.py#L391
# when comparing versions:
#   (e1, v1, r1) = stringToVersion(p1)
#   (e2, v2, r2) = stringToVersion(p2)
#   rc = vercmp((e1, v1, r1), (e2, v2, r2))
# result: rc > 0 if p1 is newer
logger = logging.getLogger('django')


def fetch_vulnerabilities():
    logger.info('started.')
    Vulnerability.objects.filter(os_release_codename='amzn2').delete()

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
                                    'critical': Vulnerability.Urgency.CRITICAL}[severity]
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
        Vulnerability.objects.bulk_create(vulnerabilities.values())
        DebPackage.objects.filter(os_release_codename='amzn2').update(processed=False)
        logger.info('finished.')
        return len(vulnerabilities)