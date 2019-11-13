import time
from collections import defaultdict

from django.conf import settings
from django.db.models import Q

import redis

from device_registry.models import Device, Vulnerability, DebPackage, DEBIAN_SUITES, UBUNTU_SUITES


def update_trust_score(batch):
    devices = Device.objects.filter(id__in=batch, update_trust_score=True)
    counter = 0
    for device in devices:
        device.trust_score = device.get_trust_score()
        device.update_trust_score = False
        device.save(update_fields=['trust_score', 'update_trust_score'])
        counter += 1
    return counter


def send_devices_to_trust_score_update(task):
    device_ids = list(Device.objects.filter(update_trust_score=True).values_list('id', flat=True))
    batch_size = 50
    position = 0
    # Create batch jobs for multiple workers.
    while True:
        batch = device_ids[position: position + batch_size]
        if not batch:
            break
        task.delay(batch)
        position += batch_size
    return len(device_ids)


def update_packages_vulnerabilities(batch):
    # We store packages as a list in order to prevent its content update during the function run.
    packages = list(DebPackage.objects.filter(id__in=batch, processed=False))

    # Get only vulns we really need and put them to the dict.
    package_info_pairs = {(package.source_name, package.os_release_codename) for package in packages}
    q_objects = Q()
    for package_info in package_info_pairs:
        q_objects.add(Q(package=package_info[0], os_release_codename=package_info[1]), Q.OR)
    vulns_list = list(Vulnerability.objects.filter(q_objects))
    vulns_dict = defaultdict(list)
    for vuln in vulns_list:
        vulns_dict[(vuln.package, vuln.os_release_codename)].append(vuln)

    # Marking the package as processed BEFORE the actual processing allows us correctly handle
    # the situation when the vulns DB was updated during the package processing.
    package_ids = [package.id for package in packages]
    DebPackage.objects.filter(id__in=package_ids).update(processed=True)

    Relation = DebPackage.vulnerabilities.through
    relations = []
    counter = 0
    for package in packages:
        vulns = vulns_dict[(package.source_name, package.os_release_codename)]
        for vuln in vulns:
            if vuln.is_vulnerable(package.source_version) and vuln.fix_available:
                relations.append(Relation(debpackage_id=package.id, vulnerability_id=vuln.id))
        counter += 1
    Relation.objects.filter(debpackage_id__in=package_ids).delete()
    Relation.objects.bulk_create(relations, batch_size=10000, ignore_conflicts=True)
    return counter, len(relations)


def send_packages_to_vulns_update(task):
    redis_conn = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD)
    try:
        # Try to acquire the lock.
        # Spend trying 3s.
        # In case of success set the lock's timeout to 2.5m.
        with redis_conn.lock('vulns_lock', timeout=60 * 2.5, blocking_timeout=3):
            distro_suites = DEBIAN_SUITES + UBUNTU_SUITES
            package_ids = list(DebPackage.objects.filter(
                processed=False, os_release_codename__in=distro_suites).order_by(
                'os_release_codename', 'source_name').values_list('id', flat=True))
            batch_size = 500
            position = 0
            # Create batch jobs for multiple workers.
            while True:
                batch = package_ids[position: position + batch_size]
                if not batch:
                    break
                task.delay(batch)
                position += batch_size
            return len(package_ids)
    except redis.exceptions.LockError:
        # Did not managed to acquire the lock within 3s - that means it's acquired by
        # another instance of the same job or by the `fetch_vulnerabilities` job.
        # In both cases this job instance shouldn't do anything.
        return -1
