import time

from django.conf import settings

import redis

from device_registry.models import Device, Vulnerability, DebPackage, DEBIAN_SUITES, UBUNTU_SUITES


def update_trust_score():
    """
    Update trust score of devices marked as needing such update.
    """
    target_devices = Device.objects.filter(update_trust_score=True).only('pk')
    device_nr = target_devices.count()
    ts_begin = time.time()
    for device in target_devices:
        device.trust_score = device.get_trust_score()
        device.update_trust_score = False
        device.save(update_fields=['trust_score', 'update_trust_score'])
    ts_end = time.time()
    print(f'update_trust_score: updated {device_nr} devices in {ts_end - ts_begin:.2f} seconds')


def update_packages_vulnerabilities(batch):
    packages = DebPackage.objects.filter(id__in=batch, processed=False)
    counter = 0
    for package in packages:
        # Marking the package as processed BEFORE the actual processing allows us correctly handle
        # the situation when the vulns DB was updated during the package processing.
        package.processed = True
        package.save(update_fields=['processed'])

        actionable_valns = []
        vulns = Vulnerability.objects.filter(package=package.source_name,
                                             os_release_codename=package.os_release_codename)
        for vuln in vulns:
            if vuln.is_vulnerable(package.source_version) and vuln.fix_available:
                actionable_valns.append(vuln)
        package.vulnerabilities.set(actionable_valns)
        counter += 1
    return counter


def send_packages_to_vulns_update(task):
    redis_conn = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD)
    try:
        # Try to acquire the lock.
        # Spend trying 3s.
        # In case of success set the lock's timeout to 60s.
        with redis_conn.lock('vulns_lock', timeout=60 * 2.5, blocking_timeout=3):
            distro_suites = DEBIAN_SUITES + UBUNTU_SUITES
            package_ids = list(DebPackage.objects.filter(
                processed=False, os_release_codename__in=distro_suites).values_list('id', flat=True))
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
