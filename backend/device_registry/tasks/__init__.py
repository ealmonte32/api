import logging
import os

from celery import shared_task
import redis

from device_registry.models import Device, Vulnerability, DebPackage, DEBIAN_SUITES, UBUNTU_SUITES

logger = logging.getLogger('django')


@shared_task
def update_trust_score():
    """
    Update trust score of devices marked as needing such update.
    """
    target_devices = Device.objects.filter(update_trust_score=True).only('pk')
    for device in target_devices:
        device.trust_score = device.get_trust_score()
        device.update_trust_score = False
        device.save(update_fields=['trust_score', 'update_trust_score'])


# Should live 4m max and throw and exception to Sentry when killed.
@shared_task(soft_time_limit=60 * 4, time_limit=60 * 4 + 5)  # Should live 4m max.
def update_packages_vulnerabilities():
    #redis_conn = redis.Redis(host=os.getenv('REDIS_HOST', 'redis'), port=int(os.getenv('REDIS_PORT', '6379')),
    #                         password=os.getenv('REDIS_PASSWORD'))
    try:
        # Try to acquire the lock.
        # Spend trying 3s.
        # In case of success set the lock's timeout to 5m.
        with redis_conn.lock('vulns_lock', timeout=60 * 5, blocking_timeout=3):
            packages = DebPackage.objects.filter(processed=False, os_release_codename__in=DEBIAN_SUITES+UBUNTU_SUITES)
            for package in packages:
                actionable_valns = []
                vulns = Vulnerability.objects.filter(package=package.source_name,
                                                     os_release_codename=package.os_release_codename)
                for vuln in vulns:
                    if vuln.is_vulnerable(package.source_version) and vuln.fix_available:
                        actionable_valns.append(vuln)
                # with transaction.atomic():
                package.vulnerabilities.set(actionable_valns)
                package.processed = True
                package.save(update_fields=['processed'])
    except redis.exceptions.LockError:
        # Did not managed to acquire the lock within 3s - that means it's acquired by
        # another instance of the same job or by the `fetch_vulnerabilities` job.
        # In both cases this job instance shouldn't do anything.
        pass
