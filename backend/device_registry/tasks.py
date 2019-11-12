from celery import shared_task

from .celery_tasks import common, ubuntu_cve, debian_cve


@shared_task(soft_time_limit=60 * 2.5, time_limit=60 * 2.9)  # Should live 2.5m max.
def update_trust_score():
    return common.update_trust_score()


@shared_task(soft_time_limit=60, time_limit=60 + 5)  # Should live 1m max.
def update_packages_vulnerabilities(batch):
    return common.update_packages_vulnerabilities(batch)


@shared_task(soft_time_limit=60 * 2.5, time_limit=60 * 2.5 + 5)  # Should live 2.5m max.
def send_packages_to_vulns_update():
    return common.send_packages_to_vulns_update(update_packages_vulnerabilities)


@shared_task(soft_time_limit=60 * 15, time_limit=60 * 15 + 5)  # Should live 15m max.
def fetch_vulnerabilities_ubuntu():
    return ubuntu_cve.fetch_vulnerabilities()


@shared_task(soft_time_limit=60 * 10, time_limit=60 * 10 + 5)  # Should live 10m max.
def fetch_vulnerabilities_debian():
    return debian_cve.fetch_vulnerabilities()
