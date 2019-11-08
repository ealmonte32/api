from celery import shared_task

from .celery_tasks import common, ubuntu_cve, debian_cve


# Should live 2.5m max and throw an exception to Sentry when killed.
@shared_task(soft_time_limit=60 * 2.5, time_limit=60 * 2.9)  # Should live 2.5m max.
def update_trust_score():
    return common.update_trust_score()


# Should live 4m max and throw and exception to Sentry when killed.
@shared_task(soft_time_limit=60 * 4, time_limit=60 * 4 + 5)  # Should live 4m max.
def update_packages_vulnerabilities():
    return common.update_packages_vulnerabilities()


@shared_task(soft_time_limit=60 * 30, time_limit=60 * 30 + 5)  # Should live 30m max.
def fetch_vulnerabilities_ubuntu():
    return ubuntu_cve.fetch_vulnerabilities()


@shared_task(soft_time_limit=60 * 10, time_limit=60 * 10 + 5)  # Should live 10m max.
def fetch_vulnerabilities_debian():
    return debian_cve.fetch_vulnerabilities()
