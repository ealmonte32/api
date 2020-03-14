from celery import shared_task

from .celery_tasks import common, github, amazon_cve, debian_cve, ubuntu_cve

# We allow process 50 devices for 10m because currently this operation
# is VERY slow and requires optimization.
@shared_task(soft_time_limit=60 * 10, time_limit=60 * 10 + 5)  # Should live 10m max.
def update_trust_score(batch):
    return common.update_trust_score(batch)


@shared_task(soft_time_limit=60, time_limit=60 + 5)  # Should live 1m max.
def send_devices_to_trust_score_update():
    return common.send_devices_to_trust_score_update(update_trust_score)


@shared_task(soft_time_limit=60, time_limit=60 + 5)  # Should live 1m max.
def update_packages_vulnerabilities(batch):
    return common.update_packages_vulnerabilities(batch)


@shared_task(soft_time_limit=60 * 2.5, time_limit=60 * 2.5 + 5)  # Should live 2.5m max.
def send_packages_to_vulns_update():
    return common.send_packages_to_vulns_update(update_packages_vulnerabilities)


@shared_task(soft_time_limit=60 * 20, time_limit=60 * 20 + 5)  # Should live 20m max.
def fetch_vulnerabilities_ubuntu():
    return ubuntu_cve.fetch_vulnerabilities()


@shared_task(soft_time_limit=60 * 15, time_limit=60 * 15 + 5)  # Should live 15m max.
def fetch_vulnerabilities_debian():
    return debian_cve.fetch_vulnerabilities()


@shared_task(soft_time_limit=60 * 15, time_limit=60 * 15 + 5)  # Should live 15m max.
def fetch_vulnerabilities_amazon():
    return amazon_cve.fetch_vulnerabilities()


@shared_task(soft_time_limit=60 * 60, time_limit=60 * 60 + 5)  # Should live 60m max.
def file_github_issues(profile_pk=None):
    return github.file_issues(profile_pk)


@shared_task(soft_time_limit=60 * 10, time_limit=60 * 10 + 5)  # Should live 10m max.
def sample_history():
    return common.sample_history()
