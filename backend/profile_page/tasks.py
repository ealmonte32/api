from celery import shared_task

from .celery_tasks import stripe_tasks


@shared_task(soft_time_limit=60 * 30, time_limit=60 * 30 + 5)  # Should live 30m max.
def sync_subscriptions():
    return stripe_tasks.sync_subscriptions()
