from celery import shared_task

from .models import Device


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
