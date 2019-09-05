from celery import shared_task

from .models import CeleryPulseTimestamp


@shared_task
def update_celery_pulse_timestamp():
    pulse_obj = CeleryPulseTimestamp.objects.order_by('id').first()
    if pulse_obj is None:
        CeleryPulseTimestamp.objects.create()
    else:
        pulse_obj.save()
