from django import template
from django.utils import timezone

register = template.Library()


@register.filter(name='fromunix')
def fromunix(value):
    return timezone.datetime.fromtimestamp(value, timezone.get_default_timezone())
