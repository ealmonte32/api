from django import template
from django.conf import settings
from django.utils import timezone

ALLOWED_SETTINGS = ['MAX_WEEKLY_RA']
register = template.Library()


@register.filter(name='fromunix')
def fromunix(value):
    return timezone.datetime.fromtimestamp(value, timezone.get_default_timezone())


@register.simple_tag
def settings_value(name):
    return getattr(settings, name, '') if name in ALLOWED_SETTINGS else ''
