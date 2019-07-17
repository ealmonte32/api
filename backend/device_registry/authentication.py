import re

from django.conf import settings

from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from device_registry.models import Device


class MTLSAuthentication(BaseAuthentication):
    """
    Custom authentication backend for mutual TLS (mTLS) auth
     based on http headers data.
    Passes further device_id in a newly added request property.
    It's not a real authentication (in terms of DRF),
     just few checks done before a view call.
    """

    def authenticate(self, request):
        if not request.META.get('HTTP_SSL_CLIENT_VERIFY') == 'SUCCESS':
            raise exceptions.PermissionDenied()

        cn_domain = re.match(r'.{1}\.(?P<domain>.*)', settings.COMMON_NAME_PREFIX).groupdict()['domain']

        matchObj = re.match(
            r'.*CN=(.*.{cn_domain})'.format(cn_domain=cn_domain),
            request.META.get('HTTP_SSL_CLIENT_SUBJECT_DN'),
            re.M | re.I)
        if not matchObj:
            raise exceptions.PermissionDenied()

        cn = matchObj.group(1)
        if not cn.endswith(settings.COMMON_NAME_PREFIX):
            raise exceptions.PermissionDenied()
        if not Device.objects.filter(device_id=cn).exists():
            raise exceptions.PermissionDenied()

        request.device_id = cn
        return None
