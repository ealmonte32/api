import datetime

from django.conf import settings
from django.db import models
from django.db.models import F
from django.utils import timezone
from jsonfield import JSONField
from device_registry import ca_helper


class Device(models.Model):
    device_id = models.CharField(
        max_length=128,
        unique=True,
        null=False,
        blank=False,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='device',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    created = models.DateTimeField(auto_now_add=True)
    last_ping = models.DateTimeField(blank=True, null=True)
    certificate = models.TextField(blank=True, null=True)
    certificate_csr = models.TextField(blank=True, null=True)
    certificate_expires = models.DateTimeField(blank=True, null=True)
    comment = models.CharField(blank=True, null=True, max_length=512)
    claim_token = models.CharField(editable=False, max_length=128)

    @staticmethod
    def get_active_inactive(user):
        devices = get_device_list(user)
        device_count = devices.count()
        day_ago = timezone.now() - datetime.timedelta(hours=24)
        active = devices.filter(last_ping__gte=day_ago).count()
        inactive = device_count - active
        return [active, inactive]

    def __str__(self):
        return self.device_id

    def claimed(self):
        return bool(self.owner)

    def has_valid_hostname(self):
        self.device_id.endswith(settings.COMMON_NAME_PREFIX)

    def get_latest_portscan(self):
        latest = self.portscan_set.order_by('-scan_date')
        if latest.exists():
            return latest[0].scan_info

    def get_cert_expiration_date(self):
        try:
            return ca_helper.get_certificate_expiration_date(self.certificate)
        except ValueError:
            pass

    def get_cert_url(self):
        if settings.IS_DEV:
            cert_url = f'http://localhost:8001/api/v0.2/device-cert/{self.device_id}?format=json'
        else:
            cert_url = f'https://api.wott.io/api/v0.2/device-cert/{self.device_id}?format=json'
        return cert_url

    class Meta:
        ordering = ('created',)


class DeviceInfo(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    device_manufacturer = models.CharField(blank=True, null=True, max_length=128)
    device_model = models.CharField(blank=True, null=True, max_length=128)
    device_architecture = models.CharField(blank=True, null=True, max_length=32)
    device_operating_system = models.CharField(blank=True, null=True, max_length=128)
    device_operating_system_version = models.CharField(blank=True, null=True, max_length=128)
    fqdn = models.CharField(blank=True, null=True, max_length=128)
    ipv4_address = models.GenericIPAddressField(
        protocol="IPv4",
        null=True,
        blank=True
    )
    RASPBERRY_MODEL_MAP = {
        '0002': 'Model B Rev 1',
        '0003': 'Model B Rev 1',
        '0004': 'Model B Rev 2',
        '0005': 'Model B Rev 2',
        '0006': 'Model B Rev 2',
        '0007': 'Model A',
        '0008': 'Model A',
        '0009': 'Model A',
        '000d': 'Model B Rev 2',
        '000e': 'Model B Rev 2',
        '000f': 'Model B Rev 2',
        '0010': 'Model B+',
        '0013': 'Model B+',
        '900032': 'Model B+',
        '0011': 'Compute Module',
        '0014': 'Compute Module',
        '0012': 'Model A+',
        '0015': 'Model A+',
        'a01041': 'Pi 2 Model B v1.1',
        'a21041': 'Pi 2 Model B v1.1',
        'a22042': 'Pi 2 Model B v1.2',
        '900092': 'Pi Zero v1.2',
        '900093': 'Pi Zero v1.3',
        '9000C1': 'Pi Zero W',
        'a02082': 'Pi 3 Model B',
        'a22082': 'Pi 3 Model B',
        'a020d3': 'Pi 3 Model B+'
    }

    def __str__(self):
        return self.device.device_id

    def get_model(self):
        model = None
        if self.device_manufacturer == 'Raspberry Pi':
            model = DeviceInfo.RASPBERRY_MODEL_MAP.get(self.device_model, None)
        return model

    def get_hardware_type(self):
        if self.device_manufacturer == 'Raspberry Pi':
            return 'Raspberry Pi'


class PortScan(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now_add=True)
    scan_info = JSONField()


def get_device_list(user):
    """Get list of devices ordered by last ping.
    """
    return Device.objects.filter(owner=user).order_by(F('last_ping').desc(nulls_last=True))
