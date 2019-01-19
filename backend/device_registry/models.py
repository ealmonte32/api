from django.conf import settings
from django.db import models
import uuid


class Device(models.Model):
    device_id = models.CharField(
        max_length=128,
        unique=True,
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
    certificate_expires = models.DateTimeField(blank=True, null=True)
    ipv4_address = models.GenericIPAddressField(
        protocol="IPv4",
        null=True,
        blank=True
    )
    comment = models.CharField(blank=True, null=True, max_length=512)
    claim_token = models.CharField(editable=False, max_length=128)

    def save(self, *args, **kwargs):
        """
        Automatically append a random claim token to each device.

        @TODO:
         * Add cryptographic verification that cert matches hostname
         * Ensure hostname matches requirements.
        """
        self.claim_token = uuid.uuid4()
        super(Device, self).save(*args, **kwargs)

    def __str__(self):
        return self.device_id

    def claimed(self):
        return bool(self.owner)

    def has_valid_hostname(self):
        self.device_id.endswith('d.wott.local')

    class Meta:
        ordering = ('created',)
