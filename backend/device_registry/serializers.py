from rest_framework import serializers
from device_registry.models import Device


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = (
            'device_id',
            'created',
            'last_ping',
            'comment',
            'ipv4_address',
            'certificate_expires',
        )
