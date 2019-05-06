from rest_framework import serializers
from device_registry.models import Device, DeviceInfo


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '__all__'


class DeviceInfoSerializer(serializers.ModelSerializer):
    device = DeviceSerializer(read_only=True)
    class Meta:
        model = DeviceInfo
        fields = '__all__'
