from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework.utils.representation import smart_repr
from rest_framework.compat import unicode_to_repr

from device_registry.models import Device, DeviceInfo, Credential


class RequiredValidator(object):
    """
    Custom validator for making optional model fields behave like required ones.
    """

    missing_message = _('This field is required')

    def __init__(self, fields):
        self.fields = fields

    def enforce_required_fields(self, attrs):
        missing = dict([
            (field_name, self.missing_message)
            for field_name in self.fields
            if field_name not in attrs
        ])
        if missing:
            raise serializers.ValidationError(missing)

    def __call__(self, attrs):
        self.enforce_required_fields(attrs)

    def __repr__(self):
        return unicode_to_repr('<%s(fields=%s)>' % (
            self.__class__.__name__,
            smart_repr(self.fields)
        ))


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '__all__'


class DeviceInfoSerializer(serializers.ModelSerializer):
    device = DeviceSerializer(read_only=True)

    class Meta:
        model = DeviceInfo
        fields = '__all__'


class CredentialsListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Credential
        fields = ['name', 'key', 'value', 'pk']


class CredentialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Credential
        fields = ['name', 'key', 'value']


class CreateDeviceSerializer(serializers.ModelSerializer):
    device_manufacturer = serializers.CharField(max_length=128, required=False)
    device_model = serializers.CharField(max_length=128, required=False)
    device_operating_system = serializers.CharField(max_length=128)
    device_operating_system_version = serializers.CharField(max_length=128)
    device_architecture = serializers.CharField(max_length=32)
    fqdn = serializers.CharField(max_length=128)
    ipv4_address = serializers.IPAddressField(protocol="IPv4", allow_null=True)

    class Meta:
        model = Device
        fields = ['device_id', 'certificate_csr', 'device_manufacturer', 'device_model', 'device_operating_system',
                  'device_operating_system_version', 'device_architecture', 'fqdn', 'ipv4_address']
        validators = [RequiredValidator(fields=['certificate_csr'])]
