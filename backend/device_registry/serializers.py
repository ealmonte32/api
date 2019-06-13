from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework.utils.representation import smart_repr
from rest_framework.compat import unicode_to_repr

from device_registry.models import Device, DeviceInfo, Credential, Tags
import tagulous.serializers.base


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


class TagsSerialiser(serializers.ModelSerializer):
    class Meta:
        model = Tags
        fields = ['name', 'pk']


class CredentialsListSerializer(serializers.ModelSerializer):
    tags = TagsSerialiser(many=True)
    class Meta:
        model = Credential
        fields = ['name', 'key', 'value', 'pk', 'tags']


class CredentialSerializer(serializers.ModelSerializer):
    tags = TagsSerialiser(many=True, read_only=True)
    class Meta:
        model = Credential
        fields = ['name', 'key', 'value', 'tags']


class TagsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tags
        fields = '__all__'


class CreateDeviceSerializer(serializers.ModelSerializer):
    csr = serializers.CharField(source='certificate_csr')
    device_manufacturer = serializers.CharField(max_length=128, required=False)
    device_model = serializers.CharField(max_length=128, required=False)
    device_operating_system = serializers.CharField(max_length=128)
    device_operating_system_version = serializers.CharField(max_length=128)
    device_architecture = serializers.CharField(max_length=32)
    fqdn = serializers.CharField(max_length=128)
    ipv4_address = serializers.IPAddressField(protocol="IPv4", allow_null=True)

    class Meta:
        model = Device
        fields = ['device_id', 'csr', 'device_manufacturer', 'device_model', 'device_operating_system',
                  'device_operating_system_version', 'device_architecture', 'fqdn', 'ipv4_address']
        validators = [RequiredValidator(fields=['certificate_csr'])]


class RenewExpiredCertSerializer(serializers.ModelSerializer):
    csr = serializers.CharField(source='certificate_csr')
    device_manufacturer = serializers.CharField(max_length=128, required=False)
    device_model = serializers.CharField(max_length=128, required=False)
    device_operating_system = serializers.CharField(max_length=128)
    device_operating_system_version = serializers.CharField(max_length=128)
    device_architecture = serializers.CharField(max_length=32)
    fqdn = serializers.CharField(max_length=128)
    ipv4_address = serializers.IPAddressField(protocol="IPv4", allow_null=True)

    class Meta:
        model = Device
        fields = ['csr', 'fallback_token', 'device_manufacturer', 'device_model', 'device_operating_system',
                  'device_operating_system_version', 'device_architecture', 'fqdn', 'ipv4_address']

    def validate_fallback_token(self, value):
        if value != self.instance.fallback_token:
            raise serializers.ValidationError('Invalid fallback token')
        return value


class DeviceIDSerializer(serializers.Serializer):
    device_id = serializers.CharField()

    def validate_device_id(self, value):
        if not Device.objects.filter(device_id=value).exists():
            raise serializers.ValidationError('Device not found')
        return value
