from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework.utils.representation import smart_repr
from rest_framework.compat import unicode_to_repr

from device_registry.models import Device, DeviceInfo, Credential, Tag, PairingKey


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
        fields = ['id', 'device_id', 'owner', 'created', 'last_ping', 'certificate_expires', 'comment', 'name',
                  'agent_version', 'tags']


class DeviceInfoSerializer(serializers.ModelSerializer):
    device = DeviceSerializer(read_only=True)

    class Meta:
        model = DeviceInfo
        fields = ['device', 'device_manufacturer', 'device_model', 'device_architecture', 'device_operating_system',
                  'device_operating_system_version', 'distr_id', 'distr_release', 'trust_score', 'fqdn', 'ipv4_address',
                  'selinux_state', 'app_armor_enabled', 'logins', 'default_password', 'detected_mirai',
                  'device_metadata']


class TagsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['name', 'pk']


class CredentialsListSerializer(serializers.ModelSerializer):
    tags_data = TagsSerializer(many=True, source='tags')

    class Meta:
        model = Credential
        fields = ['name', 'key', 'value', 'linux_user', 'pk', 'tags_data']


class CredentialSerializer(serializers.ModelSerializer):
    tags = TagsSerializer(many=True, read_only=True)

    class Meta:
        model = Credential
        fields = ['name', 'key', 'value', 'linux_user', 'tags']


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


class IsDeviceClaimedSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['claimed', 'claim_token']


class RenewCertSerializer(serializers.ModelSerializer):
    csr = serializers.CharField(source='certificate_csr')
    device_manufacturer = serializers.CharField(max_length=128, required=False)
    device_model = serializers.CharField(max_length=128, required=False)
    device_architecture = serializers.CharField(max_length=32)
    device_operating_system = serializers.CharField(max_length=128)
    device_operating_system_version = serializers.CharField(max_length=128)
    fqdn = serializers.CharField(max_length=128)
    ipv4_address = serializers.IPAddressField(protocol="IPv4", allow_null=True)

    class Meta:
        model = Device
        fields = ['device_id', 'csr', 'device_manufacturer', 'device_model', 'device_architecture',
                  'device_operating_system', 'device_operating_system_version', 'fqdn', 'ipv4_address']
        validators = [RequiredValidator(fields=['device_id', 'certificate_csr'])]


class EnrollDeviceSerializer(serializers.Serializer):

    device_id = serializers.CharField(max_length=128)
    key = serializers.UUIDField()
    claim_token = serializers.CharField(max_length=128)

    def validate_device_id(self, value):
        if not Device.objects.filter(device_id=value).exists():
            raise serializers.ValidationError('Device not found')
        return value

    def validate_key(self, value):
        if not PairingKey.objects.filter(key=value).exists():
            raise serializers.ValidationError('Pairnig-token not found')
        return value

    def validate_claim_token(self, value):
        if not Device.objects.filter(claim_token=value).exists():
            raise serializers.ValidationError('Claim-token not found')
        return value

    def validate(self, data):
        if not Device.objects.filter(claim_token=data['claim_token'], device_id=data['device_id']).exists():
            raise serializers.ValidationError('Device id and claim token do not match')
        return data


class PairingKeyListSerializer(serializers.ModelSerializer):

    class Meta:
        model = PairingKey
        fields = ['key', 'created', 'comment']


class UpdatePairingKeySerializer(serializers.ModelSerializer):

    class Meta:
        model = PairingKey
        fields = ['comment']
