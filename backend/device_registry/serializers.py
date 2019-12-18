from django.utils.translation import ugettext_lazy as _
from django.utils.timesince import timesince
from django.urls import reverse

from rest_framework import serializers
from rest_framework.utils.representation import smart_repr

from .models import Device, DeviceInfo, Credential, Tag, PairingKey
from .recommended_actions import ActionMeta


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
        return '<%s(fields=%s)>' % (
            self.__class__.__name__,
            smart_repr(self.fields)
        )


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'device_id', 'owner', 'created', 'last_ping', 'certificate_expires', 'comment', 'name',
                  'agent_version', 'trust_score', 'tags']


class DeviceInfoSerializer(serializers.ModelSerializer):
    device = DeviceSerializer(read_only=True)

    class Meta:
        model = DeviceInfo
        fields = ['device', 'device_manufacturer', 'device_model', 'device_architecture', 'device_operating_system',
                  'device_operating_system_version', 'fqdn', 'ipv4_address',
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
        fields = ['name', 'linux_user', 'pk', 'tags_data', 'data']


class CredentialSerializer(serializers.ModelSerializer):
    tags = TagsSerializer(many=True, read_only=True)

    class Meta:
        model = Credential
        fields = ['name', 'linux_user', 'tags', 'data']

    def validate_data(self, value):
        if not value:
            raise serializers.ValidationError('At least one key-value pair is required.')
        return value


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

    def validate_key(self, value):
        if not PairingKey.objects.filter(key=value).exists():
            raise serializers.ValidationError('Pairnig-token not found')
        return value

    def validate(self, data):
        if not Device.objects.filter(claim_token=data['claim_token'], device_id=data['device_id']).exists():
            raise serializers.ValidationError('Node id and claim token do not match')
        return data


class PairingKeyListSerializer(serializers.ModelSerializer):
    class Meta:
        model = PairingKey
        fields = ['key', 'created', 'comment']

    def to_representation(self, instance):
        representation = super(PairingKeyListSerializer, self).to_representation(instance)
        representation['created'] = instance.created.strftime('%Y-%m-%d %H:%M:%S')
        return representation


class UpdatePairingKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = PairingKey
        fields = ['comment']


class BatchArgsObjectSerializer(serializers.Serializer):
    pk = serializers.CharField(max_length=64)


class BatchArgsTagsSerializer(serializers.Serializer):
    action = serializers.CharField(max_length=64)
    objects = BatchArgsObjectSerializer(many=True)
    args = TagsSerializer(many=True, read_only=True)
    model_name = serializers.CharField(max_length=64)

    def validate_action(self, value):
        if value not in ['add', 'set']:
            raise serializers.ValidationError('Invalid argument')
        return value

    def validate_object(self, value):
        if value not in ['device', 'credentials']:
            raise serializers.ValidationError('Invalid argument')
        return value

    def validate(self, attrs):
        models = {'device': Device, 'credentials': Credential}
        pk_list = [obj['pk'] for obj in attrs['objects']]
        user = self.context['request'].user
        if models[attrs['model_name']].objects.filter(pk__in=pk_list, owner=user).count() != len(pk_list):
            raise serializers.ValidationError('Invalid argument')
        return attrs


class DeviceListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'get_name', 'hostname', 'last_ping', 'trust_score', 'comment', 'device_id', 'owner',
                  'trust_score_color', 'trust_score_percent']

    def to_representation(self, instance):
        representation = super(DeviceListSerializer, self).to_representation(instance)
        representation['last_ping'] = timesince(instance.last_ping) + ' ago'
        representation['actions'] = {
            'count': instance.actions_count or '',
            'url': reverse('device_actions', args=[instance.pk])
        }
        return representation


class SnoozeActionSerializer(serializers.Serializer):
    device_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=False)
    action_id = serializers.IntegerField()
    duration = serializers.IntegerField(allow_null=True, min_value=0)

    def validate_action_id(self, value):
        if not ActionMeta.is_action_id(value):
            raise serializers.ValidationError('Invalid recommended action id')
        return value

    def validate_device_ids(self, value):
        if Device.objects.filter(owner=self.context['user'], pk__in=value).count() < len(value):
            raise serializers.ValidationError('Invalid device id(s) provided')
        return value
