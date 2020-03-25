import json
import logging
import uuid
import datetime
from urllib.parse import unquote

import dateutil
import dateutil.parser
from django.http import HttpResponse
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.core.serializers.json import DjangoJSONEncoder
from django.urls import reverse
from django.db import transaction
from django.db.models import Q, F
from django.db.models.query import QuerySet
from django.db.models.functions import Round, Coalesce

from google.cloud import datastore
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, DestroyAPIView, CreateAPIView, UpdateAPIView, RetrieveAPIView
from rest_framework.generics import get_object_or_404
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from netaddr import IPAddress

from device_registry import ca_helper
from device_registry import google_cloud_helper
from device_registry.serializers import DeviceInfoSerializer, CredentialsListSerializer, CredentialSerializer
from device_registry.serializers import CreateDeviceSerializer, RenewExpiredCertSerializer, DeviceIDSerializer
from device_registry.serializers import IsDeviceClaimedSerializer, RenewCertSerializer, BatchArgsTagsSerializer
from device_registry.serializers import DeviceListSerializer
from device_registry.authentication import MTLSAuthentication
from device_registry.serializers import EnrollDeviceSerializer, PairingKeyListSerializer, UpdatePairingKeySerializer
from device_registry.serializers import SnoozeActionSerializer
from .tasks import file_github_issues
from .models import Device, DeviceInfo, FirewallState, PortScan, Credential, Tag, PairingKey, GlobalPolicy, DebPackage,\
    RecommendedAction

logger = logging.getLogger(__name__)

if google_cloud_helper.credentials and google_cloud_helper.project:
    datastore_client = datastore.Client(project=google_cloud_helper.project,
                                        credentials=google_cloud_helper.credentials)
else:
    datastore_client = None


class PolicyDeviceNumberView(APIView):
    """
    Ajax view for getting the number of devices with a given global policy applied.
    """

    def get(self, request, *args, **kwargs):
        global_policy = get_object_or_404(GlobalPolicy, owner=request.user, pk=kwargs['pk'])
        return Response({'devices_nr': global_policy.get_devices_nr()})


class MtlsPingView(APIView):
    """Endpoint for sending a heartbeat."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]

    def get(self, request, *args, **kwargs):
        device = Device.objects.get(device_id=request.device_id)
        device.last_ping = timezone.now()
        device.save(update_fields=['last_ping'])
        portscan_object, _ = PortScan.objects.get_or_create(device=device)
        firewallstate_object, _ = FirewallState.objects.get_or_create(device=device)
        if firewallstate_object.global_policy:  # Use security settings from the global policy.
            block_networks = firewallstate_object.global_policy.networks.copy()
            block_ports = firewallstate_object.global_policy.ports
            policy_string = firewallstate_object.global_policy.policy_string
            ports_field_name = firewallstate_object.global_policy.ports_field_name
        else:  # User's per-device security settings.
            block_networks = []
            block_ports = []
            policy_string = 'allow'
            ports_field_name = 'block_ports'
        block_networks.extend(settings.SPAM_NETWORKS)
        return Response({
            'policy': policy_string, ports_field_name: block_ports, 'block_networks': block_networks,
            'deb_packages_hash': device.deb_packages_hash
        })

    def post(self, request, *args, **kwargs):
        data = request.data
        device = Device.objects.get(device_id=request.device_id)
        device.last_ping = timezone.now()
        device.agent_version = data.get('agent_version')
        device.audit_files = data.get('audit_files', [])
        os_release = data.get('os_release', {})
        device.auto_upgrades = data.get('auto_upgrades')
        if 'deb_packages' in data:
            deb_packages = data['deb_packages']
            device.deb_packages_hash = deb_packages['hash']
            device.set_deb_packages(deb_packages['packages'], os_release)
        kernel_deb_package = data.get('kernel_package')
        if kernel_deb_package:
            device.kernel_deb_package = device.deb_packages.get(name=kernel_deb_package['name'],
                                                                version=kernel_deb_package['version'],
                                                                arch=kernel_deb_package['arch'],
                                                                os_release_codename=os_release['codename'])
        else:
            device.kernel_deb_package = None
        device.reboot_required = data.get('reboot_required')
        device.cpu = data.get('cpu', {})
        device.os_release = os_release
        device.mysql_root_access = data.get('mysql_root_access')
        device.default_password_users = data.get('default_password_users')
        device_info_object, _ = DeviceInfo.objects.get_or_create(device=device)
        device_info_object.device__last_ping = timezone.now()
        device_info_object.device_operating_system_version = data.get('device_operating_system_version')
        device_info_object.fqdn = data.get('fqdn')
        device_info_object.ipv4_address = data.get('ipv4_address')
        device_info_object.device_manufacturer = data.get('device_manufacturer')
        device_info_object.device_model = data.get('device_model')
        device_info_object.selinux_state = data.get('selinux_status', {})
        device_info_object.app_armor_enabled = data.get('app_armor_enabled')
        device_info_object.logins = data.get('logins', {})
        processes = data.get('processes')
        if processes:
            # Convert from list to dict.
            device_info_object.processes = {e['pid']: (e['name'], e['username'], e['cmdline'], e.get('container'))
                                            for e in processes}
        else:
            device_info_object.processes = {}
        device_info_object.default_password = data.get('default_password')
        device_info_object.save()

        portscan_object, _ = PortScan.objects.get_or_create(device=device)
        scan_info = data.get('scan_info', [])
        if isinstance(scan_info, str):
            scan_info = json.loads(scan_info)
        # Add missing IP protocol version info.
        for record in scan_info:
            if 'ip_version' not in record:
                ipaddr = IPAddress(record['host'])
                record['ip_version'] = ipaddr.version
        portscan_object.scan_info = scan_info
        portscan_object.netstat = data.get('netstat', [])
        portscan_object.save()
        firewall_state, _ = FirewallState.objects.get_or_create(device=device)
        firewall_rules = data.get('firewall_rules', {})
        if isinstance(firewall_rules, str):
            firewall_rules = json.loads(firewall_rules)
        firewall_state.rules = firewall_rules
        firewall_state.save()

        device.update_trust_score = True
        device.save(update_fields=['last_ping', 'agent_version', 'audit_files', 'deb_packages_hash',
                                   'update_trust_score', 'os_release', 'auto_upgrades',
                                   'mysql_root_access', 'cpu', 'kernel_deb_package', 'reboot_required',
                                   'default_password_users'])
        # Un-snooze recommended actions which were "Fixed" (i.e. snoozed until next ping)
        device.recommendedactionstatus_set.filter(status=RecommendedAction.Status.SNOOZED_UNTIL_PING) \
            .update(status=RecommendedAction.Status.AFFECTED)
        device.generate_recommended_actions()

        if datastore_client:
            # logins may have empty string as a key. DataStore doesn't accept that.
            logins = data.get('logins', [])
            if type(logins) is dict:
                logins = [{'username': k, 'failed': v['failed'], 'success': v['success']} for k, v in logins.items()]
            data['logins'] = logins
            task_key = datastore_client.key('Ping')
            entity = google_cloud_helper.dicts_to_ds_entities(data, task_key)
            entity['device_id'] = device.device_id  # Will be indexed.
            entity['last_ping'] = timezone.now()  # Will be indexed.
            datastore_client.put(entity)

        return Response({'message': 'pong'})


class MtlsRenewCertView(APIView):
    """Renewal of certificate."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]

    def post(self, request, *args, **kwargs):
        device_id = request.device_id
        device = Device.objects.get(device_id=device_id)

        serializer = RenewCertSerializer(device, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if serializer.validated_data['device_id'] != device_id:
            return Response('Invalid request.', status=status.HTTP_400_BAD_REQUEST)

        if not ca_helper.csr_is_valid(csr=serializer.validated_data['certificate_csr'], device_id=device_id):
            return Response('Invalid CSR.', status=status.HTTP_400_BAD_REQUEST)

        signed_certificate = ca_helper.sign_csr(serializer.validated_data['certificate_csr'], device_id)
        if not signed_certificate:
            return Response('Unknown error', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)

        serializer.save(certificate=signed_certificate, certificate_expires=certificate_expires,
                        last_ping=timezone.now(), claim_token=uuid.uuid4(), fallback_token=uuid.uuid4())

        device_info, _ = DeviceInfo.objects.get_or_create(device=device)
        device_info.device_manufacturer = serializer.validated_data.get('device_manufacturer', '')
        device_info.device_model = serializer.validated_data.get('device_model', '')
        device_info.device_operating_system = serializer.validated_data['device_operating_system']
        device_info.device_operating_system_version = serializer.validated_data['device_operating_system_version']
        device_info.device_architecture = serializer.validated_data['device_architecture']
        device_info.fqdn = serializer.validated_data['fqdn']
        device_info.ipv4_address = serializer.validated_data['ipv4_address']
        device_info.save()

        return Response({
            'certificate': signed_certificate,
            'certificate_expires': certificate_expires,
            'claim_token': device.claim_token,
            'fallback_token': device.fallback_token,
            'claimed': device.claimed
        })


class MtlsDeviceMetadataView(APIView):
    """Return device specific metadata."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]

    def get(self, request, *args, **kwargs):
        device = Device.objects.get(device_id=request.device_id)
        if device.claimed:
            metadata = device.deviceinfo.device_metadata
            metadata['device-name'] = device.name
            metadata['device_id'] = request.device_id
            metadata['manufacturer'] = device.deviceinfo.device_manufacturer
            metadata['model'] = device.deviceinfo.device_model
        else:
            metadata = {}
        return Response(metadata)


class MtlsCredsView(APIView):
    """Return all user's credentials."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]

    def get(self, request, *args, **kwargs):
        device = Device.objects.get(device_id=request.device_id)
        if device.owner:
            qs = device.owner.credentials.filter(tags__in=device.tags.tags).distinct()
        else:
            qs = Credential.objects.none()
        serializer = CredentialsListSerializer(qs, many=True)
        return Response(serializer.data)


class ActionView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        return Response({'id': kwargs['action_id'], 'name': kwargs['action_name']})


class MtlsTesterView(APIView):
    """Return the Device ID of the sender."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]

    def get(self, request, *args, **kwargs):
        return Response({'message': 'Hello {}'.format(request.device_id)})


class IsDeviceClaimedView(RetrieveAPIView):
    """Return claimed status of a node."""
    permission_classes = [AllowAny]
    authentication_classes = [MTLSAuthentication]
    queryset = Device.objects.all()
    serializer_class = IsDeviceClaimedSerializer

    def get_object(self):
        """
        Standard `get_object` method overwritten in order to get device_id
         from the request instance which received it from MTLSAuthentication.
        """
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, **{'device_id': self.request.device_id})
        return obj


class RenewExpiredCertView(UpdateAPIView):
    """
    Renewal of certificate.
    """
    permission_classes = [AllowAny]
    serializer_class = RenewExpiredCertSerializer

    def post(self, request, *args, **kwargs):
        device_id_serializer = DeviceIDSerializer(data=request.data)
        if not device_id_serializer.is_valid():
            return Response(device_id_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        device = Device.objects.get(device_id=device_id_serializer.validated_data['device_id'])
        if device.certificate_expires > timezone.now():
            return Response('Certificate is not expired yet', status=status.HTTP_400_BAD_REQUEST)

        # Primary serializer.
        serializer = self.get_serializer(device, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        if not ca_helper.csr_is_valid(serializer.validated_data['certificate_csr'], device.device_id):
            return Response('Invalid CSR', status=status.HTTP_400_BAD_REQUEST)

        signed_certificate = ca_helper.sign_csr(serializer.validated_data['certificate_csr'], device.device_id)
        if not signed_certificate:
            return Response('Unknown error', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)
        claim_token = uuid.uuid4()
        fallback_token = uuid.uuid4()
        serializer.save(certificate=signed_certificate, certificate_expires=certificate_expires,
                        last_ping=timezone.now(), claim_token=claim_token, fallback_token=fallback_token)

        device_info, _ = DeviceInfo.objects.get_or_create(device=device)
        device_info.device_manufacturer = serializer.validated_data.get('device_manufacturer', '')
        device_info.device_model = serializer.validated_data.get('device_model', '')
        device_info.device_operating_system = serializer.validated_data['device_operating_system']
        device_info.device_operating_system_version = serializer.validated_data['device_operating_system_version']
        device_info.device_architecture = serializer.validated_data['device_architecture']
        device_info.fqdn = serializer.validated_data['fqdn']
        device_info.ipv4_address = serializer.validated_data['ipv4_address']
        device_info.save()

        return Response({
            'certificate': signed_certificate,
            'certificate_expires': certificate_expires,
            'claim_token': claim_token,
            'fallback_token': fallback_token,
            'claimed': device.claimed
        })


class SignNewDeviceView(CreateAPIView):
    """
    Sign a submitted CSR.
    """
    permission_classes = [AllowAny]
    serializer_class = CreateDeviceSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = Device(device_id=serializer.validated_data['device_id'],
                        certificate_csr=serializer.validated_data['certificate_csr'])

        signed_certificate = ca_helper.sign_csr(serializer.validated_data['certificate_csr'],
                                                serializer.validated_data['device_id'])
        if not signed_certificate:
            return Response('Unknown error', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)
        device.certificate = signed_certificate
        device.certificate_expires = certificate_expires
        device.last_ping = timezone.now()
        device.claim_token = uuid.uuid4()
        device.fallback_token = uuid.uuid4()
        device.save()

        DeviceInfo.objects.create(
            device=device,
            device_manufacturer=serializer.validated_data.get('device_manufacturer', ''),
            device_model=serializer.validated_data.get('device_model', ''),
            device_operating_system=serializer.validated_data['device_operating_system'],
            device_operating_system_version=serializer.validated_data['device_operating_system_version'],
            device_architecture=serializer.validated_data['device_architecture'],
            fqdn=serializer.validated_data['fqdn'],
            ipv4_address=serializer.validated_data['ipv4_address']
        )

        return Response({
            'certificate': signed_certificate,
            'certificate_expires': certificate_expires,
            'claim_token': device.claim_token,
            'fallback_token': device.fallback_token
        })


class DeviceCertView(APIView):
    """
    Return a device certificate from the database.
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            device = Device.objects.get(device_id=kwargs['device_id'])
        except ObjectDoesNotExist:
            return Response('Device not found', status=status.HTTP_404_NOT_FOUND)

        response = HttpResponse(device.certificate, content_type='application/x-pem-file')
        response['Content-Disposition'] = 'attachment; filename={}.crt'.format(device.device_id)
        return response


class DeviceIDView(APIView):
    """
    Return a device ID for enrolling a new device.
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        while True:
            device_id = '{}.{}'.format(uuid.uuid4().hex, settings.COMMON_NAME_PREFIX)
            if not Device.objects.filter(device_id=device_id).exists():
                return Response({'device_id': device_id})


class CACertView(APIView):
    """
    Return the CA cert
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        return Response({'ca_certificate': ca_helper.get_ca_certificate()})


class CABundleView(APIView):
    """
    Return the root cert bundle
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        with open('files/cert-bundle.crt') as f:
            ca_bundle = f.read()
        return Response({'ca_bundle': ca_bundle})


class ClaimByLink(APIView):
    def get(self, request, *args, **kwargs):
        params = request.query_params
        device = get_object_or_404(
            Device,
            claim_token=params['claim-token'],
            device_id=params['device-id'],
            owner__isnull=True
        )
        device.claim(request.user)
        return Response(f'Device {device.device_id} claimed!')


class DeviceEnrollView(APIView):
    """
    enroll the device using enroll token (pairing key) to authorize
    params:
    key - enroll token
    claim_token - claim token
    device_id - device id to be enrolled
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = EnrollDeviceSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        pair_key = PairingKey.objects.get(key=serializer.validated_data['key'])

        device = Device.objects.get(
            claim_token=serializer.validated_data['claim_token'],
            device_id=serializer.validated_data['device_id'],
            owner__isnull=True
        )
        device.claim(pair_key.owner)
        device.owner.profile.track_first_device()
        return Response()


class DeviceListView(ListAPIView):
    """
    List all of the users devices.
    """
    serializer_class = DeviceInfoSerializer
    authentication_classes = [SessionAuthentication, TokenAuthentication]

    def get_queryset(self):
        return DeviceInfo.objects.filter(device__owner=self.request.user)


class CredentialsQSMixin(object):
    def get_queryset(self):
        return self.request.user.credentials.all()


class CredentialsView(CredentialsQSMixin, ListAPIView):
    """
    Return all current user's credentials.
    """
    serializer_class = CredentialsListSerializer

    def list(self, request, *args, **kwargs):
        """
        Overwritten default `list` method in order to return a dict instead of list.
        """
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({'data': serializer.data})


class DeleteCredentialView(CredentialsQSMixin, DestroyAPIView):
    pass


class UpdateCredentialView(CredentialsQSMixin, UpdateAPIView):
    serializer_class = CredentialSerializer

    def update(self, request, *args, **kwargs):
        """
        Overwritten the default `update` method in order to catch unique constraint violation.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        if Credential.objects.filter(
                owner=request.user, name=serializer.validated_data['name'],
                linux_user=serializer.validated_data['linux_user']).exclude(pk=instance.pk).exists():
            return Response({'error': '\'Name\'/\'File owner\' combination should be unique'},
                            status=status.HTTP_400_BAD_REQUEST)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def perform_update(self, serializer):
        """
        Overwrite the default 'perform_update' method in order to properly handle tags received as values.
        """
        instance = serializer.save()
        # Lowercase all unprotected tags.
        tags = [
            tag['name'] if Tag.objects.filter(name=tag['name'], protected=True).exists() else tag['name'].lower()
            for tag in serializer.initial_data['tags']
        ]
        instance.tags.set(*tags)


class CreateCredentialView(CreateAPIView):
    serializer_class = CredentialSerializer

    def create(self, request, *args, **kwargs):
        """
        Overwritten the default `create` method in order to catch unique constraint violation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if Credential.objects.filter(
                owner=request.user, name=serializer.validated_data['name'],
                linux_user=serializer.validated_data['linux_user']).exists():
            return Response({'error': '\'Name\'/\'File owner\' combination should be unique'},
                            status=status.HTTP_400_BAD_REQUEST)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        """
        Overwrite the default 'perform_create' method in order to properly handle tags received as values.
        """
        instance = serializer.save(owner=self.request.user)
        # Lowercase all unprotected tags.
        tags = [
            tag['name'] if Tag.objects.filter(name=tag['name'], protected=True).exists() else tag['name'].lower()
            for tag in serializer.initial_data['tags']
        ]
        instance.tags.add(*tags)


def autocomplete(request, tag_model):
    """
    The 'django-tagulous' `autocomplete` method overwritten in order to set proper tags ordering
    (meta-tags 1st, regular tags 2nd).

    Arguments:
        request
            The request object from the dispatcher
        tag_model
            Reference to the tag model (eg MyModel.tags.tag_model), or a
            queryset of the tag model (eg MyModel.tags.tag_model.objects.all())

    The following GET parameters can be set:
        q   The query string to filter by (match against start of string)
        p   The current page

    Response is a JSON object with following keys:
        results     List of tags
        more        Boolean if there is more
    }
    """
    # Get model, queryset and tag options
    if isinstance(tag_model, QuerySet):
        queryset = tag_model
        tag_model = queryset.model
    else:
        queryset = tag_model.objects
    options = tag_model.tag_options

    # Get query string
    query = request.GET.get('q', '')
    page = int(request.GET.get('p', 1))

    # Perform search
    if query:
        if options.force_lowercase:
            query = query.lower()

        if options.case_sensitive:
            results = queryset.filter(name__startswith=query)
        else:
            results = queryset.filter(name__istartswith=query)
    else:
        results = queryset.all()

    results = results.order_by('-protected', 'name')

    # Limit results
    if options.autocomplete_limit:
        start = options.autocomplete_limit * (page - 1)
        end = options.autocomplete_limit * page
        more = results.count() > end
        results = results[start:end]

    # Build response
    response = {
        'results': [tag.name for tag in results],
        'more': more,
    }
    return HttpResponse(
        json.dumps(response, cls=DjangoJSONEncoder),
        content_type='application/json',
    )


@login_required
def autocomplete_tags(request):
    return autocomplete(request, Tag.objects.filter(device__owner=request.user).distinct())


class PairingKeysQSMixin(object):
    def get_queryset(self):
        return self.request.user.pairing_keys.all()


class PairingKeyListView(PairingKeysQSMixin, ListAPIView):
    """
    Return all current user's pairing keys
    """
    serializer_class = PairingKeyListSerializer


class DeletePairingKeyView(PairingKeysQSMixin, DestroyAPIView):
    """
    Delete specified pairing key of current user
    """
    pass


class CreatePairingKeyView(CreateAPIView):
    """
    Create a new pairing key for the current user
    """

    def create(self, request, *args, **kwargs):
        pairing_key = PairingKey.objects.create(owner=self.request.user)
        serializer = PairingKeyListSerializer(instance=pairing_key)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class UpdatePairingKeyView(PairingKeysQSMixin, UpdateAPIView):
    """
    Update specified pairing key of current user. Only the `comment` field could be updated.
    """
    serializer_class = UpdatePairingKeySerializer


class InstallInstructionKeyView(APIView):

    def post(self, request, *args, **kwargs):
        serializer = PairingKeyListSerializer(instance=self.request.user.profile.pairing_key)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BatchAction:
    """
    Batch Actions Base Class
    """

    def __init__(self, target, subject='', subject_model=None, name='', display_name=None,
                 js_init=None, js_init_ext='', js_postprocess=None, js_get=None, url='#', ctl_ext='', **kwargs):
        """
        Create BatchAction Object
        :param target: Model/object name who is the target of action ( f.ex. on the device pace it would be 'Device')
        :param subject: Field name in the target object for applied acton
        :param name: Action name. Used as method name
        :param display_name: Action name. What is displayed in control. If None then `name` is used
        :param args_control: Html element template. If None <input text> will be created.
        :param ctl_ext: If default <input 'text'> used, it could be customized here (see Tags initialization)
        :param js_postprocess: Html element postpocessing script (to be called when element is placed on page)
        :param ls_get: js getter for args value. If none then default input text value getter used.
        :param url: url to  view used to apply action
        """
        self.object = target
        self.subject = subject
        self.name = name
        self.display_name = name if display_name is None else display_name
        self.args_control = f'''
            <input type="text" name="batch_{self.name}" id="batch_{self.name}" action_name="{self.name}" {ctl_ext} >
        '''.strip()
        self.js_postprocess = js_postprocess if js_postprocess is not None else 'function(el){}'
        self.js_get = js_get if js_get is not None else 'function(el){ return el.val();}'
        self.url = url


class GetBatchActionsView(APIView):
    def __init__(self, *args, **kwargs):
        super(GetBatchActionsView, self).__init__(**kwargs)
        #  tags elements js init/post_place. (also needed to be included TagsWidget().Media to context)
        tags_ctl_ext = '''
            data-tagulous data-tag-url="/ajax/tags/autocomplete/" autocomplete="off" style="width:100%;"
            '''.strip()
        tags_js_postprocess = 'function(el){Tagulous.select2(el);}'
        tags_js_get = '''function(el){
            let tags=[];
            Tagulous.parseTags( el.val(), true, false ).forEach( function (tag) {
                tags.push({ "name" : tag  })
            });
            return tags;
          }'''

        #  batch actions lists initialization.
        self.batch_actions = {
            'device': [
                BatchAction('device', 'Tags', name='add', display_name='Add Tags',
                            url=reverse('tags_batch', kwargs={'model_name': 'device'}), js_get=tags_js_get,
                            ctl_ext=tags_ctl_ext, js_postprocess=tags_js_postprocess).__dict__,
                BatchAction('device', 'Tags', name='set', display_name='Set Tags',
                            url=reverse('tags_batch', kwargs={'model_name': 'device'}), js_get=tags_js_get,
                            ctl_ext=tags_ctl_ext, js_postprocess=tags_js_postprocess).__dict__
            ],
            'default': []
        }

    def get(self, request, *args, **kwargs):
        if 'model_name' not in kwargs:
            return Response({'error': 'Invalid Arguments'}, status=status.HTTP_400_BAD_REQUEST)
        selector = kwargs['model_name']
        if selector not in self.batch_actions:
            selector = 'default'
        return Response(self.batch_actions[selector])


class BatchUpdateTagsView(APIView):

    def post(self, request, *args, **kwargs):
        objs = {'device': Device, 'credentials': Credential}
        request.data['model_name'] = kwargs['model_name']
        serializer = BatchArgsTagsSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        tag_names = []
        for tag in serializer.initial_data['args']:
            if Tag.objects.filter(name=tag['name']).exists():
                tag_names.append(tag['name'])
            else:
                name = tag['name'].lower()
                tag_names.append(name)
                Tag.objects.create(name=name)
        tags = Tag.objects.filter(name__in=tag_names)

        model_name = serializer.validated_data['model_name']
        model = objs[model_name]
        obj_ids = [obj['pk'] for obj in serializer.validated_data['objects']]
        objects = model.objects.filter(pk__in=obj_ids)
        action = serializer.validated_data['action']

        Relation = model.tags.through
        relations = []
        obj_id_str = f"{model_name}_id"
        for obj in objects:
            kwargs = {obj_id_str: obj.id}
            relations.extend(
                [Relation(tag_id=tag.id, **kwargs) for tag in tags if tag not in obj.tags or action == 'set']
            )

        with transaction.atomic():
            if action == 'set':
                obj_id__in_str = f"{model_name}_id__in"
                kwargs = {obj_id__in_str: obj_ids}
                Relation.objects.filter(**kwargs).delete()
            Relation.objects.bulk_create(relations)

        verb = "Added" if action == 'add' else 'Set'
        msg = f"{verb} tags to {objects.count()} {model_name}s."
        return Response(msg, status=status.HTTP_200_OK)


class DeviceListFilterMixin:
    """
    Mixin with device list filtering functionality
    """
    FILTER_FIELDS = {
        'device-name': (
            ['deviceinfo__fqdn', 'name'],
            'Node Name',
            'str'
        ),
        'hostname': (
            'deviceinfo__fqdn',
            'Hostname',
            'str'
        ),
        'comment': (
            'comment',
            'Comment',
            'str'
        ),
        'last-ping': (
            'last_ping',
            'Last Ping',
            'datetime'
        ),
        'trust-score': (
            'trust_score_prcnt',
            'Trust Score',
            'float'
        ),
        'default-credentials': (
            'deviceinfo__default_password',
            'Default Credentials Found',
            'bool'
        ),
        'tags': (
            'tags__name',
            'Tags',
            'tags'
        )
    }
    PREDICATES = {
        'str': {
            'eq': 'iexact',
            'c': 'icontains'
        },
        'tags': {
            'c': 'in'
        },
        'float': {
            'eq': 'exact',
            'lt': 'lt',
            'gt': 'gt'
        },
        'datetime': {
            'eq': 'exact',
            'lt': 'lt',
            'gt': 'gt'
        },
        'bool': {
            'eq': 'exact'
        }
    }

    def get_filter_q(self, set_filter_dict=False):
        """
        Create Device List Filter Query Object
        GET params:
        filter_by : filter field argument. (see self.FILTER_FIELDS)
        filter_value: value used for filtering
        filter_predicate:
                "eq" - matches
                "neq" - not matches
                "c" - contains
                "nc" - not contains
                "lt" - greater than
                "gt" - less than
        :return: Q object
        """
        query = Q()
        filter_by = self.request.GET.get('filter_by')
        filter_predicate = self.request.GET.get('filter_predicate')
        filter_value = self.request.GET.get('filter_value')
        since = self.request.GET.get('since')

        if filter_by and filter_predicate:
            if filter_by not in self.FILTER_FIELDS:
                raise ValidationError('filter subject is invalid.')

            query_by, _, query_type = self.FILTER_FIELDS[filter_by]
            invert = filter_predicate[0] == 'n'
            orig_filter_predicate = filter_predicate  # Keep original value for restoring filter in the UI.
            if invert:
                filter_predicate = filter_predicate[1:]
            if filter_predicate not in ['', 'eq', 'c', 'lt', 'gt']:
                raise ValidationError('filter predicate is invalid.')

            predicate = self.PREDICATES[query_type][filter_predicate]
            if query_type != 'str' and not filter_value:
                filter_value = None
            if set_filter_dict:
                self.filter_dict = {
                    'by': filter_by,
                    'predicate': orig_filter_predicate,
                    'value': filter_value,
                    'type': query_type
                }

            if query_type == 'datetime':
                if ',' not in filter_value:
                    raise ValidationError('invalid datetime interval argument format.')
                parts = filter_value.split(',')
                if len(parts) != 2:
                    raise ValidationError('invalid datetime interval argument parts.')
                number, measure = parts
                if not number:
                    number = '0'
                if not number.isdigit() or measure not in ['hours', 'days']:
                    raise ValidationError('datetime interval argument is invalid.')

                number = int(number)
                if filter_predicate == 'eq':
                    interval_start = timezone.now() - datetime.timedelta(**{measure: number + 1})
                    interval_end = timezone.now() - datetime.timedelta(**{measure: number})
                    filter_value = (interval_start, interval_end)
                    predicate = 'range'
                else:
                    filter_value = timezone.now() - datetime.timedelta(**{measure: number})
            elif query_type == 'tags':
                filter_value = filter_value.split(',') if filter_value else []
                if filter_value:
                    filter_value = [unquote(v) for v in filter_value]
                    if len(filter_value) != Tag.objects.filter(device__owner=self.request.user,
                                                               name__in=filter_value).distinct().count():
                        raise ValidationError('tags argument list is invalid.')

            if isinstance(query_by, list):
                query = Q()
                for field in query_by:
                    query.add(Q(**{f'{field}__{predicate}': filter_value}), Q.OR)
            else:
                query = Q(**{f'{query_by}__{predicate}': filter_value})

            if invert:
                query = ~query
        else:
            if set_filter_dict:
                self.filter_dict = None

        if since:
            try:
                since_timestamp = dateutil.parser.parse(since)
                if not timezone.is_aware(since_timestamp):
                    raise ValueError
            except ValueError:
                raise ValidationError('"since" is invalid.')
            else:
                query = Q(claimed_at__gt=since_timestamp) & query

        return query


class DeviceListAjaxView(ListAPIView, DeviceListFilterMixin):
    """
    List all of the users devices.
    """
    serializer_class = DeviceListSerializer
    ajax_info = dict()

    def _get_int_arg(self, name, default, min_val):
        try:
            val = int(self.request.GET.get(name, default))
        except ValueError:
            raise ValidationError(f'{name} argument is invalid.')
        if val < min_val:
            raise ValidationError(f'{name} argument is out of range.')
        return val

    def _datatables(self, *args, **kwargs):
        """
        Process JQuery DataTables AJAX arguments (GET mode used, because of device list filter use GET params)
        parameters description https://datatables.net/manual/server-side
        :return: device list queryset, and additional DataTables params in self.ajax_info
        """

        self.ajax_info['draw'] = self.request.GET.get('draw', '-')  # this value should be repeated in response

        start = self._get_int_arg('start', 0, 0)  # start row of page [0..oo)
        length = self._get_int_arg('length', -1, -1)  # page length or -1 for all [-1..oo)
        queryset = self.get_queryset(*args, **kwargs)
        self.ajax_info['recordsTotal'] = queryset.count()  # total unfiltered records count
        query = self.get_filter_q()  # our filters
        if self.request.GET.get('filter_by') == 'trust-score':
            devices = queryset.annotate(trust_score_prcnt=Round(Coalesce(F('trust_score'), 0.0) * 100)).filter(
                query).distinct()
        else:
            devices = queryset.filter(query).distinct()
        self.ajax_info['recordsFiltered'] = devices.count()  # total filtered records count
        self.ajax_info['timestamp'] = timezone.now()  # timestamp to be used by UI in "since" param to receive new nodes
        if length == -1:  # currently we have only 2 "modes":
            if start == 0:  # - with length = -1, then returns all records
                return devices
            else:
                return devices[start:]
        if start == 0:  # - with length = N, then return first N records
            return devices[:length]
        else:
            return devices[start:start + length]

    def get_queryset(self, *args, **kwargs):
        queryset = Device.objects.filter(owner=self.request.user)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self._datatables(*args, **kwargs)
        serializer = self.get_serializer(queryset, many=True)
        payload = {'data': serializer.data}
        payload.update(self.ajax_info)
        return Response(payload)


class SnoozeActionView(APIView):
    """Snooze particular recommended action for given devices list."""

    def post(self, request, *args, **kwargs):
        serializer = SnoozeActionSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        devices = request.user.devices.filter(pk__in=serializer.validated_data['device_ids'])
        have_snoozed_forever = False
        for dev in devices:
            action_class = serializer.validated_data['action_class']
            action_param = serializer.validated_data['action_param']
            duration = serializer.validated_data['duration']
            if duration is None:
                snoozed = RecommendedAction.Status.NOT_AFFECTED
                have_snoozed_forever = True  # at least one device has an action "resolved" -> need to update gh issue.
            elif duration == 0:
                snoozed = RecommendedAction.Status.SNOOZED_FOREVER
            else:
                snoozed = RecommendedAction.Status.SNOOZED_UNTIL_TIME
            dev.snooze_action(action_class, action_param, snoozed, duration)
        if have_snoozed_forever and settings.GITHUB_IMMEDIATE_SYNC:
            file_github_issues.delay(request.user.profile.pk)
        return Response(status=status.HTTP_200_OK)
