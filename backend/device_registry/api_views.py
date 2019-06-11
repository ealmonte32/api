import json
import logging
import uuid
import re

from django.http import HttpResponse
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, DestroyAPIView, CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny
from netaddr import IPAddress

from device_registry import ca_helper
from device_registry.serializers import DeviceInfoSerializer, CredentialsListSerializer, CredentialSerializer
from device_registry.datastore_helper import datastore_client, dicts_to_ds_entities
from .models import Device, DeviceInfo, FirewallState, PortScan, Credential

logger = logging.getLogger(__name__)


class DeviceCertView(APIView):
    """
    Returns a device certificate from the database.
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            device = Device.objects.get(device_id=kwargs['device_id'])
        except ObjectDoesNotExist:
            return Response('Device not found', status=status.HTTP_404_NOT_FOUND)

        if 'format' in request.GET:
            return Response({
                'certificate': device.certificate,
                'certificate_expires': device.certificate_expires,
                'is_expired':
                    device.certificate_expires < timezone.now() if device.certificate_expires is not None else False,
                'device_id': device.device_id,
            })
        else:
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
        device.owner = request.user
        device.claim_token = ''
        device.save(update_fields=['owner', 'claim_token'])
        return Response(f'Device {device.device_id} claimed!')


class DeviceListView(ListAPIView):
    """
    List all of the users devices.
    """
    serializer_class = DeviceInfoSerializer

    def get_queryset(self):
        return DeviceInfo.objects.filter(device__owner=self.request.user)


@api_view(['POST'])
@permission_classes([AllowAny])
def sign_new_device_view(request, format=None):
    """
    Signs a submitted CSR.
    """

    csr = request.data.get('csr')
    device_id = request.data.get('device_id')

    if not csr:
        return Response(
            'Missing csr key in payload.',
            status=status.HTTP_400_BAD_REQUEST
        )

    if not device_id:
        return Response(
            'Missing device_id key in payload.',
            status=status.HTTP_400_BAD_REQUEST
        )

    if Device.objects.filter(device_id=device_id):
        return Response(
            'Device already exist.',
            status=status.HTTP_409_CONFLICT
        )

    if not ca_helper.csr_is_valid(csr=csr, device_id=device_id):
        return Response(
            'Invalid CSR.',
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        Device.objects.create(
            device_id=device_id,
            certificate_csr=csr
        )
    except IntegrityError:
        return Response(
            'Device already exist.',
            status=status.HTTP_409_CONFLICT
        )
    except:
        return Response(
            'Unknown error.',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    signed_certificate = ca_helper.sign_csr(csr, device_id)
    if not signed_certificate:
        return Response(
            'Unknown error',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)

    device_object = Device.objects.get(device_id=device_id)
    device_object.certificate = signed_certificate
    device_object.certificate_expires = certificate_expires
    device_object.last_ping = timezone.now()
    device_object.claim_token = uuid.uuid4()
    device_object.fallback_token = uuid.uuid4()
    device_object.save()

    DeviceInfo(
        device=device_object,
        device_manufacturer=request.data.get('device_manufacturer'),
        device_model=request.data.get('device_model'),
        device_operating_system=request.data.get('device_operating_system'),
        device_operating_system_version=request.data.get('device_operating_system_version'),
        device_architecture=request.data.get('device_architecture'),
        fqdn=request.data.get('fqdn'),
        ipv4_address=request.data.get('ipv4_address'),
    ).save()

    return Response({
        'certificate': signed_certificate,
        'certificate_expires': certificate_expires,
        'claim_token': device_object.claim_token,
        'fallback_token': device_object.fallback_token
    })


def is_mtls_authenticated(request):
    """
    Returns the device id if authenticated properly
    through mTLS.

    This should probably be moved to a permission class.
    """

    if not request.META.get('HTTP_SSL_CLIENT_VERIFY') == 'SUCCESS':
        return Response(
            'You shall not pass!',
            status=status.HTTP_403_FORBIDDEN,
        )
    cn_domain = re.match(r'.{1}\.(?P<domain>.*)', settings.COMMON_NAME_PREFIX).groupdict()['domain']

    # @TODO clean up this as it will likely break
    matchObj = re.match(
        r'.*CN=(.*.{cn_domain})'.format(cn_domain=cn_domain),
        request.META.get('HTTP_SSL_CLIENT_SUBJECT_DN'),
        re.M|re.I
    )
    if not matchObj:
        logging.error('[MTLS-Auth] No valid CN found in header HTTP_SSL_CLIENT_SUBJECT_DN.')
        return False

    cn = matchObj.group(1)
    if cn.endswith(settings.COMMON_NAME_PREFIX):
        return cn
    else:
        logging.error('[MTLS-Auth] CN does not match {}'.format(settings.COMMON_NAME_PREFIX))
        return False


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def mtls_ping_view(request, format=None):
    """
    Endpoint for sending a heartbeat.
    """

    device_id = is_mtls_authenticated(request)
    if type(device_id) is Response:
        return device_id

    if not device_id:
        return Response(
            'Invalid request.',
            status=status.HTTP_400_BAD_REQUEST
        )

    if request.method == 'GET':
        device_object = Device.objects.get(device_id=device_id)
        device_object.last_ping = timezone.now()
        device_object.save(update_fields=['last_ping'])
        portscan_object, _ = PortScan.objects.get_or_create(device=device_object)
        block_networks = portscan_object.block_networks.copy()
        block_networks.extend(settings.SPAM_NETWORKS)
        return Response({'block_ports': portscan_object.block_ports, 'block_networks': block_networks})

    elif request.method == 'POST':
        data = request.data
        device_object = Device.objects.get(device_id=device_id)
        device_object.last_ping = timezone.now()
        device_object.agent_version = data.get('agent_version')
        device_object.save(update_fields=['last_ping', 'agent_version'])

        device_info_object, _ = DeviceInfo.objects.get_or_create(device=device_object)
        device_info_object.device__last_ping = timezone.now()
        device_info_object.device_operating_system_version = data.get('device_operating_system_version')
        device_info_object.fqdn = data.get('fqdn')
        device_info_object.ipv4_address = data.get('ipv4_address')
        device_info_object.device_manufacturer = data.get('device_manufacturer')
        device_info_object.device_model = data.get('device_model')
        device_info_object.distr_id = data.get('distr_id', None)
        device_info_object.distr_release = data.get('distr_release', None)
        device_info_object.selinux_state = data.get('selinux_status', {})
        device_info_object.app_armor_enabled = data.get('app_armor_enabled', None)
        device_info_object.logins = data.get('logins', {})
        device_info_object.default_password = data.get('default_password')
        device_info_object.save()

        portscan_object, _ = PortScan.objects.get_or_create(device=device_object)
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
        firewall_state, _ = FirewallState.objects.get_or_create(device=device_object)
        firewall_state.enabled = data.get('firewall_enabled')
        firewall_rules = data.get('firewall_rules', {})
        if isinstance(firewall_rules, str):
            firewall_rules = json.loads(firewall_rules)
        firewall_state.rules = firewall_rules
        firewall_state.save()

        if datastore_client:
            task_key = datastore_client.key('Ping')
            entity = dicts_to_ds_entities(data, task_key)
            entity['device_id'] = device_id  # Will be indexed.
            entity['last_ping'] = timezone.now()  # Will be indexed.
            datastore_client.put(entity)

        return Response({'message': 'pong'})


@api_view(['GET'])
@permission_classes([AllowAny])
def mtls_tester_view(request, format=None):
    """
    Simply returns the Device ID of the sender.
    """

    device_id = is_mtls_authenticated(request)

    if not device_id:
        return Response(
            'Invalid request.',
            status=status.HTTP_400_BAD_REQUEST
        )

    return Response({
        'message': 'Hello {}'.format(device_id)
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def mtls_renew_cert_view(request, format=None):
    """
    Renewal of certificate.
    """

    csr = request.data.get('csr')
    device_id = request.data.get('device_id')
    tls_device_id = is_mtls_authenticated(request)

    if not tls_device_id:
        return Response(
            'You shall not pass!.',
            status=status.HTTP_403_FORBIDDEN
        )

    if not tls_device_id == device_id:
        return Response(
            'Invalid request.',
            status=status.HTTP_400_BAD_REQUEST
        )

    if not ca_helper.csr_is_valid(csr=csr, device_id=device_id):
        return Response(
            'Invalid CSR.',
            status=status.HTTP_400_BAD_REQUEST
        )

    signed_certificate = ca_helper.sign_csr(csr, device_id)
    if not signed_certificate:
        return Response(
            'Unknown error',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)

    device_object = Device.objects.get(device_id=device_id)
    device_object.certificate_csr = csr
    device_object.certificate = signed_certificate
    device_object.certificate_expires = certificate_expires
    device_object.last_ping = timezone.now()
    device_object.claim_token = uuid.uuid4()
    device_object.fallback_token = uuid.uuid4()
    device_object.save()

    # @TODO: Log changes
    device_info_object, _ = DeviceInfo.objects.get_or_create(device=device_object)
    device_info_object.device_manufacturer = request.data.get('device_manufacturer')
    device_info_object.device_model = request.data.get('device_model')
    device_info_object.device_operating_system = request.data.get('device_operating_system')
    device_info_object.device_operating_system_version = request.data.get('device_operating_system_version')
    device_info_object.device_architecture = request.data.get('device_architecture')
    device_info_object.fqdn = request.data.get('fqdn')
    device_info_object.ipv4_address = request.data.get('ipv4_address')
    device_info_object.save()

    return Response({
        'certificate': signed_certificate,
        'certificate_expires': certificate_expires,
        'claim_token': device_object.claim_token,
        'fallback_token': device_object.fallback_token,
        'claimed': device_object.claimed
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def renew_expired_cert_view(request, format=None):
    """
    Renewal of certificate.
    """

    csr = request.data.get('csr')
    device_id = request.data.get('device_id')
    fallback_token = request.data.get('fallback_token')

    if not ca_helper.csr_is_valid(csr=csr, device_id=device_id):
        return Response(
            'Invalid CSR.',
            status=status.HTTP_400_BAD_REQUEST
        )

    device_object = get_object_or_404(Device, device_id=device_id)

    if fallback_token != device_object.fallback_token:
        return Response(
            'Invalid fallback token.',
            status=status.HTTP_400_BAD_REQUEST
        )

    if device_object.certificate_expires > timezone.now():
        return Response(
            'Certificate is not expired yet.',
            status=status.HTTP_400_BAD_REQUEST
        )

    signed_certificate = ca_helper.sign_csr(csr, device_id)
    if not signed_certificate:
        return Response(
            'Unknown error.',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    certificate_expires = ca_helper.get_certificate_expiration_date(signed_certificate)
    device_object.certificate_csr = csr
    device_object.certificate = signed_certificate
    device_object.certificate_expires = certificate_expires
    device_object.last_ping = timezone.now()
    device_object.claim_token = uuid.uuid4()
    device_object.fallback_token = uuid.uuid4()
    device_object.save()

    # @TODO: Log changes
    device_info_object, _ = DeviceInfo.objects.get_or_create(device=device_object)
    device_info_object.device_manufacturer = request.data.get('device_manufacturer')
    device_info_object.device_model = request.data.get('device_model')
    device_info_object.device_operating_system = request.data.get('device_operating_system')
    device_info_object.device_operating_system_version = request.data.get('device_operating_system_version')
    device_info_object.device_architecture = request.data.get('device_architecture')
    device_info_object.fqdn = request.data.get('fqdn')
    device_info_object.ipv4_address = request.data.get('ipv4_address')
    device_info_object.save()

    return Response({
        'certificate': signed_certificate,
        'certificate_expires': certificate_expires,
        'claim_token': device_object.claim_token,
        'fallback_token': device_object.fallback_token,
        'claimed': device_object.claimed
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def action_view(request, action_id, action_name):
    # Perform action
    return Response({
        'id': action_id,
        'name': action_name
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def mtls_creds_view(request, format=None):
    """
    Return all user's credentials.
    """
    device_id = is_mtls_authenticated(request)

    if not device_id:
        return Response(
            'Invalid request.',
            status=status.HTTP_400_BAD_REQUEST
        )
    if type(device_id) is Response:
        return device_id

    device = Device.objects.get(device_id=device_id)
    serializer = CredentialsListSerializer(device.owner.credentials.all(), many=True)
    return Response(serializer.data)


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
        Overwritten default `update` method in order to catch unique constraint violation.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        if Credential.objects.filter(owner=request.user, key=serializer.validated_data['key'],
                                     name=serializer.validated_data['name']).exists():
            return Response({'error': 'Name/Key combo should be unique'}, status=status.HTTP_400_BAD_REQUEST)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)


class CreateCredentialView(CreateAPIView):
    serializer_class = CredentialSerializer

    def create(self, request, *args, **kwargs):
        """
        Overwritten default `create` method in order to catch unique constraint violation.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if Credential.objects.filter(owner=request.user, key=serializer.validated_data['key'],
                                     name=serializer.validated_data['name']).exists():
            return Response({'error': 'Name/Key combo should be unique'}, status=status.HTTP_400_BAD_REQUEST)
        serializer.save(owner=self.request.user)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


@api_view(['GET'])
@permission_classes([AllowAny])
def mtls_is_claimed_view(request, format=None):
    """
    Return claimed status of a device.
    """
    device_id = is_mtls_authenticated(request)

    if not device_id:
        return Response(
            'Invalid request.',
            status=status.HTTP_400_BAD_REQUEST
        )
    if type(device_id) is Response:
        return device_id

    device = Device.objects.get(device_id=device_id)
    return Response({'claimed': device.claimed})
