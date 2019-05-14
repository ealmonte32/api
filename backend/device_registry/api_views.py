import logging
import uuid
import re

from django.http import HttpResponse
from django.utils import timezone
from django.conf import settings
from django.db import IntegrityError
from django.shortcuts import get_object_or_404

from rest_framework import permissions
from rest_framework import status
from rest_framework.decorators import api_view, renderer_classes, permission_classes
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from device_registry import ca_helper
from device_registry.serializers import DeviceInfoSerializer
from device_registry.datastore_helper import datastore, datastore_client
from .models import Device, DeviceInfo, FirewallState, PortScan


logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes((permissions.IsAuthenticated,))
def device_list_view(request, format=None):
    """
    List all of the users devices.
    """
    infos = DeviceInfo.objects.filter(device__owner=request.user)
    serializer = DeviceInfoSerializer(infos, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@renderer_classes((JSONRenderer,))
@permission_classes((permissions.AllowAny,))
def get_ca_bundle_view(request, format=None):
    """
    Returns the root cert bundle
    """

    with open('files/cert-bundle.crt') as f:
        ca_bundle = f.read()

    return Response({'ca_bundle': ca_bundle})


@api_view(['GET'])
@renderer_classes((JSONRenderer,))
@permission_classes((permissions.AllowAny,))
def get_ca_view(request, format=None):
    """
    Returns the CA cert
    """
    return Response({'ca_certificate': ca_helper.get_ca_certificate()})


@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
def generate_device_id_view(request, format=None):
    """
    Returns a device ID for enrolling a new device.
    """

    cert_in_use = True
    while cert_in_use:
        device_id = '{}.{}'.format(
            uuid.uuid4().hex,
            settings.COMMON_NAME_PREFIX
        )
        if not Device.objects.filter(device_id=device_id):
            return Response({'device_id': device_id})
    return Response(
        'Unknown error',
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
def get_device_cert_view(request, device_id, format=None):
    """
    Returns a device certificate from the database.
    """
    device_info = Device.objects.filter(device_id=device_id)

    if device_info:
        if 'format' in request.GET:
            return Response({
                'certificate': device_info[0].certificate,
                'certificate_expires': device_info[0].certificate_expires,
                    'is_expired': device_info[0].certificate_expires < timezone.now(),
                'device_id': device_id,
            })
        else:
            response = HttpResponse(device_info[0].certificate, content_type='application/x-pem-file')
            response['Content-Disposition'] = 'attachment; filename={}.crt'.format(device_id)
            return response
    return Response('Device not found', status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes((permissions.AllowAny,))
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
@permission_classes((permissions.AllowAny,))
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
        return Response({'message': 'pong'})
    elif request.method == 'POST':
        device_object = Device.objects.get(device_id=device_id)
        device_object.last_ping = timezone.now()
        device_info_object, _ = DeviceInfo.objects.get_or_create(device=device_object)
        device_info_object.device__last_ping = timezone.now()
        device_info_object.device_operating_system_version = request.data.get('device_operating_system_version')
        device_info_object.fqdn = request.data.get('fqdn')
        device_info_object.ipv4_address = request.data.get('ipv4_address')
        device_info_object.device_manufacturer = request.data.get('device_manufacturer')
        device_info_object.device_model = request.data.get('device_model')
        device_info_object.distr_id = request.data.get('distr_id', None)
        device_info_object.distr_release = request.data.get('distr_release', None)
        device_info_object.save()
        portscan_object, _ = PortScan.objects.get_or_create(device=device_object)
        portscan_object.scan_info = request.data.get('scan_info', [])
        portscan_object.netstat = request.data.get('netstat', [])
        block_networks = portscan_object.block_networks.copy()
        block_networks.extend(settings.SPAM_NETWORKS)
        portscan_object.save()
        firewall_state, _ = FirewallState.objects.get_or_create(device=device_object)
        firewall_state.enabled = request.data.get('firewall_enabled', None)
        firewall_state.rules = request.data.get('firewall_rules', {})
        firewall_state.save()
        device_object.save(update_fields=['last_ping'])

        if datastore_client:
            task_key = datastore_client.key('Ping')
            entity = datastore.Entity(key=task_key)
            for k, v in request.data.items():
                entity[k] = v
            entity['device_id'] = device_id
            entity['last_ping'] = timezone.now()
            datastore_client.put(entity)

        return Response({'block_ports': portscan_object.block_ports, 'block_networks': block_networks})


@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
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
@permission_classes((permissions.AllowAny,))
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
        'fallback_token': device_object.fallback_token
    })


@api_view(['POST'])
@permission_classes((permissions.AllowAny,))
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

    device_object = Device.objects.get(device_id=device_id)

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
        'fallback_token': device_object.fallback_token
    })


@api_view(['POST'])
@permission_classes((permissions.AllowAny,))
def action_view(request, action_id, action_name):
    # Perform action
    return Response({
        'id': action_id,
        'name': action_name
    })


@api_view(['GET'])
@permission_classes((permissions.IsAuthenticated,))
def claim_by_link(request):
    params = request.query_params
    device = get_object_or_404(
        Device,
        claim_token=params['claim-token'],
        device_id=params['device-id'],
        owner__isnull=True
    )
    if device:
        device.owner = request.user
        device.save()
        return Response(f'Device {device.device_id} claimed!')
    return Response('Device not found', status=status.HTTP_404_NOT_FOUND)

