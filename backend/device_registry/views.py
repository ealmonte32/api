import logging
import cfssl
import uuid

from backend import settings
from device_registry import ca_helper
from device_registry.models import Device
from device_registry.serializers import DeviceSerializer
from django.db import IntegrityError
from rest_framework import permissions
from rest_framework import status
from rest_framework.decorators import api_view, renderer_classes, permission_classes
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response


logger = logging.getLogger(__name__)


@api_view(['GET'])
def device_list_view(request, format=None):
    """
    List all of the users devices.
    """
    devices = Device.objects.filter(owner=request.user)
    serializer = DeviceSerializer(devices, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@renderer_classes((JSONRenderer,))
@permission_classes((permissions.AllowAny,))
def get_ca_view(request, format=None):
    """
    Returns the root cert from the CA
    """

    cf = cfssl.cfssl.CFSSL(
            host=settings.CFSSL_SERVER,
            port=settings.CFSSL_PORT,
            ssl=False
    )

    ca = cf.info(label='primary')['certificate']
    return Response({'ca_certificate': ca})


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
        return Response({
            'certificate': device_info[0].certificate,
            'certificate_expires': device_info[0].certificate_expires,
            'device_id': device_id,
        })
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

    signed_cert = ca_helper.sign_csr(csr, device_id)
    if not signed_cert:
        return Response(
            'Unknown error',
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    certificate_expires = ca_helper.get_certificate_expiration_date(signed_cert)

    Device.objects.update(
        device_id=device_id,
        certificate=signed_cert,
        certificate_expires=certificate_expires,
    )

    return Response({
        'certificate': signed_cert,
        'certificate_expires': certificate_expires,
        'device_id': device_id,
    })
