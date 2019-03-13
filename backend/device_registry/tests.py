import json

from django.conf import settings
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from device_registry import ca_helper
from django.test import TestCase
from rest_framework.test import APIRequestFactory
from .api_views import mtls_ping_view
from .models import Device, DeviceInfo, PortScan


def generate_cert(common_name=None, subject_alt_name=None):
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(common_name)),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'UK'),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'London'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Web of Trusted Things'),
            ]))

    if subject_alt_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(u'{}'.format(subject_alt_name))]
            ),
            critical=False
        )

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    serialized_csr = csr.public_bytes(serialization.Encoding.PEM)

    return {
        'csr': serialized_csr.decode(),
        'key': serialized_private_key.decode()
    }


class CsrHelperTests(TestCase):

    def test_common_name_matches_san_and_device_id(self):
        """
        Test if the function returns True for when the
        device_id matches the common name and subject alt name.
        """

        device_id = 'foobar.{}'.format(settings.COMMON_NAME_PREFIX)
        cert = generate_cert(common_name=device_id, subject_alt_name=device_id)

        self.assertIs(
            ca_helper.csr_is_valid(csr=cert['csr'], device_id=device_id),
            True
        )

    def test_common_name_does_not_match_san(self):
        """
        csr_is_valid should return False when the common name
        does not match the subject alt name.
        """

        device_id = 'foobar.{}'.format(settings.COMMON_NAME_PREFIX)
        cert = generate_cert(
            common_name=device_id,
            subject_alt_name='foobar2.d.wott.local'
        )

        self.assertIs(
            ca_helper.csr_is_valid(csr=cert['csr'], device_id=device_id),
            False
        )

    def test_common_name_does_not_match_valid_domain(self):
        """
        csr_is_valid should return False when the common name
        does not match the accepted domain.
        """

        device_id = 'foobar.com'
        cert = generate_cert(
            common_name=device_id,
            subject_alt_name=device_id
        )

        self.assertIs(
            ca_helper.csr_is_valid(csr=cert['csr'], device_id=device_id),
            False
        )


class APIPingTest(TestCase):
    def setUp(self):
        self.api = APIRequestFactory()
        self.device0 = Device.objects.create(device_id='device0.d.wott.local')
        scan_info = [
                {"host": "localhost", "port": 22, "proto": "tcp", "state": "open"}
            ]
        self.ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'scan_info': json.dumps(scan_info)
        }
        self.ping_headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_ping_endpoint(self):
        request = self.api.post(
            '/v0.2/ping/',
            self.ping_payload,
            **self.ping_headers
        )
        response = mtls_ping_view(request)
        self.assertEqual(response.status_code, 200)

    def test_ping_creates_models(self):
        request = self.api.post(
            '/v0.2/ping/',
            self.ping_payload,
            **self.ping_headers
        )
        devinfo_obj_count_before = DeviceInfo.objects.count()
        portscan_obj_count_before = PortScan.objects.count()
        mtls_ping_view(request)
        devinfo_obj_count_after = DeviceInfo.objects.count()
        portscan_obj_count_after = PortScan.objects.count()
        self.assertEqual(devinfo_obj_count_before, 0)
        self.assertEqual(portscan_obj_count_before, 0)
        self.assertEqual(devinfo_obj_count_after, 1)
        self.assertEqual(portscan_obj_count_after, 1)

    def test_ping_writes_scan_info(self):
        request = self.api.post(
            '/v0.2/ping/',
            self.ping_payload,
            **self.ping_headers
        )
        mtls_ping_view(request)
        portscan = PortScan.objects.get(device=self.device0)
        self.assertJSONEqual(self.ping_payload['scan_info'], portscan.scan_info)
