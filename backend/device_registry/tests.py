import datetime
import json

from django.conf import settings
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from device_registry import ca_helper
from django.contrib.auth.models import User
from django.utils import timezone
from django.test import TestCase, RequestFactory
from rest_framework.test import APIRequestFactory
from .api_views import mtls_ping_view, claim_by_link
from .models import Device, DeviceInfo, PortScan, get_avg_trust_score


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
        self.device0 = Device.objects.create(device_id='device0.d.wott-dev.local')
        self.scan_info = [
                {"host": "localhost", "port": 22, "proto": "tcp", "state": "open"}
            ]
        self.ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device0',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'distr_id': 'Raspbian',
            'distr_release': '9.4',
            'scan_info': json.dumps(self.scan_info)
        }
        self.ping_headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
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
        scan_info = portscan.scan_info
        self.assertListEqual(scan_info, self.scan_info)

    def test_ping_distr_info(self):
        request = self.api.post(
            '/v0.2/ping/',
            self.ping_payload,
            **self.ping_headers
        )
        mtls_ping_view(request)
        self.assertEqual(self.device0.deviceinfo.distr_id, 'Raspbian')
        self.assertEqual(self.device0.deviceinfo.distr_release, '9.4')


TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAPMjGMrzQcI/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xOTAzMDUyMDE5MjRaFw0xOTA0MDQyMDE5MjRaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOgfhzltW1Bx/PLve7sk228G9FeBQmTVkEwiU1tgagvIzM8fhoeDnXoMVRf5
GPWZr4h0E4BtDRQUO7NqgW+r3RQMq4nJljTV9f8Om3Owx41BM5M5w5YH75JZzcZ1
OVBmJRPOG06I3Hk/uQjCGo1YN7ZggAdUmFQqQ03GdstqQhd6UzbV2dPphq+R2npV
oAjByawBwuxi+NJXxz20dUVkXrrxGgDUKcUn4NPsIUGf9hSHZcDMZ3XQcQQ/ykD9
i/zeVU6jGnsMOO+YZUguBlq/GKI2fzezfG7fv394oAJP9mV0T8k9ArciTigUehuv
a8sHA+vrvRXCNbpV8vEQbRh/+0sCAwEAAaM6MDgwFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0B
AQsFAAOCAQEAL+KRDdqbbAFiMROy7eNkbMUj3Dp4S24y5QnGjFl4eSFLWu9UhBT+
FcElSbo1vKaW5DJi+XG9snyZfqEuknQlBEDTuBlOEqguGpmzYE/+T0wt9zLTByN8
N44fGr4f9ORj6Y6HJkzdlp+XCDdzHb2+3ienNle6bWlmBpbQaMVrayDxJ5yxldgJ
czUUClEc0OJDMw8PsHyYvrl+jk0JFXgDqBgAutPzSiC+pWL3H/5DO8t/NcccNNlR
2UZyh8r3qmVWo1jROR98z/J59ytNgMfYTmVI+ClUWKF5OWEOneKTf7dvic0Bqiyb
1lti7kgwF5QeRU2eEn3VC2F5JreBMpTkeA==
-----END CERTIFICATE-----
"""


class DeviceModelTest(TestCase):
    def setUp(self):
        self.user0 = User.objects.create_user('test')
        self.user1 = User.objects.create_user('test-no-device')
        week_ago = timezone.now() - datetime.timedelta(days=7)
        hour_ago = timezone.now() - datetime.timedelta(hours=1)
        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            last_ping=week_ago,
            owner=self.user0,
            certificate=TEST_CERT
        )
        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user0
        )
        self.device2 = Device.objects.create(
            device_id='device2.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user0
        )
        self.device3 = Device.objects.create(
            device_id='device3.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user0
        )
        self.device_info0 = DeviceInfo.objects.create(
            device=self.device0,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            trust_score=0.6
        )
        self.device_info1 = DeviceInfo.objects.create(
            device=self.device1,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            trust_score=0.8
        )
        portscan0 = [
            {"host": "localhost", "port": 22, "proto": "tcp", "state": "open"},
            {"host": "localhost", "port": 25, "proto": "tcp", "state": "open"}
        ]
        portscan1 = [
            {"host": "localhost", "port": 80, "proto": "tcp", "state": "open"},
            {"host": "localhost", "port": 110, "proto": "tcp", "state": "open"}
        ]
        self.portscan0 = PortScan.objects.create(device=self.device0, scan_info=portscan0)
        self.portscan1 = PortScan.objects.create(device=self.device0, scan_info=portscan1)

    def test_get_model(self):
        model = self.device_info0.device_model
        self.device_info0.device_model = '000d'
        self.assertEqual(self.device_info0.get_model(), 'Model B Rev 2')
        self.device_info0.device_model = '000D'  # case insensitive
        self.assertEqual(self.device_info0.get_model(), 'Model B Rev 2')
        self.device_info0.device_model = model

    def test_get_hardware_type(self):
        hw_type = self.device_info0.get_hardware_type()
        self.assertEqual(hw_type, 'Raspberry Pi')

    def test_latest_portscan(self):
        latest_portscan = self.device0.get_latest_portscan()
        scans = set([si['port'] for si in latest_portscan])
        self.assertSetEqual({80, 110}, scans)

    def test_active_inactive(self):
        active_inactive = Device.get_active_inactive(self.user0)
        self.assertListEqual(active_inactive, [3, 1])

    def test_get_expiration_date(self):
        exp_date = self.device0.get_cert_expiration_date()
        self.assertEqual(exp_date.date(), datetime.date(2019, 4, 4))

    def test_bad_ports_score(self):
        score0 = self.portscan0.get_score()
        score1 = self.portscan1.get_score()
        self.assertEqual(score0, 0.6)
        self.assertEqual(score1, 0.7)

    def test_avg_trust_score(self):
        user = self.user0
        avg_score = get_avg_trust_score(user)
        self.assertEqual(avg_score, 0.7)

    def test_empty_avg_trust_score(self):
        user = self.user1
        avg_score = get_avg_trust_score(user)
        self.assertIsNone(avg_score)


class ClaimLinkTest(TestCase):
    def setUp(self):
        self.api = RequestFactory()
        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            claim_token='token'
        )
        self.user0 = User.objects.create_user('test')

    def test_claim_get_view(self):
        request = self.api.get(f'/api/v0.2/claim-device/?device-id={self.device0.device_id}&claim-token={self.device0.claim_token}')
        request.user = self.user0
        self.assertFalse(self.device0.claimed())
        response = claim_by_link(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, f'Device {self.device0.device_id} claimed!')
        self.device0.refresh_from_db()
        self.assertTrue(self.device0.claimed())

    def test_claim_get_404(self):
        request = self.api.get(f'/claim-device/?device-id=none&claim-token=none')
        request.user = self.user0
        response = claim_by_link(request)
        self.assertEqual(response.status_code, 404)
