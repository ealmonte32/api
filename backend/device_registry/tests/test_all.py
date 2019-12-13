import json
import sys
from collections import defaultdict
from unittest.mock import patch, PropertyMock

from dateutil.relativedelta import relativedelta, TU, SU
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.urls import reverse
from django.test import TestCase
from django.utils.http import urlencode

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from freezegun import freeze_time

from device_registry import ca_helper
from device_registry.models import DebPackage, Device, DeviceInfo, FirewallState, PortScan, GlobalPolicy, PairingKey, \
    Vulnerability, RecommendedAction, HistoryRecord
from device_registry.forms import DeviceAttrsForm, PortsForm, ConnectionsForm, FirewallStateGlobalPolicyForm
from device_registry.forms import GlobalPolicyForm
from device_registry.recommended_actions import BaseAction, ActionMeta, Severity
from device_registry.views import CVEView
from profile_page.models import Profile


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


OPEN_PORTS_INFO = [{"host": "192.168.1.178", "port": 22, "proto": "tcp", "state": "open", "ip_version": 4}]

OPEN_CONNECTIONS_INFO = [
    {'ip_version': 4, 'type': 'tcp', 'local_address': ['192.168.1.178', 4567],
     'remote_address': ['192.168.1.177', 5678], 'status': 'open', 'pid': 3425}
]

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
        User = get_user_model()
        self.user0 = User.objects.create_user('test')
        self.user1 = User.objects.create_user('test-no-device')
        week_ago = timezone.now() - timezone.timedelta(days=7)
        hour_ago = timezone.now() - timezone.timedelta(hours=1)
        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            last_ping=week_ago,
            owner=self.user1,
            certificate=TEST_CERT
        )
        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user1
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
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )
        self.device_info1 = DeviceInfo.objects.create(
            device=self.device1,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )

        portscan0 = [
            {"host": "192.168.1.178", "port": 22, "proto": "tcp", "state": "open", "ip_version": 4},
            {"host": "192.168.1.178", "port": 25, "proto": "tcp", "state": "open", "ip_version": 4}
        ]
        portscan1 = [
            {"host": "192.168.1.178", "port": 80, "proto": "tcp", "state": "open", "ip_version": 4},
            {"host": "192.168.1.178", "port": 110, "proto": "tcp", "state": "open", "ip_version": 4}
        ]
        self.portscan0 = PortScan.objects.create(device=self.device0, scan_info=portscan0)
        self.portscan1 = PortScan.objects.create(device=self.device1, scan_info=portscan1)

        self.firewall0 = FirewallState.objects.create(device=self.device0, policy=FirewallState.POLICY_ENABLED_BLOCK)
        self.firewall1 = FirewallState.objects.create(device=self.device1, policy=FirewallState.POLICY_ENABLED_BLOCK)

        self.user4 = User.objects.create_user('test-fixing-issues')
        self.device4 = Device.objects.create(
            device_id='device4.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user4
        )
        self.device_info4 = DeviceInfo.objects.create(
            device=self.device4,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': False},
            app_armor_enabled=False,
            default_password=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )
        PortScan.objects.create(device=self.device4, scan_info=[
            {"host": "0.0.0.0", "port": 22, "proto": "tcp", "state": "open", "ip_version": 4},
            {"host": "::", "port": 22, "proto": "tcp", "state": "open", "ip_version": 6},
            {"host": "0.0.0.0", "port": 80, "proto": "tcp", "state": "open", "ip_version": 4},
            {"host": "::", "port": 80, "proto": "tcp", "state": "open", "ip_version": 6},
        ])
        self.firewall4 = FirewallState.objects.create(device=self.device4, policy=FirewallState.POLICY_ENABLED_ALLOW)

    def test_ftp_public_no_portscan(self):
        self.assertIsNone(self.device3.is_ftp_public)

    def test_fixed_issues(self):
        self.device4.update_trust_score_now()
        # initial state: firewall disabled, default password found - trust score low
        self.assertLess(self.device4.trust_score_percent(), 66)
        self.firewall4.policy = FirewallState.POLICY_ENABLED_BLOCK
        self.firewall4.save()
        self.device_info4.default_password = False
        self.device_info4.save()
        self.device4.update_trust_score_now()

        # result: trust score high
        self.assertGreaterEqual(self.device4.trust_score_percent(), 66)

    def test_get_model(self):
        model = self.device_info0.device_model
        self.device_info0.device_model = 'Model B Rev 2'
        self.assertEqual(self.device_info0.get_model(), 'Model B Rev 2')
        self.device_info0.device_model = model

    def test_get_hardware_type(self):
        hw_type = self.device_info0.get_hardware_type()
        self.assertEqual(hw_type, 'Raspberry Pi')

    def test_active_inactive(self):
        active_inactive = Device.get_active_inactive(self.user0)
        self.assertListEqual(active_inactive, [2, 0])

    def test_bad_ports_score(self):
        ps = self.device0.portscan
        self.assertIsNotNone(ps)
        score0 = self.portscan0.get_score()
        score1 = self.portscan1.get_score()
        self.assertEqual(score0, 0.6)
        self.assertEqual(score1, 0.7)

    def test_empty_average_trust_score(self):
        profile = Profile.objects.create(user=self.user0)
        avg_score = profile.average_trust_score
        self.assertIsNone(avg_score)

    def test_trust_score(self):
        self.device0.update_trust_score_now()
        self.device1.update_trust_score_now()
        all_good_except_port_score = sum(Device.COEFFICIENTS.values()) - Device.COEFFICIENTS['port_score']
        self.assertEqual(self.device0.trust_score,
                         (all_good_except_port_score + 0.6 * Device.COEFFICIENTS['port_score']) /
                         sum(Device.COEFFICIENTS.values()))
        self.assertEqual(self.device1.trust_score,
                         (all_good_except_port_score + 0.7 * Device.COEFFICIENTS['port_score']) /
                         sum(Device.COEFFICIENTS.values()))

    def test_cve_trust_score(self):
        # Reset port_score to 1,0 for simplicity.
        self.portscan0.scan_info = []
        self.portscan0.save()

        cve_score_coef = Device.COEFFICIENTS['cve_score']
        all_good_except_cve_score = sum(Device.COEFFICIENTS.values()) - cve_score_coef

        self.device0.update_trust_score_now()
        # All good, cve_score is 1.0 because no packages and no CVEs
        self.assertEqual(self.device0.trust_score,
                         (all_good_except_cve_score + 1.0 * cve_score_coef) /
                         sum(Device.COEFFICIENTS.values()))

        pkg1 = DebPackage.objects.create(os_release_codename='buster', name='linux', version='5.0.0',
                                         source_name='linux', source_version='5.0.0', arch=DebPackage.Arch.i386)
        pkg2 = DebPackage.objects.create(os_release_codename='buster', name='linux', version='5.0.1',
                                         source_name='linux', source_version='5.0.1', arch=DebPackage.Arch.i386)
        self.device0.deb_packages.add(pkg1)
        self.device0.deb_packages.add(pkg2)
        # Two deb packages have 10 high priority remotely exploitable CVEs.
        # This should max out cve_score and test for distinct filter.
        for i in range(10):
            vuln = Vulnerability.objects.create(os_release_codename='buster', name=f'CVE-{i}', package='linux',
                                                other_versions=[], is_binary=False, urgency=Vulnerability.Urgency.HIGH,
                                                fix_available=True, remote=True)
            pkg1.vulnerabilities.add(vuln)

        self.device0.update_trust_score_now()
        # Now cve_score is 0.0.
        self.assertEqual(self.device0.trust_score,
                         (all_good_except_cve_score + 0.0 * cve_score_coef) /
                         sum(Device.COEFFICIENTS.values()))

    def test_average_trust_score(self):
        profile = Profile.objects.create(user=self.user1)
        self.device0.update_trust_score_now()
        self.device1.update_trust_score_now()
        average_score = profile.average_trust_score
        real_average_score = ((self.device0.trust_score + self.device1.trust_score) / 2.0)
        self.assertLessEqual(abs(average_score - real_average_score), 2 * sys.float_info.epsilon)

    def test_heartbleed(self):
        self.assertIsNone(self.device0.heartbleed_vulnerable)

        self.device0.set_deb_packages([{
            'name': 'libssl',
            'version': '1.0.0',
            'source_name': 'openssl',
            'source_version': '1.0.0',
            'arch': 'i386'
        }], {'codename': 'stretch'})
        self.assertFalse(self.device0.heartbleed_vulnerable)

        v = Vulnerability.objects.create(name='CVE-2014-0160', package='openssl', unstable_version='',
                                         other_versions=[], is_binary=False, urgency=Vulnerability.Urgency.NONE,
                                         remote=None, fix_available=True, os_release_codename='stretch')
        self.device0.deb_packages.first().vulnerabilities.add(v)
        self.assertTrue(self.device0.heartbleed_vulnerable)

    def test_cpu_vulnerable(self):
        self.assertIsNone(self.device0.cpu_vulnerable)

        pkg = DebPackage.objects.create(os_release_codename='buster', name='linux', version='5.0.0',
                                        source_name='linux', source_version='5.0.0', arch=DebPackage.Arch.i386)
        self.device0.kernel_deb_package = pkg

        self.device0.cpu = {'vendor': 'GenuineIntel', 'vulnerable': True}
        self.device0.save()
        self.assertTrue(self.device0.cpu_vulnerable)

        self.device0.cpu = {'vendor': 'GenuineIntel', 'vulnerable': False}
        self.device0.save()
        self.assertFalse(self.device0.cpu_vulnerable)

        self.device0.cpu = {'vendor': 'GenuineIntel', 'vulnerable': None, 'mitigations_disabled': True}
        self.device0.save()
        self.assertTrue(self.device0.cpu_vulnerable)

        vuln = Vulnerability.objects.create(os_release_codename='buster', name='CVE-2017-5753', package='linux',
                                            other_versions=[], is_binary=False, urgency=Vulnerability.Urgency.HIGH,
                                            fix_available=True)
        pkg.vulnerabilities.add(vuln)
        pkg.save()
        self.device0.cpu = {'vendor': 'GenuineIntel', 'vulnerable': None, 'mitigations_disabled': False}
        self.device0.save()
        self.assertTrue(self.device0.cpu_vulnerable)

        self.device0.cpu = {'vendor': 'AuthenticAMD'}
        self.device0.save()
        self.assertFalse(self.device0.cpu_vulnerable)

    def test_ra_last_week(self):
        now = timezone.now()
        # Last week's tuesday
        last_tuesday = (now + relativedelta(days=-1, weekday=SU(-1)) + relativedelta(weekday=TU(-1))).date()
        ra0 = RecommendedAction.objects.create(device=self.device0, action_id=1,
                                               status=RecommendedAction.Status.NOT_AFFECTED)
        ra1 = RecommendedAction.objects.create(device=self.device0, action_id=2,
                                               status=RecommendedAction.Status.NOT_AFFECTED)
        ra2 = RecommendedAction.objects.create(device=self.device0, action_id=3,
                                               status=RecommendedAction.Status.SNOOZED_UNTIL_PING)

        self.assertEqual(self.device0.actions_count_last_week, 0)
        self.assertEqual(self.device0.actions_count_delta['count'], 0)
        self.assertEqual(self.device0.actions_count_delta['arrow'], 'up')

        with freeze_time(last_tuesday):
            ra0.status = RecommendedAction.Status.AFFECTED
            ra0.save()
            self.device0.sample_history()
        with freeze_time(last_tuesday + timezone.timedelta(days=1)):
            ra1.status = RecommendedAction.Status.AFFECTED
            ra1.save()
            self.device0.sample_history()
        self.assertEqual(self.device0.actions_count_last_week, 2)

        ra2.status = RecommendedAction.Status.AFFECTED
        ra2.save()
        self.assertEqual(self.device0.actions_count_delta['count'], 1)
        self.assertEqual(self.device0.actions_count_delta['arrow'], 'up')

        ra0.status = RecommendedAction.Status.NOT_AFFECTED
        ra2.status = RecommendedAction.Status.NOT_AFFECTED
        ra0.save()
        ra2.save()
        self.assertEqual(self.device0.actions_count_last_week, 2)
        self.assertEqual(self.device0.actions_count_delta['count'], 1)
        self.assertEqual(self.device0.actions_count_delta['arrow'], 'down')


class FormsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.device_info = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
        )
        self.portscan = PortScan.objects.create(device=self.device, scan_info=OPEN_PORTS_INFO,
                                                netstat=OPEN_CONNECTIONS_INFO)
        self.firewallstate = FirewallState.objects.create(device=self.device)

    def test_device_metadata_form(self):
        form_data = {'device_metadata': {"test": "value"}}
        form = DeviceAttrsForm(data=form_data, instance=self.device)
        self.assertTrue(form.is_valid())

    def test_device_attrs_form(self):
        form_data = {'comment': 'Test comment', 'name': 'My device 1'}
        form = DeviceAttrsForm(data=form_data, instance=self.device)
        self.assertTrue(form.is_valid())

    def test_ports_form(self):
        ports_form_data = self.portscan.ports_form_data()
        form_data = {'is_ports_form': 'true', 'open_ports': ['0'], 'policy': self.firewallstate.policy}
        form = PortsForm(data=form_data, ports_choices=ports_form_data[0])
        self.assertTrue(form.is_valid())

    def test_networks_form(self):
        connections_form_data = self.portscan.connections_form_data()
        form_data = {'is_connections_form': 'true', 'open_connections': ['0']}
        form = ConnectionsForm(data=form_data, open_connections_choices=connections_form_data[0])
        self.assertTrue(form.is_valid())

    def test_global_policy_form(self):
        gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        form_data = {'global_policy': str(gp.pk)}
        form = FirewallStateGlobalPolicyForm(data=form_data, instance=self.firewallstate)
        self.assertTrue(form.is_valid())


class DeviceDetailViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        Profile.objects.create(user=self.user, unlimited_customer=True)
        self.user2 = User.objects.create_user('user')
        self.device = Device.objects.create(
            device_id='device0.d.wott-dev.local', owner=self.user, certificate=TEST_CERT,
            cpu={'vulnerable': True, 'vendor': 'GenuineIntel'},
            certificate_expires=timezone.datetime(2019, 7, 4, 13, 55, tzinfo=timezone.utc))
        self.deviceinfo = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )
        self.portscan = PortScan.objects.create(device=self.device, scan_info=OPEN_PORTS_INFO,
                                                netstat=OPEN_CONNECTIONS_INFO)
        self.firewall = FirewallState.objects.create(device=self.device, policy=FirewallState.POLICY_ENABLED_BLOCK)
        self.url = reverse('device-detail', kwargs={'pk': self.device.pk})
        self.url2 = reverse('device-detail-software', kwargs={'pk': self.device.pk})
        self.url3 = reverse('device-detail-security', kwargs={'pk': self.device.pk})
        self.url4 = reverse('device-detail-network', kwargs={'pk': self.device.pk})
        self.url5 = reverse('device-detail-hardware', kwargs={'pk': self.device.pk})
        self.url6 = reverse('device-detail-metadata', kwargs={'pk': self.device.pk})

        self.device_no_portscan = Device.objects.create(device_id='device1.d.wott-dev.local', owner=self.user,
                                                        certificate=TEST_CERT)
        self.firewall2 = FirewallState.objects.create(device=self.device_no_portscan)

        self.device_no_firewall = Device.objects.create(device_id='device2.d.wott-dev.local', owner=self.user,
                                                        certificate=TEST_CERT)
        self.portscan2 = PortScan.objects.create(device=self.device_no_firewall, scan_info=OPEN_PORTS_INFO,
                                                 netstat=OPEN_CONNECTIONS_INFO)

        self.device_no_logins = Device.objects.create(
            device_id='device3.d.wott-dev.local', owner=self.user, certificate=TEST_CERT,
            certificate_expires=timezone.datetime(2019, 7, 4, 13, 55, tzinfo=timezone.utc))
        self.deviceinfo3 = DeviceInfo.objects.create(
            device=self.device_no_logins,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={},
            default_password=True
        )
        self.portscan3 = PortScan.objects.create(device=self.device_no_logins, scan_info=OPEN_PORTS_INFO,
                                                 netstat=OPEN_CONNECTIONS_INFO)
        self.firewall3 = FirewallState.objects.create(device=self.device_no_logins)
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)

    def test_device_detail_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/')

    def test_device_detail_software_not_logged_in(self):
        response = self.client.get(self.url2)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/software/')

    def test_device_detail_security_not_logged_in(self):
        response = self.client.get(self.url3)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/security/')

    def test_device_detail_network_not_logged_in(self):
        response = self.client.get(self.url4)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/network/')

    def test_device_detail_hardware_not_logged_in(self):
        response = self.client.get(self.url5)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/hardware/')

    def test_device_detail_metadata_not_logged_in(self):
        response = self.client.get(self.url6)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/metadata/')

    def test_credentials_not_logged_in(self):
        url = reverse('credentials')
        response = self.client.get(url)
        self.assertRedirects(response, '/accounts/login/?next=/credentials/')

    def test_get(self):
        """
        If no questions exist, an appropriate message is displayed.
        """
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Node Profile')
        self.assertEqual(self.device.actions_count, 0)
        self.assertNotContains(response, 'Show recommended actions')

    def test_actions_btn_pos(self):
        self.client.login(username='test', password='123')
        self.device_no_logins.generate_recommended_actions()
        url = reverse('device-detail', kwargs={'pk': self.device_no_logins.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertGreater(self.device_no_logins.actions_count, 0)
        self.assertContains(response, 'Recommended Actions')

    def test_no_portscan(self):
        """
        Neither Hardware nor Security tabs should be rendered if Device object
        has no PortScan.
        """
        url = reverse('device-detail', kwargs={'pk': self.device_no_portscan.pk})
        self.client.login(username='test', password='123')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Node Profile')
        self.assertNotContains(response, '<a id="tab-security"')
        self.assertNotContains(response, '<a id="tab-hardware"')

    def test_no_firewall(self):
        """
        Security tab should not be rendered if Device object has no FirewallState.
        """
        url = reverse('device-detail', kwargs={'pk': self.device_no_firewall.pk})
        self.client.login(username='test', password='123')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Node Profile')
        self.assertContains(response, '<a id="tab-hardware"')
        self.assertNotContains(response, '<a id="tab-security"')

    def test_device_metadata(self):
        self.client.login(username='test', password='123')
        form_data = {'device_metadata': '{"test": "value"}'}
        self.client.post(self.url6, form_data)
        response = self.client.get(self.url6)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.context_data["device"].deviceinfo.device_metadata, {"test": "value"})

    def test_comment(self):
        self.client.login(username='test', password='123')
        form_data = {'comment': 'Test comment'}
        self.client.post(self.url, form_data)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test comment')

    def test_device_name(self):
        self.client.login(username='test', password='123')
        form_data = {'name': 'My device 1'}
        self.client.post(self.url, form_data)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'My device 1')

    def test_open_ports(self):
        self.client.login(username='test', password='123')
        form_data = {'is_ports_form': 'true', 'open_ports': ['0'], 'policy': self.firewall.policy}
        self.client.post(self.url3, form_data)
        portscan = PortScan.objects.get(pk=self.portscan.pk)
        self.assertListEqual(portscan.block_ports, [['192.168.1.178', 'tcp', 22, False]])
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Firewall Ports Policy')
        self.assertInHTML('<span class="pl-1" id="ports-table-column-1">Allowed</span>', response.rendered_content)

    def test_open_ports_global_policy(self):
        self.client.login(username='test', password='123')
        form_data = {'is_ports_form': 'true', 'open_ports': ['0'], 'policy': self.firewall.policy}
        self.client.post(self.url3, form_data)
        portscan = PortScan.objects.get(pk=self.portscan.pk)
        self.assertListEqual(portscan.block_ports, [['192.168.1.178', 'tcp', 22, False]])
        self.firewall.global_policy = self.gp
        self.firewall.save(update_fields=['global_policy'])
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Open Ports')
        self.assertNotContains(response, '<th scope="col" width="5%"><span\n                                      '
                                         'id="ports-table-column-1">Allowed</span></th>')

    def test_open_ports_forbidden(self):
        self.client.login(username='test', password='123')
        self.firewall.global_policy = self.gp
        self.firewall.save(update_fields=['global_policy'])
        form_data = {'is_ports_form': 'true', 'open_ports': ['0'], 'policy': self.firewall.policy}
        response = self.client.post(self.url3, form_data)
        self.assertEqual(response.status_code, 403)

    def test_open_connections(self):
        self.client.login(username='test', password='123')
        form_data = {'is_connections_form': 'true', 'open_connections': ['0']}
        self.client.post(self.url3, form_data)
        portscan = PortScan.objects.get(pk=self.portscan.pk)
        self.assertListEqual(portscan.block_networks, [['192.168.1.177', False]])
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertInHTML('<input type="checkbox" value="0" id="connections-check-all">Blocked',
                          response.rendered_content)

    def test_open_connections_global_policy(self):
        self.client.login(username='test', password='123')
        form_data = {'is_connections_form': 'true', 'open_connections': ['0']}
        self.client.post(self.url3, form_data)
        portscan = PortScan.objects.get(pk=self.portscan.pk)
        self.assertListEqual(portscan.block_networks, [['192.168.1.177', False]])
        self.firewall.global_policy = self.gp
        self.firewall.save(update_fields=['global_policy'])
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, '<th scope="col" width="5%">Blocked</th>')

    def test_open_connections_forbidden(self):
        self.client.login(username='test', password='123')
        self.firewall.global_policy = self.gp
        self.firewall.save(update_fields=['global_policy'])
        form_data = {'is_connections_form': 'true', 'open_connections': ['0']}
        response = self.client.post(self.url3, form_data)
        self.assertEqual(response.status_code, 403)

    def test_no_logins(self):
        self.client.login(username='test', password='123')
        url = reverse('device-detail-security', kwargs={'pk': self.device_no_logins.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No recent login attempts detected')

    def test_logins(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<pre class="mb-0">pi:')
        self.assertContains(response, 'success: 1')

    def test_insecure_services(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'telnetd')
        self.assertNotContains(response, 'fingerd')
        self.assertNotContains(response, 'No insecure services detected')

        self.device.set_deb_packages([
            {'name': 'python2', 'version': 'VERSION', 'source_name': 'python2', 'source_version': 'abcd',
             'arch': 'i386', 'os_release_codename': 'jessie'},
            {'name': 'python3', 'version': 'VERSION', 'source_name': 'python3', 'source_version': 'abcd',
             'arch': 'i386', 'os_release_codename': 'jessie'}
        ], {'codename': 'jessie'})
        self.device.deb_packages_hash = 'abcdef'
        self.device.save()
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'telnetd')
        self.assertNotContains(response, 'fingerd')
        self.assertContains(response, 'No insecure services detected')
        self.assertListEqual(list(self.device.deb_packages.values('name', 'version', 'arch', 'os_release_codename')),
                             [{'name': 'python2', 'version': 'VERSION', 'arch': 'i386',
                               'os_release_codename': 'jessie'},
                              {'name': 'python3', 'version': 'VERSION', 'arch': 'i386',
                               'os_release_codename': 'jessie'}])

        self.device.set_deb_packages([
            {'name': 'telnetd', 'version': 'VERSION', 'source_name': 'telnetd', 'source_version': 'abcd',
             'arch': 'i386', 'os_release_codename': 'jessie'},
            {'name': 'fingerd', 'version': 'VERSION', 'source_name': 'fingerd', 'source_version': 'abcd',
             'arch': 'i386', 'os_release_codename': 'jessie'}
        ], {'codename': 'jessie'})
        self.device.save()
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'telnetd')
        self.assertContains(response, 'fingerd')
        self.assertNotContains(response, 'No insecure services detected')
        self.assertListEqual(list(self.device.deb_packages.values('name', 'version', 'arch', 'os_release_codename')),
                             [{'name': 'telnetd', 'version': 'VERSION', 'arch': 'i386',
                               'os_release_codename': 'jessie'},
                              {'name': 'fingerd', 'version': 'VERSION', 'arch': 'i386',
                               'os_release_codename': 'jessie'}])

    def test_heartbleed_render(self):
        self.device.deb_packages_hash = 'aabbccdd'
        self.client.login(username='test', password='123')
        response = self.client.get(self.url3)
        self.assertNotContains(response, 'Patched against Heartbleed')

        self.device.set_deb_packages([{
            'name': 'libssl',
            'version': '1.0.0',
            'source_name': 'openssl',
            'source_version': '1.0.0',
            'arch': 'i386'
        }], {'codename': 'stretch'})
        self.device.save()

        response = self.client.get(self.url3)
        self.assertInHTML("""<th class="wott-table-label" scope="row">Patched against Heartbleed</th>
                             <td>
                               <span class="p-1 text-success"><i class="fas fa-check" ></i></span>
                               Yes
                             </td>""", response.rendered_content)

        v = Vulnerability.objects.create(name='CVE-2014-0160', package='openssl', unstable_version='',
                                         other_versions=[], is_binary=False, urgency=Vulnerability.Urgency.NONE,
                                         remote=None, fix_available=True, os_release_codename='stretch')
        self.device.deb_packages.first().vulnerabilities.add(v)

        response = self.client.get(self.url3)
        self.assertInHTML("""<th class="wott-table-label" scope="row">Patched against Heartbleed</th>
                             <td>
                               <span class="p-1 text-danger"><i class="fas fa-exclamation-circle" ></i></span>
                               No
                             </td>""", response.rendered_content)

    def test_cpu_vulnerable_render(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url3)
        self.assertContains(response, 'Patched against Meltdown/Spectre')

        self.device.cpu['vendor'] = 'AuthenticAMD'
        self.device.save()
        response = self.client.get(self.url3)
        self.assertNotContains(response, 'Patched against Meltdown/Spectre')

    def test_global_policies_list(self):
        gp2 = GlobalPolicy.objects.create(name='gp2', owner=self.user2, policy=GlobalPolicy.POLICY_ALLOW)
        self.client.login(username='test', password='123')
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        # Current user's global policy is available as an option.
        self.assertContains(response, '<option value="%d">%s</option>' % (self.gp.pk, self.gp.name))
        # Other user's global policy is not available as an option.
        self.assertNotContains(response, '<option value="%d">%s</option>' % (gp2.pk, gp2.name))

    @patch('django.utils.timezone.now')
    def test_get_device_detail_software(self, mock_timezone):
        mock_timezone.return_value = timezone.datetime(2019, 11, 5, tzinfo=timezone.utc)
        self.client.login(username='test', password='123')
        # Unknown distro.
        response = self.client.get(self.url2)
        self.assertInHTML('<td class="pl-4" id="eol_info">N/A</td>', response.rendered_content)
        # Supported distro version.
        self.device.os_release = {'distro': 'raspbian', 'version': '10', 'codename': 'buster',
                                  'distro_root': 'debian', 'full_version': '10 (buster)'}
        self.device.save(update_fields=['os_release'])
        response = self.client.get(self.url2)
        # print(response.content)
        self.assertInHTML('<td class="pl-4" id="eol_info">July 1, 2022</td>', response.rendered_content)
        # Outdated distro version.
        self.device.os_release = {'distro': 'debian', 'version': '7', 'codename': 'wheezy',
                                  'distro_root': 'debian', 'full_version': '7 (wheezy)'}
        self.device.save(update_fields=['os_release'])
        response = self.client.get(self.url2)
        self.assertInHTML('<td class="pl-4" id="eol_info"><span class="p-1 text-danger"><i '
                          'class="fas fa-exclamation-circle" ></i></span>May 31, 2018</td>',
                          response.rendered_content)

    def test_default_credentials(self):
        self.client.login(username='test', password='123')

        self.device.deviceinfo.default_password = False
        self.device.deviceinfo.save()
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No default credentials detected.")

        self.device.deviceinfo.default_password = True
        self.device.deviceinfo.save()
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Default credentials detected!")

        self.device.default_password_users = ['pi', 'root']
        self.device.save()
        response = self.client.get(self.url3)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Users with default credentials: pi, root")


class PairingKeysView(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.url = reverse('pairing-keys')
        self.pairing_key = PairingKey.objects.create(owner=self.user)

    def test_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, '/accounts/login/?next=/pairing-keys/')

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Pairing Keys')

    def test_get_file(self):
        self.client.login(username='test', password='123')
        url = f'/pairing-keys/download?pk={self.pairing_key.pk}'
        data = f'[DEFAULT]\n\nenroll_token = {self.pairing_key.key.hex}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode("utf-8"), data)


class RootViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        Profile.objects.create(user=self.user, unlimited_customer=True)

        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            certificate=TEST_CERT,
            name='First',
            last_ping=timezone.now() - timezone.timedelta(days=1, hours=1)
        )
        DeviceInfo.objects.create(
            device=self.device0,
            fqdn='FirstFqdn',
            default_password=False,
            detected_mirai=True,
        )

        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            owner=self.user,
            certificate=TEST_CERT,
            last_ping=timezone.now() - timezone.timedelta(days=2, hours=23)
        )
        DeviceInfo.objects.create(
            device=self.device1,
            fqdn='SecondFqdn',
            default_password=True,
            detected_mirai=True,
        )
        PortScan.objects.create(device=self.device0)
        PortScan.objects.create(device=self.device1)
        FirewallState.objects.create(device=self.device0)
        FirewallState.objects.create(device=self.device1)
        [d.generate_recommended_actions() for d in (self.device0, self.device1)]

    def test_wizard(self):
        self.client.login(username='test', password='123')
        response = self.client.get(reverse('root'))
        self.assertContains(response, 'tour.start();')
        response = self.client.post(reverse('wizard-complete'))
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse('root'))
        self.assertNotContains(response, 'tour.start();')

    def test_no_filter(self):
        self.client.login(username='test', password='123')
        url = reverse('root')
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0, self.device1])

    def test_filter_date(self):
        self.client.login(username='test', password='123')

        url = reverse('root') + '?' + urlencode({
            'filter_by': 'last-ping',
            'filter_predicate': 'eq',
            'filter_value': '1,days'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0])

        url = reverse('root') + '?' + urlencode({
            'filter_by': 'last-ping',
            'filter_predicate': 'eq',
            'filter_value': '2,days'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device1])

        url = reverse('root') + '?' + urlencode({
            'filter_by': 'last-ping',
            'filter_predicate': 'lt',
            'filter_value': '1,days'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0, self.device1])

        url = reverse('root') + '?' + urlencode({
            'filter_by': 'last-ping',
            'filter_predicate': 'gt',
            'filter_value': '1,days'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [])

    def test_filter_name(self):
        self.client.login(username='test', password='123')

        # Context-insensitive filter by node name set in device.name (exact match)
        url = reverse('root') + '?' + urlencode({
            'filter_by': 'device-name',
            'filter_predicate': 'eq',
            'filter_value': 'first'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0])

        # Context-insensitive filter by node name set in deviceinfo.fqdn (exact match)
        url = reverse('root') + '?' + urlencode({
            'filter_by': 'device-name',
            'filter_predicate': 'eq',
            'filter_value': 'firstfqdn'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0])

        # Context-insensitive filter by node name set in device.name (not match)
        url = reverse('root') + '?' + urlencode({
            'filter_by': 'device-name',
            'filter_predicate': 'neq',
            'filter_value': 'first'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device1])

        # Context-insensitive filter by node name set in device.name (contains)
        url = reverse('root') + '?' + urlencode({
            'filter_by': 'device-name',
            'filter_predicate': 'c',
            'filter_value': 'fir'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device0])

        # Context-insensitive filter by node name set in device.name (not contains)
        url = reverse('root') + '?' + urlencode({
            'filter_by': 'device-name',
            'filter_predicate': 'nc',
            'filter_value': 'fir'
        })
        response = self.client.get(url)
        self.assertListEqual(list(response.context['object_list']), [self.device1])

    def test_recommended_actions_count(self):
        self.client.login(username='test', password='123')
        self.assertEqual(self.user.profile.actions_count, 2)
        self.assertEqual(self.device0.actions_count, 1)
        self.assertEqual(self.device1.actions_count, 2)
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertInHTML('<div class="badge wott-badge-pill">'
                          '<span id="actions-sidebar" class="wott-badge-text">2</span></div>',
                          response.rendered_content)

    def test_recommended_actions_zero(self):
        self.client.login(username='test', password='123')
        self.user.devices.set([])  # no devices => no actions
        self.assertEqual(self.user.profile.actions_count, 0)
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertInHTML('<div class="badge wott-badge-pill">'
                          '<span id="actions-sidebar" class="wott-badge-text">0</span></div>',
                          response.rendered_content, count=0)  # check that there is NO badge


class SaveDeviceSettingsAsPolicyViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.portscan = PortScan.objects.create(device=self.device, scan_info=OPEN_PORTS_INFO,
                                                netstat=OPEN_CONNECTIONS_INFO)
        self.firewallstate = FirewallState.objects.create(device=self.device)
        self.url = reverse('save_as_policy', kwargs={'pk': self.device.pk})

    def test_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f'/accounts/login/?next=/devices/{self.device.pk}/security/save-as-policy/')

    def test_get(self):
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        # TODO: check page content.

    def test_get_forbidden(self):
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        self.client.login(username='test', password='123')
        gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        self.firewallstate.global_policy = gp
        self.firewallstate.save(update_fields=['global_policy'])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(GlobalPolicy.objects.count(), 1)


class GlobalPolicyDeleteViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        self.url = reverse('delete_global_policy', kwargs={'pk': self.gp.pk})

    def test_not_logged_in(self):
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        response = self.client.post(self.url)
        self.assertRedirects(response, f'/accounts/login/?next=/policies/{self.gp.pk}/delete/')
        self.assertEqual(GlobalPolicy.objects.count(), 1)

    def test_post(self):
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        self.client.login(username='test', password='123')
        response = self.client.post(self.url)
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        self.assertRedirects(response, '/policies/')


class GlobalPolicyEditViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        self.url = reverse('edit_global_policy', kwargs={'pk': self.gp.pk})

    def test_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, f'/accounts/login/?next=/policies/{self.gp.pk}/')

    def test_get(self):
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<input type="text" name="name" value="gp1"')
        self.assertContains(response, '<option value="1" selected>Allow by default</option>')
        self.assertContains(response, '[]</textarea>')

    def test_post(self):
        self.client.login(username='test', password='123')
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK)}
        response = self.client.post(self.url, form_data)
        self.assertRedirects(response, '/policies/')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<input type="text" name="name" value="My policy"')
        self.assertContains(response, '<option value="2" selected>Block by default</option>')

    def test_post_non_unique_name(self):
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        GlobalPolicy.objects.create(owner=self.user, name='Policy 1', policy=GlobalPolicy.POLICY_ALLOW)
        self.assertEqual(GlobalPolicy.objects.count(), 2)
        self.client.login(username='test', password='123')
        form_data = {'name': 'Policy 1', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(None)}
        response = self.client.post(self.url, form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Global policy with this name already exists.')
        self.assertEqual(GlobalPolicy.objects.count(), 2)


class GlobalPolicyCreateViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.url = reverse('create_global_policy')

    def test_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, '/accounts/login/?next=/policies/add/')

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_post(self):
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        self.client.login(username='test', password='123')
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK)}
        response = self.client.post(self.url, form_data)
        self.assertRedirects(response, '/policies/')
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        gp = GlobalPolicy.objects.all()[0]
        response = self.client.get(reverse('edit_global_policy', kwargs={'pk': gp.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<input type="text" name="name" value="My policy"')
        self.assertContains(response, '<option value="2" selected>Block by default</option>')

    def test_post_non_unique_name(self):
        self.assertEqual(GlobalPolicy.objects.count(), 0)
        GlobalPolicy.objects.create(owner=self.user, name='Policy 1', policy=GlobalPolicy.POLICY_ALLOW)
        self.assertEqual(GlobalPolicy.objects.count(), 1)
        self.client.login(username='test', password='123')
        form_data = {'name': 'Policy 1', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(None)}
        response = self.client.post(self.url, form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Global policy with this name already exists.')
        self.assertEqual(GlobalPolicy.objects.count(), 1)


class GlobalPoliciesListViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='test', password='123')
        self.url = reverse('global_policies')

    def test_not_logged_in(self):
        response = self.client.get(self.url)
        self.assertRedirects(response, '/accounts/login/?next=/policies/')

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<th class="col-3">Firewall Ports Policy</th>')


class GlobalPolicyFormTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)

    def test_success(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False},
                      {'address': '2002:c0a8:101::', 'protocol': 'udp', 'port': 34, 'ip_version': True}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_wrong_key(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False},
                      {'address': '0.0.0.1', 'xxx': 'yyy', 'protocol': 'udp', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['Wrong or missing fields.']})

    def test_missing_key(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False},
                      {'address': '0.0.0.1', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['Wrong or missing fields.']})

    def test_duplicated_rule(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False},
                      {'address': '0.0.0.1', 'protocol': 'udp', 'port': 34, 'ip_version': False},
                      {'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"0.0.0.0:34/udp" is a duplicating/conflicting rule.']})

    def test_wrong_address(self):
        ports_data = [{'address': '0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"0.0.0" is not a correct IP address.']})

    def test_wrong_protocol(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'xxx', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"xxx" is not a valid protocol value.']})

    def test_wrong_port_type(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': '34', 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"34" is not a valid port value.']})

    def test_wrong_port_value(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': -34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"-34" is not a valid port value.']})

    def test_wrong_ip_version(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': 'false'}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"false" is not a valid IP version field value.']})

    def test_wrong_ipv6_address(self):
        ports_data = [{'address': '0.0.0.0', 'protocol': 'udp', 'port': 34, 'ip_version': True}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"0.0.0.0" is wrong IP address format for IPv6.']})

    def test_wrong_ipv4_address(self):
        ports_data = [{'address': '2002:c0a8:101::', 'protocol': 'udp', 'port': 34, 'ip_version': False}]
        form_data = {'name': 'My policy', 'policy': str(GlobalPolicy.POLICY_BLOCK), 'ports': json.dumps(ports_data)}
        form = GlobalPolicyForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'ports': ['"2002:c0a8:101::" is wrong IP address format for IPv4.']})


class ClaimDeviceViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.claim_token = 'abcd'
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local',
                                            claim_token=self.claim_token)
        self.client.login(username='test', password='123')

    def test_post(self):
        settings.MIXPANEL_TOKEN = ''
        response = self.client.post(reverse('claim-device'), {
            'device_id': self.device.device_id,
            'claim_token': self.claim_token
        })
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.owner, self.user)

    def test_post_track(self):
        settings.MIXPANEL_TOKEN = 'abcd'
        with patch('profile_page.models.Mixpanel') as MockMixpanel:
            mixpanel_instance = MockMixpanel.return_value
            mixpanel_instance.track.return_value = None
            response = self.client.post(reverse('claim-device'), {
                'device_id': self.device.device_id,
                'claim_token': self.claim_token
            })
            self.assertEqual(response.status_code, 200)
            self.device.refresh_from_db()
            self.assertEqual(self.device.owner, self.user)
            mixpanel_instance.track.assert_called_once_with(self.user.email, 'First Node')


class DashboardViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')
        self.url = reverse('dashboard')
        self.profile = Profile.objects.create(user=self.user)

        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user
        )
        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            owner=self.user
        )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        severities = [Severity.LO, Severity.HI, Severity.MED, Severity.MED,
                      Severity.HI, Severity.MED, Severity.MED, Severity.HI]
        cls.test_actions = []
        for i in range(len(severities)):
            class TestActionOne(BaseAction, metaclass=ActionMeta):
                """
                A simple dummy action class with specified severity.
                """
                action_id = 9990 + i
                severity = severities[i]
                action_config = defaultdict(str)

            cls.test_actions.append(TestActionOne)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        for a in cls.test_actions:
            ActionMeta.unregister(a)

    def test_empty(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data['weekly_progress'], 0)
        self.assertListEqual(response.context_data['actions'], [])

    def test_weekly_ra(self):
        today = timezone.now()
        RecommendedAction.objects.bulk_create([
            # Both devices affected - counts as one RA.
            # This one is low severity and will be displaced by three other RAs below.
            RecommendedAction(action_id=self.test_actions[0].action_id, device=self.device0,
                              status=RecommendedAction.Status.AFFECTED),
            RecommendedAction(action_id=self.test_actions[0].action_id, device=self.device1,
                              status=RecommendedAction.Status.AFFECTED),

            # both devices affected - counts as one RA
            RecommendedAction(action_id=self.test_actions[1].action_id, device=self.device0,
                              status=RecommendedAction.Status.AFFECTED),
            RecommendedAction(action_id=self.test_actions[1].action_id, device=self.device1,
                              status=RecommendedAction.Status.AFFECTED),

            # one device is affected, second was never affected (and never fixed)
            RecommendedAction(action_id=self.test_actions[2].action_id, device=self.device0,
                              status=RecommendedAction.Status.NOT_AFFECTED),
            RecommendedAction(action_id=self.test_actions[2].action_id, device=self.device1,
                              status=RecommendedAction.Status.AFFECTED),

            # one device is affected, second fixed - still not fixed
            RecommendedAction(action_id=self.test_actions[3].action_id, device=self.device0,
                              status=RecommendedAction.Status.NOT_AFFECTED,
                              resolved_at=today),
            RecommendedAction(action_id=self.test_actions[3].action_id, device=self.device1,
                              status=RecommendedAction.Status.AFFECTED),

            # fixed on both devices - completely fixed
            RecommendedAction(action_id=self.test_actions[4].action_id, device=self.device0,
                              status=RecommendedAction.Status.NOT_AFFECTED,
                              resolved_at=today),
            RecommendedAction(action_id=self.test_actions[4].action_id, device=self.device1,
                              status=RecommendedAction.Status.NOT_AFFECTED,
                              resolved_at=today),

            # one never affected, another one fixed - completely fixed
            RecommendedAction(action_id=self.test_actions[5].action_id, device=self.device0,
                              status=RecommendedAction.Status.NOT_AFFECTED),
            RecommendedAction(action_id=self.test_actions[5].action_id, device=self.device1,
                              status=RecommendedAction.Status.NOT_AFFECTED,
                              resolved_at=today),

            # resolved a week ago - doesn't count
            RecommendedAction(action_id=self.test_actions[6].action_id, device=self.device1,
                              status=RecommendedAction.Status.NOT_AFFECTED,
                              resolved_at=today - timezone.timedelta(days=7)),

            # snoozed - doesn't count
            RecommendedAction(action_id=self.test_actions[7].action_id, device=self.device1,
                              status=RecommendedAction.Status.SNOOZED_FOREVER)
        ])
        # expected result: 1, 2, 3 - unfixed, 4, 5 - fixed
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual([(a.action_id, a.resolved) for a in response.context_data['actions']],
                             [(self.test_actions[1].action_id, False),
                              (self.test_actions[2].action_id, False),
                              (self.test_actions[3].action_id, False),
                              (self.test_actions[4].action_id, True),
                              (self.test_actions[5].action_id, True)])
        self.assertEqual(response.context_data['weekly_progress'], 40)


class CVEViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.user_unrelated = User.objects.create_user('unrelated')
        self.client.login(username='test', password='123')
        self.profile = Profile.objects.create(user=self.user)

        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            deb_packages_hash='abcd',
            os_release={'codename': 'stretch'}
        )
        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            owner=self.user
        )
        self.device_unrelated = Device.objects.create(
            device_id='device-unrelated.d.wott-dev.local',
            owner=self.user_unrelated
        )
        self.url = reverse('cve')
        self.device_url = reverse('device_cve', kwargs={'device_pk': self.device0.pk})

        self.packages = [
            DebPackage(name='one_first', version='version_one', source_name='one_source',
                       source_version='one_version', arch=DebPackage.Arch.i386),
            DebPackage(name='one_second', version='version_one', source_name='one_source',
                       source_version='one_version', arch=DebPackage.Arch.i386),
            DebPackage(name='two_first', version='version_two', source_name='two_source', source_version='two_version',
                       arch=DebPackage.Arch.i386),
            DebPackage(name='two_second', version='version_two', source_name='two_source',
                       source_version='two_version', arch=DebPackage.Arch.i386),
        ]
        self.today = timezone.now().date()
        self.vulns = [
            Vulnerability(os_release_codename='stretch', name='CVE-2018-1', package='one_source', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=True),
            Vulnerability(os_release_codename='buster', name='CVE-2018-2', package='one_source', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=True,
                          pub_date=self.today),
            Vulnerability(os_release_codename='stretch', name='CVE-2018-3', package='one_source', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=False)
        ]
        DebPackage.objects.bulk_create(self.packages)
        Vulnerability.objects.bulk_create(self.vulns)
        self.device0.deb_packages.set(self.packages)
        self.device_unrelated.deb_packages.set(self.packages)

    @staticmethod
    def _hyperlinks(devices):
        return [CVEView.Hyperlink(text=device.get_name(), href=reverse('device_cve', kwargs={'device_pk': device.pk}))
                for device in devices]

    def test_sort_package_hosts_affected(self):
        self.packages[0].vulnerabilities.set(self.vulns)
        self.packages[1].vulnerabilities.set(self.vulns[1:])
        self.device1.deb_packages.set(self.packages[1:])

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.context_data['table_rows'], [
            CVEView.TableRow(cve_name='CVE-2018-2', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                # These two AffectedPackage's should be sorted by hosts_affected
                CVEView.AffectedPackage('one_second', 2, self._hyperlinks([self.device0, self.device1])),
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0]))
            ], cve_date=self.today),
            CVEView.TableRow(cve_name='CVE-2018-1', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0]))
            ])
        ])

    def test_sort_urgency(self):
        self.vulns[1].urgency = Vulnerability.Urgency.HIGH
        self.vulns[1].save()
        self.packages[0].vulnerabilities.set(self.vulns)
        self.packages[1].vulnerabilities.set(self.vulns)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.context_data['table_rows'], [
            # These two TableRow's should be sorted by urgency
            CVEView.TableRow(cve_name='CVE-2018-2', cve_url='', urgency=Vulnerability.Urgency.HIGH, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0])),
                CVEView.AffectedPackage('one_second', 1, self._hyperlinks([self.device0]))
            ], cve_date=self.today),
            CVEView.TableRow(cve_name='CVE-2018-1', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0])),
                CVEView.AffectedPackage('one_second', 1, self._hyperlinks([self.device0]))
            ])
        ])

    def test_sort_total_hosts_affected(self):
        self.packages[0].vulnerabilities.set(self.vulns)
        self.packages[1].vulnerabilities.set(self.vulns[1:])

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.context_data['table_rows'], [
            # These two TableRow's should be sorted by the sum of hosts_affected
            CVEView.TableRow(cve_name='CVE-2018-2', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0])),
                CVEView.AffectedPackage('one_second', 1, self._hyperlinks([self.device0]))
            ], cve_date=self.today),
            CVEView.TableRow(cve_name='CVE-2018-1', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0]))
            ])
        ])

    def test_filter_device(self):
        # The setup is the same as in test_sort_package_hosts_affected.
        # The result should also be the same except without device1.
        self.packages[0].vulnerabilities.set(self.vulns)
        self.packages[1].vulnerabilities.set(self.vulns[1:])
        self.device1.deb_packages.set(self.packages[1:])

        response = self.client.get(self.device_url)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.context_data['table_rows'], [
            CVEView.TableRow(cve_name='CVE-2018-2', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0])),
                CVEView.AffectedPackage('one_second', 1, self._hyperlinks([self.device0]))
            ], cve_date=self.today),
            CVEView.TableRow(cve_name='CVE-2018-1', cve_url='', urgency=Vulnerability.Urgency.LOW, packages=[
                CVEView.AffectedPackage('one_first', 1, self._hyperlinks([self.device0]))
            ])
        ])


class CVECountTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.user_unrelated = User.objects.create_user('unrelated')
        self.client.login(username='test', password='123')
        self.profile = Profile.objects.create(user=self.user)

        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            deb_packages_hash='abcd',
            os_release={'codename': 'stretch'}
        )
        self.device_unrelated = Device.objects.create(
            device_id='device-unrelated.d.wott-dev.local',
            owner=self.user_unrelated
        )
        self.url = reverse('cve')
        self.device_url = reverse('device_cve', kwargs={'device_pk': self.device0.pk})
        self.today = timezone.now().date()

        self.packages = [
            DebPackage(name='one_first', version='version_one', source_name='one_source', source_version='one_version',
                       arch=DebPackage.Arch.i386),
            DebPackage(name='one_second', version='version_one', source_name='one_source',
                       source_version='one_version', arch=DebPackage.Arch.i386),
            DebPackage(name='two_first', version='version_two', source_name='two_source', source_version='two_version',
                       arch=DebPackage.Arch.i386),
            DebPackage(name='two_second', version='version_two', source_name='two_source',
                       source_version='two_version', arch=DebPackage.Arch.i386),
        ]
        DebPackage.objects.bulk_create(self.packages)
        self.vulns = [
            Vulnerability(os_release_codename='stretch', name='CVE-2018-1', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.HIGH, fix_available=True),
            Vulnerability(os_release_codename='buster', name='CVE-2018-2', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.MEDIUM, fix_available=True,
                          pub_date=self.today),
            Vulnerability(os_release_codename='buster', name='CVE-2018-3', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.MEDIUM, fix_available=True,
                          pub_date=self.today),
            Vulnerability(os_release_codename='stretch', name='CVE-2018-4', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=True),
            Vulnerability(os_release_codename='stretch', name='CVE-2018-5', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=True),
            Vulnerability(os_release_codename='stretch', name='CVE-2018-6', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=True),
            Vulnerability(os_release_codename='stretch', name='CVE-2018-7', package='', is_binary=False,
                          other_versions=[], urgency=Vulnerability.Urgency.LOW, fix_available=False)
        ]
        Vulnerability.objects.bulk_create(self.vulns)
        self.packages[0].vulnerabilities.set(self.vulns)
        self.packages[1].vulnerabilities.set(self.vulns)

        self.device0.deb_packages.set(self.packages)
        self.device_unrelated.deb_packages.set(self.packages)

    def test_cve_count(self):
        self.assertDictEqual(self.device0.cve_count, {'high': 1, 'med': 2, 'low': 3})

    def test_cve_count_history(self):
        self.profile.sample_history()
        history_record = HistoryRecord.objects.get()
        self.assertEquals(history_record.cve_high_count, 1)
        self.assertEquals(history_record.cve_medium_count, 2)
        self.assertEquals(history_record.cve_low_count, 3)

    def test_cve_count_empty_history(self):
        now = timezone.now()
        # Last week's tuesday
        last_tuesday = (now + relativedelta(days=-1, weekday=SU(-1)) + relativedelta(weekday=TU(-1))).date()

        with freeze_time(last_tuesday):
            self.profile.sample_history()
        with freeze_time(last_tuesday + timezone.timedelta(days=1)):
            self.profile.sample_history()

        # Last week's history without CVE counts - a week after this code was merged.
        HistoryRecord.objects.update(cve_high_count=None,
                                     cve_medium_count=None,
                                     cve_low_count=None)
        # Make sure it's not (None, None, None)
        self.assertTupleEqual(self.profile.cve_count_last_week, (0, 0, 0))

    def test_cve_count_last_week(self):
        # No history -> all CVE counts should be 0
        self.assertTupleEqual(self.profile.cve_count_last_week, (0, 0, 0))

        now = timezone.now()
        # Last week's tuesday
        last_tuesday = (now + relativedelta(days=-1, weekday=SU(-1)) + relativedelta(weekday=TU(-1))).date()

        with freeze_time(last_tuesday):
            self.profile.sample_history()
        with freeze_time(last_tuesday + timezone.timedelta(days=1)):
            self.profile.sample_history()

        self.assertTupleEqual(self.profile.cve_count_last_week, (1, 2, 3))


class DevicePaymentStatusTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device1 = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.device2 = Device.objects.create(device_id='device1.d.wott-dev.local', owner=self.user)
        self.device3 = Device.objects.create(device_id='device2.d.wott-dev.local', owner=self.user)

    def test_user_no_profile(self):
        self.assertEqual(self.device1.payment_status, 'free')
        self.assertEqual(self.device2.payment_status, 'unpaid')
        self.assertEqual(self.device3.payment_status, 'unpaid')

    def test_user_has_profile(self):
        Profile.objects.create(user=self.user)
        self.assertEqual(self.device1.payment_status, 'free')
        self.assertEqual(self.device2.payment_status, 'unpaid')
        self.assertEqual(self.device3.payment_status, 'unpaid')

    def test_unlimited_customer(self):
        Profile.objects.create(user=self.user, unlimited_customer=True)
        self.assertEqual(self.device1.payment_status, 'free')
        self.assertEqual(self.device2.payment_status, 'paid')
        self.assertEqual(self.device3.payment_status, 'paid')

    @patch('profile_page.models.Profile.paid_nodes_number', new_callable=PropertyMock)
    def test_paid_one_device(self, mock_paid_nodes_number):
        mock_paid_nodes_number.return_value = 1
        Profile.objects.create(user=self.user)
        self.assertEqual(self.device1.payment_status, 'free')
        self.assertEqual(self.device2.payment_status, 'paid')
        self.assertEqual(self.device3.payment_status, 'unpaid')
        mock_paid_nodes_number.assert_called()


class UnpaidNodesPagesTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device1 = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.device2 = Device.objects.create(device_id='device1.d.wott-dev.local', owner=self.user)
        self.device3 = Device.objects.create(device_id='device2.d.wott-dev.local', owner=self.user)
        for device in (self.device1, self.device2, self.device3):
            DeviceInfo.objects.create(device=device)
            PortScan.objects.create(device=device)
            FirewallState.objects.create(device=device)
        self.url_pattern_names = (
            'device-detail', 'device-detail-software', 'device-detail-security', 'device-detail-network',
            'device-detail-hardware', 'device-detail-metadata', 'device_actions'
        )
        self.client.login(username='test', password='123')

    def test_free_device(self):
        for url_pattern in self.url_pattern_names:
            url = reverse(url_pattern, kwargs={'pk': self.device1.pk})
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)

    @patch('profile_page.models.Profile.paid_nodes_number', new_callable=PropertyMock)
    def test_paid_device(self, mock_paid_nodes_number):
        mock_paid_nodes_number.return_value = 1
        for url_pattern in self.url_pattern_names:
            url = reverse(url_pattern, kwargs={'pk': self.device2.pk})
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)

    @patch('profile_page.models.Profile.paid_nodes_number', new_callable=PropertyMock)
    def test_unpaid_device(self, mock_paid_nodes_number):
        mock_paid_nodes_number.return_value = 1
        for url_pattern in self.url_pattern_names:
            url = reverse(url_pattern, kwargs={'pk': self.device3.pk})
            response = self.client.get(url)
            self.assertEqual(response.status_code, 403)
