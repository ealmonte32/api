from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase

from device_registry.models import Device, DeviceInfo, FirewallState, PortScan, DebPackage, Vulnerability, GlobalPolicy
from device_registry.recommended_actions import DefaultCredentialsAction, FirewallDisabledAction, AutoUpdatesAction,\
                                                VulnerablePackagesAction, MySQLDefaultRootPasswordAction,\
                                                InsecureServicesAction, OpensshConfigurationIssuesAction,\
                                                FtpServerAction, MongodbAction, MysqlAction, MemcachedAction,\
                                                CpuVulnerableAction


class NoDevicesActionTest(TestCase):
    def test_get(self):
        User = get_user_model()
        user = User.objects.create_user('test')
        user.set_password('123')
        user.save()
        self.client.login(username='test', password='123')
        common_actions_url = reverse('actions')
        search_string = 'In order to receive recommended actions'

        # No devices.
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, search_string)

        # Create a device.
        device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=user)
        FirewallState.objects.create(device=device)
        PortScan.objects.create(device=device)
        DeviceInfo.objects.create(device=device)
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, search_string)

        # Revoke the device.
        device.owner = None
        device.save(update_fields=['owner'])
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, search_string)


class TestsMixin:
    """
    A mixin with actual unified tests code.

    The reason of putting them in a separate mixin out of the base test class -
     is that otherwise the Django test runner considers the base test class as
     a regular test class and run its tests which isn't what we want from it.
    """

    def test_get(self):
        search_string_common_page = self.get_search_string()

        # No action at the beginning.
        self.assertEqual(self.device.actions_count, 0)
        response = self.client.get(self.common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, search_string_common_page)
        response = self.client.get(self.device_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.search_pattern_device_page)

        # Enable the action.
        self.enable_action()
        self.assertEqual(self.device.actions_count, 1)
        response = self.client.get(self.common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, search_string_common_page)
        response = self.client.get(self.device_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.search_pattern_device_page)

        # Snooze the action.
        self.snooze_action()
        self.assertEqual(self.device.actions_count, 0)
        response = self.client.get(self.common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, search_string_common_page)
        response = self.client.get(self.device_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.search_pattern_device_page)


class BaseActionTest(TestCase):
    """
    Base action test class.

    Doesn't supposed to be exectuted by the Django test runner because it
     doesn't contain real tests code.
    """

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user, auto_upgrades=True,
                                            mysql_root_access=False)
        FirewallState.objects.create(device=self.device, policy=FirewallState.POLICY_ENABLED_BLOCK)
        PortScan.objects.create(device=self.device)
        DeviceInfo.objects.create(device=self.device, default_password=False)
        self.client.login(username='test', password='123')
        self.device_page_url = reverse('device-detail', kwargs={'pk': self.device.pk})
        self.common_actions_url = reverse('actions')
        self.device_actions_url = reverse('device_actions', kwargs={'device_pk': self.device.pk})

    def get_search_string(self):
        return self.search_pattern_common_page % (self.device_page_url, self.device.get_name())

    def snooze_action(self):
        self.device.snooze_action(self.action_class.action_id)


class DefaultCredentialsActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found default credentials present on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found default credentials present on this node'
    action_class = DefaultCredentialsAction

    def enable_action(self):
        self.device.deviceinfo.default_password = True
        self.device.deviceinfo.save(update_fields=['default_password'])


class FirewallDisabledActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found permissive firewall policy present on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found permissive firewall policy present on this node'
    action_class = FirewallDisabledAction

    def enable_action(self):
        self.device.firewallstate.policy = FirewallState.POLICY_ENABLED_ALLOW
        self.device.firewallstate.save(update_fields=['policy'])


class FirewallPolicyActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found permissive firewall policy present on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found permissive firewall policy present on this node'
    action_class = FirewallDisabledAction

    def enable_action(self):
        policy = GlobalPolicy.objects.create(name='test policy', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        self.device.firewallstate.global_policy = policy
        self.device.firewallstate.save()


class VulnerablePackagesActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found vulnerable packages on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found vulnerable packages on this node'
    action_class = VulnerablePackagesAction

    def enable_action(self):
        self.device.deb_packages_hash = 'abcd'
        self.device.save(update_fields=['deb_packages_hash'])
        deb_package = DebPackage.objects.create(name='package', version='version1', source_name='package',
                                                source_version='sversion1', arch='amd64', os_release_codename='jessie')
        vulnerability = Vulnerability.objects.create(name='name', package='package', is_binary=True, other_versions=[],
                                                     urgency='L', fix_available=True, os_release_codename='jessie')
        deb_package.vulnerabilities.add(vulnerability)
        self.device.deb_packages.add(deb_package)


class AutoUpdatesActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found that your node <a href="%s">%s</a> is not configured to automatically ' \
                                 'install security updates'
    search_pattern_device_page = 'We found that this node is not configured to automatically install security updates'
    action_class = AutoUpdatesAction

    def enable_action(self):
        self.device.auto_upgrades = False
        self.device.save(update_fields=['auto_upgrades'])


class MySQLDefaultRootPasswordActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We detected that there is no root password set for MySQL/MariaDB on ' \
                                 '<a href="%s">%s</a>'
    search_pattern_device_page = 'We detected that there is no root password set for MySQL/MariaDB on this node'
    action_class = MySQLDefaultRootPasswordAction

    def enable_action(self):
        self.device.mysql_root_access = True
        self.device.save(update_fields=['mysql_root_access'])


class InsecureServicesActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found insecure services installed on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found insecure services installed on this node'
    action_class = InsecureServicesAction

    def enable_action(self):
        self.device.deb_packages_hash = 'abcd'
        self.device.save(update_fields=['deb_packages_hash'])
        deb_package = DebPackage.objects.create(name='telnetd', version='version1', source_name='telnetd',
                                                source_version='sversion1', arch='amd64', os_release_codename='jessie')
        self.device.deb_packages.add(deb_package)


class OpensshConfigurationIssuesActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We found insecure configuration issues with OpenSSH on <a href="%s">%s</a>'
    search_pattern_device_page = 'We found insecure configuration issues with OpenSSH on this node'
    action_class = OpensshConfigurationIssuesAction

    def enable_action(self):
        self.device.audit_files = [{'name': '/etc/ssh/sshd_config',
                                    'issues': {'PermitRootLogin': 'prohibit-password', 'AllowAgentForwarding': 'yes',
                                               'PasswordAuthentication': 'yes'},
                                    'sha256': 'abcd', 'last_modified': 1554718384.0}]
        self.device.save(update_fields=['audit_files'])


class FtpServerActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'There appears to be an FTP server running on <a href="%s">%s</a>'
    search_pattern_device_page = 'There appears to be an FTP server running on this node'
    action_class = FtpServerAction

    def enable_action(self):
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': '???', 'host': '0.0.0.0', 'port': 21, 'pid': 45678}
        ]
        self.device.portscan.save(update_fields=['scan_info'])


class MongodbActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We detected that a MongoDB instance on <a href="%s">%s</a> may be accessible ' \
                                 'remotely'
    search_pattern_device_page = 'We detected that a MongoDB instance on this node may be accessible remotely'
    action_class = MongodbAction

    def enable_action(self):
        self.device.deviceinfo.processes = {12345: ('mongod', '', 'mongo', None)}
        self.device.deviceinfo.save(update_fields=['processes'])
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': '???', 'host': '0.0.0.0', 'port': 27017, 'pid': 12345}
        ]
        self.device.portscan.save(update_fields=['scan_info'])


class MysqlActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We detected that a MySQL instance on <a href="%s">%s</a> may be accessible remotely'
    search_pattern_device_page = 'We detected that a MySQL instance on this node may be accessible remotely'
    action_class = MysqlAction

    def enable_action(self):
        self.device.deviceinfo.processes = {34567: ('mysqld', '', 'mysql', None)}
        self.device.deviceinfo.save(update_fields=['processes'])
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': '???', 'host': '0.0.0.0', 'port': 3306, 'pid': 34567}
        ]
        self.device.portscan.save(update_fields=['scan_info'])


class MemcachedActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We detected that a Memcached instance on <a href="%s">%s</a> may be accessible ' \
                                 'remotely'
    search_pattern_device_page = 'We detected that a Memcached instance on this node may be accessible remotely'
    action_class = MemcachedAction

    def enable_action(self):
        self.device.deviceinfo.processes = {34568: ('memcached', '', 'memcache', None)}
        self.device.deviceinfo.save(update_fields=['processes'])
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': 'LISTEN', 'host': '0.0.0.0', 'port': 11211, 'pid': 34568}
        ]
        self.device.portscan.save(update_fields=['scan_info'])


class CpuVulnerableActionTest(BaseActionTest, TestsMixin):
    search_pattern_common_page = 'We detected that <a href="%s">%s</a> is vulnerable to Meltdown/Spectre'
    search_pattern_device_page = 'We detected that this node is vulnerable to Meltdown/Spectre'
    action_class = CpuVulnerableAction

    def enable_action(self):
        pkg = DebPackage.objects.create(os_release_codename='buster', name='linux', version='5.0.0',
                                        source_name='linux', source_version='5.0.0', arch=DebPackage.Arch.i386)
        self.device.kernel_deb_package = pkg
        self.device.cpu = {'vendor': 'GenuineIntel', 'vulnerable': True}
        self.device.save()
