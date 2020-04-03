from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from device_registry.models import Device, DeviceInfo, FirewallState, PortScan, DebPackage, Vulnerability, \
    GlobalPolicy, RecommendedAction, RecommendedActionStatus
from device_registry.recommended_actions import DefaultCredentialsAction, FirewallDisabledAction, AutoUpdatesAction, \
    MySQLDefaultRootPasswordAction, FtpServerAction, CpuVulnerableAction, ActionMeta, \
    Action, PUBLIC_SERVICE_PORTS, GithubAction, EnrollAction, INSECURE_SERVICES, InsecureServicesAction, \
    SSHD_CONFIG_PARAMS_INFO, OpensshIssueAction, PubliclyAccessibleServiceAction, Severity, SimpleAction, ParamStatus, \
    AuditdNotInstalledAction, RebootRequiredAction, CVEAction

from freezegun import freeze_time

from profile_page.models import Profile


class NoDevicesActionTest(TestCase):
    def test_get(self):
        User = get_user_model()
        user = User.objects.create_user('test')
        user.set_password('123')
        user.save()
        self.client.login(username='test', password='123')
        common_actions_url = reverse('actions')

        # No devices.
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(EnrollAction.__name__, [a.action_class for a in response.context_data['actions']])

        # Create a device.
        device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=user)
        FirewallState.objects.create(device=device)
        PortScan.objects.create(device=device)
        DeviceInfo.objects.create(device=device)
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(EnrollAction.__name__, [a.action_class for a in response.context_data['actions']])

        # Revoke the device.
        device.owner = None
        device.save(update_fields=['owner'])
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(EnrollAction.__name__, [a.action_class for a in response.context_data['actions']])


class GithubActionTest(TestCase):
    def test_get(self):
        User = get_user_model()
        user = User.objects.create_user('test')
        user.set_password('123')
        user.save()
        common_actions_url = reverse('actions')
        self.client.login(username='test', password='123')

        # The user has one device - no "Enroll your nodes" RA.
        device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=user)
        device_actions_url = reverse('device_actions', kwargs={'device_pk': device.pk})

        # Github integration is not set up - RA is shown at the common actions page.
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['actions']), 1)
        self.assertIn(GithubAction.__name__, [a.action_class for a in response.context_data['actions']])

        # This RA should not be shown on the per-device action page.
        response = self.client.get(device_actions_url)
        self.assertNotIn(GithubAction.__name__, [a.action_class for a in response.context_data['actions']])

        # Set up Github integration - RA should disappear.
        user.profile.github_repo_id = 1234
        user.profile.github_oauth_token = 'abcd'
        user.profile.save()
        response = self.client.get(common_actions_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(GithubAction.__name__, [a.action_class for a in response.context_data['actions']])


class GenerateActionsTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        class TestActionOne(SimpleAction, metaclass=ActionMeta):
            """
            A simple dummy subclass of BaseAction which always reports devices as affected and has a hopefully unique id.
            """
            affected = False
            _severity = Severity.LO

            @classmethod
            def _is_affected(cls, device) -> bool:
                return cls.affected

        class TestActionTwo(SimpleAction, metaclass=ActionMeta):
            """
            A simple dummy subclass of BaseAction which always reports devices as affected and has a hopefully unique id.
            """
            affected = False
            _severity = Severity.LO

            @classmethod
            def _is_affected(cls, device) -> bool:
                return cls.affected

        cls.TestActionOne = TestActionOne
        cls.TestActionTwo = TestActionTwo

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        ActionMeta.unregister(cls.TestActionOne)
        ActionMeta.unregister(cls.TestActionTwo)

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.TestActionOne.affected = False
        self.TestActionTwo.affected = False

    def check_actions_status(self, status_one, status_two, classes=None):
        self.device.generate_recommended_actions(classes)
        self.assertQuerysetEqual(self.device.recommendedactionstatus_set
                                 .filter(ra__action_class__in=[self.TestActionOne.__name__,
                                                           self.TestActionTwo.__name__])
                                 .order_by('ra__action_class')
                                 .values_list('ra__action_class', 'status'),
                                 [(self.TestActionOne.__name__, status_one.value),
                                  (self.TestActionTwo.__name__, status_two.value)],
                                 transform=lambda v: v)

    def test_generate_recommended_actions(self):
        self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.NOT_AFFECTED)

        self.TestActionOne.affected = True
        self.check_actions_status(RecommendedAction.Status.AFFECTED, RecommendedAction.Status.NOT_AFFECTED)

        self.TestActionTwo.affected = True
        self.check_actions_status(RecommendedAction.Status.AFFECTED, RecommendedAction.Status.AFFECTED)

        self.TestActionOne.affected = False
        self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.AFFECTED)

    def test_snooze(self):
        self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.NOT_AFFECTED)
        self.TestActionOne.affected = True
        self.TestActionTwo.affected = True
        self.device.snooze_action(self.TestActionOne.__name__, None, RecommendedAction.Status.SNOOZED_UNTIL_PING)
        self.check_actions_status(RecommendedAction.Status.SNOOZED_UNTIL_PING, RecommendedAction.Status.AFFECTED)

        self.TestActionOne.affected = False
        self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.AFFECTED)

    def test_classes(self):
        self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.NOT_AFFECTED)
        self.TestActionOne.affected = True
        self.TestActionTwo.affected = True
        self.check_actions_status(RecommendedAction.Status.AFFECTED, RecommendedAction.Status.NOT_AFFECTED,
                                  classes=[self.TestActionOne])

    def test_resolved_at(self):
        self.TestActionOne.affected = True
        self.TestActionTwo.affected = True
        self.check_actions_status(RecommendedAction.Status.AFFECTED, RecommendedAction.Status.AFFECTED)
        now = timezone.now()
        with freeze_time(now):
            self.TestActionOne.affected = False
            self.check_actions_status(RecommendedAction.Status.NOT_AFFECTED, RecommendedAction.Status.AFFECTED)
        ra = RecommendedActionStatus.objects.get(device=self.device, ra__action_class=self.TestActionOne.__name__)
        self.assertEquals(ra.resolved_at, now)


class ResolvedTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        class TestAction(SimpleAction, metaclass=ActionMeta):
            """
            A simple dummy subclass of BaseAction which always reports devices as affected and has a hopefully unique id.
            """
            affected = True
            affected_device = None
            action_config = {
                'long': '',
                'title': '',
                'short': ''
            }
            _severity = Severity.LO

            @classmethod
            def _is_affected(cls, device) -> bool:
                return device == cls.affected_device

        cls.TestAction = TestAction

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        ActionMeta.unregister(cls.TestAction)

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device_one = Device.objects.create(device_id='a.d.wott-dev.local', owner=self.user,
                                                last_ping=timezone.now(), name="One")
        self.device_two = Device.objects.create(device_id='u.d.wott-dev.local', owner=self.user,
                                                last_ping=timezone.now(), name="Two")
        self.TestAction.affected_device = None

    def check_description(self, is_none):
        self.device_one.generate_recommended_actions(classes=[self.TestAction])
        self.device_two.generate_recommended_actions(classes=[self.TestAction])
        desc = self.TestAction.get_description(self.user)
        if is_none:
            self.assertIsNone(desc)
        else:
            self.assertIsNotNone(desc)
            return desc[1]

    def test_description(self):
        # Initially no devices are affected - no description.
        self.check_description(is_none=True)

        # One device gets affected - description should list it but not the second device
        # which was never affected.
        self.TestAction.affected_device = self.device_one
        body = self.check_description(is_none=False)
        self.assertIn(f'- [ ] [{self.device_one.get_name()}]', body)
        self.assertNotIn(f'[{self.device_two.get_name()}]', body)

        # Second device gets affected, first gets unaffected (resolved). Description should
        # list first device as "resolved" (ticked) and the second unticked.
        self.TestAction.affected_device = self.device_two
        body = self.check_description(is_none=False)
        self.assertIn(f'- [x] [{self.device_one.get_name()}]', body)
        self.assertIn(f'- [ ] [{self.device_two.get_name()}]', body)

        # Both devices get unaffected (resolved) - no description, issue closed.
        self.TestAction.affected_device = None
        self.check_description(is_none=True)

    def test_last_ping(self):
        self.TestAction.affected_device = self.device_one

        self.check_description(is_none=False)
        with freeze_time(timezone.now() + timezone.timedelta(days=1)):
            # Devices which pinged more than a day ago are ignored.
            self.check_description(is_none=True)


class SnoozeTest(TestCase):
    """
    Test snoozing functionality.
    setUpClass() and tearDownClass() were overloaded to register and unregister TestAction only once.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        class TestAction(SimpleAction, metaclass=ActionMeta):
            """
            A simple dummy subclass of BaseAction which always reports devices as affected and has a hopefully unique id.
            """
            action_config = {
                'title': '',
                'subtitle': '',
                'short': '',
                'long': ''
            }
            _severity = Severity.LO

            @classmethod
            def _is_affected(cls, device) -> bool:
                return True

        cls.TestAction = TestAction

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        ActionMeta.unregister(cls.TestAction)

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        Profile.objects.create(user=self.user, github_repo_id=1234, github_oauth_token='abcd')
        self.client.login(username='test', password='123')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user,
                                            os_release={'codename': 'jessie'})
        gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_BLOCK, ports=[],
                                         networks=[])
        FirewallState.objects.create(device=self.device, global_policy=gp)
        deb_package = DebPackage.objects.create(name='auditd', version='version1', source_name='auditd',
                                                source_version='sversion1', arch='amd64', os_release_codename='jessie')
        self.device.deb_packages.add(deb_package)
        self.device.generate_recommended_actions()
        self.common_actions_url = reverse('actions')
        self.snooze_url = reverse('snooze_action')

    def _assertHasAction(self, has_action, generate=True):
        if generate:
            self.device.generate_recommended_actions(classes=[self.TestAction])
        response = self.client.get(self.common_actions_url)
        self.assertEqual(response.status_code, 200)
        if has_action:
            self.assertEqual(len(response.context['actions']), 1)
            self.assertEqual(response.context['actions'][0].action_class, self.TestAction.__name__)
        else:
            self.assertEqual(len(response.context['actions']), 0)

    def test_snooze_forever(self):
        self._assertHasAction(True)
        self.snooze_action(0)
        self._assertHasAction(False)
        with freeze_time(timezone.now() + timezone.timedelta(days=10)):
            self._assertHasAction(False)

    def test_snooze_until_ping(self):
        self._assertHasAction(True)
        self.snooze_action(None)
        self._assertHasAction(False, False)  # Don't generate RAs -> will stay "fixed"
        self._assertHasAction(True, True)    # Generate RAs -> will be "unfixed" again

    def test_snooze_interval(self):
        self._assertHasAction(True)

        with freeze_time(timezone.now() - timezone.timedelta(hours=23)):
            # 23 hours ago this action had been snoozed for 24 hours
            # self.device.snooze_action(self.TestAction.action_id, RecommendedAction.Status.SNOOZED_UNTIL_TIME, 24)
            self.snooze_action(24)

        # ... which means now it's still snoozed
        self._assertHasAction(False)

        # ... but in an hour from now it won't be snoozed anymore
        with freeze_time(timezone.now() + timezone.timedelta(hours=1)):
            self._assertHasAction(True)

    def snooze_action(self, duration):
        response = self.client.post(self.snooze_url, data={'device_ids': [self.device.pk],
                                                           'action_class': self.TestAction.__name__,
                                                           'action_param': None,
                                                           'duration': duration},
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)


class TestsMixin:
    """
    A mixin with actual unified tests code.

    The reason of putting them in a separate mixin out of the base test class -
     is that otherwise the Django test runner considers the base test class as
     a regular test class and run its tests which isn't what we want from it.
    """

    param = None

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user, auto_upgrades=True,
                                            mysql_root_access=False, last_ping=timezone.now(),
                                            os_release={'codename': 'jessie'})
        gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_BLOCK,
                                         ports=[], networks=[])
        FirewallState.objects.create(device=self.device, global_policy=gp)
        PortScan.objects.create(device=self.device)
        DeviceInfo.objects.create(device=self.device, default_password=False)
        self.client.login(username='test', password='123')
        Profile.objects.create(user=self.user, github_repo_id = 1234, github_oauth_token = 'abcd')
        self.device_page_url = reverse('device-detail', kwargs={'pk': self.device.pk})
        self.common_actions_url = reverse('actions')
        self.device_actions_url = reverse('device_actions', kwargs={'device_pk': self.device.pk})
        deb_package = DebPackage.objects.create(name='auditd', version='version1', source_name='auditd',
                                                source_version='sversion1', arch='amd64', os_release_codename='jessie')
        self.device.deb_packages.add(deb_package)

    def assertOneAction(self, url):
        self.assertEqual(self.device.actions_count, 1)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['actions']), 1)
        return response.context['actions'][0]

    def assertNoAction(self, url):
        self.assertEqual(self.device.actions_count, 0)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['actions']), 0)

    def test_get(self):
        # No action at the beginning.
        self.device.generate_recommended_actions()
        affected = self.action_class.affected_params(self.device)
        self.assertFalse(any(a.affected for a in affected))
        # self.assertFalse(self.action_class.affected_devices(self.user.devices.all()).exists())
        self.assertNoAction(self.common_actions_url)
        self.assertNoAction(self.device_actions_url)
        self.assertIsNone(self.action_class.get_description(self.user, self.param))

        # Enable the action.
        self.enable_action()
        self.device.generate_recommended_actions()
        affected = self.action_class.affected_params(self.device)
        self.assertIn(ParamStatus(self.param, True), affected)
        # self.assertTrue(self.action_class.affected_devices(self.user.devices.all()).exists())
        self.check_action(self.assertOneAction(self.common_actions_url))
        self.check_action(self.assertOneAction(self.device_actions_url))
        self.check_description()

    def check_description(self):
        title, text, affected, resolved = self.action_class.get_description(self.user, self.param)
        # Just check that title and text are not None and not empty.
        self.assertTrue(title)
        self.assertTrue(text)
        self.assertEquals(affected[0], self.device)

    def check_action(self, action: Action):
        self.assertEquals(action.action_class, self.action_class.__name__)

    def get_search_string(self):
        return self.search_pattern_common_page.format(url=self.device_page_url, name=self.device.get_name())


class DefaultCredentialsActionTest(TestsMixin, TestCase):
    action_class = DefaultCredentialsAction
    param = 'pi'

    def enable_action(self):
        self.device.default_password_users = ['pi']
        self.device.save(update_fields=['default_password_users'])


class FirewallDisabledActionTest(TestsMixin, TestCase):
    action_class = FirewallDisabledAction

    def enable_action(self):
        self.device.firewallstate.global_policy.policy = GlobalPolicy.POLICY_ALLOW
        self.device.firewallstate.global_policy.save(update_fields=['policy'])


class CVEActionTest(TestsMixin, TestCase):
    action_class = CVEAction
    param = 'CVE'

    def enable_action(self):
        self.device.deb_packages_hash = 'abcd'
        self.device.save(update_fields=['deb_packages_hash'])
        deb_package = DebPackage.objects.create(name='package', version='version1', source_name='package',
                                                source_version='sversion1', arch='amd64', os_release_codename='jessie')
        vulnerability = Vulnerability.objects.create(name=self.param, package='package', is_binary=True, other_versions=[],
                                                     urgency=Vulnerability.Urgency.LOW, fix_available=True,
                                                     os_release_codename='jessie')
        deb_package.vulnerabilities.add(vulnerability)
        self.device.deb_packages.add(deb_package)


class AutoUpdatesActionTest(TestsMixin, TestCase):
    action_class = AutoUpdatesAction

    def enable_action(self):
        self.device.auto_upgrades = False
        self.device.save(update_fields=['auto_upgrades'])


class MySQLDefaultRootPasswordActionTest(TestsMixin, TestCase):
    action_class = MySQLDefaultRootPasswordAction

    def enable_action(self):
        self.device.mysql_root_access = True
        self.device.save(update_fields=['mysql_root_access'])


class InsecureServicesActionTest(TestsMixin, TestCase):
    action_class = InsecureServicesAction

    def setUp(self):
        super().setUp()
        self.device.deb_packages_hash = 'abcd'
        self.device.save(update_fields=['deb_packages_hash'])

    def enable_action(self):
        deb_package = DebPackage.objects.create(name=self.param, version='version1',
                                                source_name=self.param, source_version='sversion1',
                                                arch='amd64', os_release_codename='jessie')
        self.device.deb_packages.add(deb_package)

    def disable_action(self):
        self.device.deb_packages.remove(DebPackage.objects.get(name=self.param))

    def test_get(self):
        for service in INSECURE_SERVICES:
            self.param = service.name
            super().test_get()
            self.disable_action()


class OpensshIssueActionTest(TestsMixin, TestCase):
    action_class = OpensshIssueAction

    bad_config = {'PermitRootLogin': 'prohibit-password',
                  'AllowAgentForwarding': 'yes',
                  'PasswordAuthentication': 'yes',
                  'PermitEmptyPasswords': 'yes',
                  'Protocol': '1',
                  'ClientAliveInterval': '0',
                  'ClientAliveCountMax': '4',
                  'HostbasedAuthentication': 'yes',
                  'IgnoreRhosts': 'no',
                  'LogLevel': 'WARN',
                  'LoginGraceTime': '120',
                  'MaxAuthTries': '6',
                  'PermitUserEnvironment': 'yes',
                  'X11Forwarding': 'yes'}

    def setUp(self):
        super().setUp()
        self.device.audit_files = [{'name': '/etc/ssh/sshd_config',
                                    'issues': {},
                                    'sha256': 'abcd', 'last_modified': 1554718384.0}]
        self.device.save()
        self.device.generate_recommended_actions()

    def enable_action(self):
        self.device.audit_files[0]['issues'] = \
            {self.param: self.bad_config[self.param]}
        self.device.save(update_fields=['audit_files'])

    def disable_action(self):
        self.device.audit_files[0]['issues'] = {}
        self.device.save(update_fields=['audit_files'])

    def test_get(self):
        for sshd_name in SSHD_CONFIG_PARAMS_INFO.keys():
            self.param = sshd_name
            super().test_get()
            self.disable_action()


class FtpServerActionTest(TestsMixin, TestCase):
    action_class = FtpServerAction

    def enable_action(self):
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': '???', 'host': '0.0.0.0', 'port': 21, 'pid': 45678}
        ]
        self.device.portscan.save(update_fields=['scan_info'])


class PubliclyAccessibleServiceActionTest(TestsMixin, TestCase):
    action_class = PubliclyAccessibleServiceAction

    def enable_action(self):
        dummy_pid = 34568
        self.device.deviceinfo.processes = {str(dummy_pid): (self.param, '', '', None)}
        self.device.deviceinfo.save(update_fields=['processes'])
        self.device.portscan.scan_info = [
            {'ip_version': 4, 'proto': 'tcp', 'state': 'LISTEN', 'host': '0.0.0.0',
             'port': self.port, 'pid': dummy_pid}
        ]
        self.device.portscan.save(update_fields=['scan_info'])

    def disable_action(self):
        self.device.deviceinfo.processes = {}
        self.device.deviceinfo.save(update_fields=['processes'])
        self.device.portscan.scan_info = []
        self.device.portscan.save(update_fields=['scan_info'])

    def test_get(self):
        for service, info in PUBLIC_SERVICE_PORTS.items():
            self.param = service
            self.port = info.port
            super().test_get()
            self.disable_action()


class CpuVulnerableActionTest(TestsMixin, TestCase):
    action_class = CpuVulnerableAction

    def enable_action(self):
        pkg = DebPackage.objects.create(os_release_codename='buster', name='linux', version='5.0.0',
                                        source_name='linux', source_version='5.0.0', arch=DebPackage.Arch.i386)
        self.device.kernel_deb_package = pkg
        vuln = Vulnerability.objects.create(os_release_codename='buster', name='CVE-2017-5753', package='linux',
                                            other_versions=[], is_binary=False, urgency=Vulnerability.Urgency.HIGH,
                                            fix_available=True)
        pkg.vulnerabilities.add(vuln)
        pkg.save()
        self.device.cpu = {'vendor': 'GenuineIntel'}
        self.device.save()


class RebootRequiredActionTest(TestsMixin, TestCase):
    action_class = RebootRequiredAction

    def enable_action(self):
        self.device.reboot_required = True
        self.device.save(update_fields=['reboot_required'])


class AuditdNotInstalledActionTest(TestsMixin, TestCase):
    action_class = AuditdNotInstalledAction

    def enable_action(self):
        self.device.deb_packages.clear()
