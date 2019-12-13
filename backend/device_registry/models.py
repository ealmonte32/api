from enum import Enum, IntEnum
import datetime
import json
import uuid
from typing import NamedTuple

from dateutil.relativedelta import relativedelta, SU, MO
from django.conf import settings
from django.db import models, transaction
from django.db.models import Q, Max, Window, Count
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.exceptions import ObjectDoesNotExist

import yaml
import tagulous.models
import apt_pkg

from .validators import UnicodeNameValidator, LinuxUserNameValidator
from .recommended_actions import ActionMeta, INSECURE_SERVICES, SSHD_CONFIG_PARAMS_INFO, PUBLIC_SERVICE_PORTS

apt_pkg.init()

DEBIAN_SUITES = ('jessie', 'stretch', 'buster')  # Supported Debian suite names.
UBUNTU_SUITES = ('xenial', 'bionic')  # Supported Ubuntu suite names.
IPV4_ANY = '0.0.0.0'
IPV6_ANY = '::'
FTP_PORT = 21


def get_bootstrap_color(val):
    if val <= 33:
        return 'danger'
    elif val < 66:
        return 'warning'
    else:
        return 'success'


class Tag(tagulous.models.TagModel):
    class TagMeta:
        # Tag options
        initial = "Hardware: All, Hardware: Raspberry Pi"
        force_lowercase = True
        autocomplete_view = 'ajax-tags-autocomplete'


class JsonFieldTransitionHelper(JSONField):
    def from_db_value(self, value, expression, connection, context):
        if isinstance(value, str):
            return json.loads(value)
        return value


class DebPackage(models.Model):
    class Arch(Enum):
        i386 = 'i386'
        AMD64 = 'amd64'
        ARMHF = 'armhf'
        ALL = 'all'

    os_release_codename = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=128)
    version = models.CharField(max_length=128)
    source_name = models.CharField(max_length=128, db_index=True)
    source_version = models.CharField(max_length=128)
    arch = models.CharField(max_length=16, choices=[(tag, tag.value) for tag in Arch])
    processed = models.BooleanField(default=False, db_index=True)
    vulnerabilities = models.ManyToManyField('Vulnerability')

    class Meta:
        unique_together = ['name', 'version', 'arch', 'os_release_codename']


class Device(models.Model):
    class SshdIssueItem(NamedTuple):
        safe_value: str
        unsafe_value: str
        doc_url: str

    device_id = models.CharField(
        max_length=128,
        unique=True,
        null=False,
        blank=False,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='devices',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    created = models.DateTimeField(auto_now_add=True)
    last_ping = models.DateTimeField(blank=True, null=True)
    certificate = models.TextField(blank=True, null=True)
    certificate_csr = models.TextField(blank=True, null=True)
    certificate_expires = models.DateTimeField(blank=True, null=True)
    comment = models.CharField(blank=True, null=True, max_length=512)
    claim_token = models.CharField(max_length=128)
    fallback_token = models.CharField(max_length=128, default='')
    name = models.CharField(max_length=36, blank=True)
    agent_version = models.CharField(max_length=36, blank=True, null=True)
    tags = tagulous.models.TagField(to=Tag, blank=True)
    trust_score = models.FloatField(null=True)
    update_trust_score = models.BooleanField(default=False, db_index=True)
    deb_packages = models.ManyToManyField(DebPackage)
    deb_packages_hash = models.CharField(max_length=32, blank=True)
    cpu = JSONField(blank=True, default=dict)
    kernel_deb_package = models.ForeignKey(DebPackage, null=True, on_delete=models.SET_NULL, related_name='+')
    audit_files = JSONField(blank=True, default=list)
    os_release = JSONField(blank=True, default=dict)
    auto_upgrades = models.BooleanField(null=True, blank=True)
    mysql_root_access = models.BooleanField(null=True, blank=True)
    default_password_users = ArrayField(models.CharField(max_length=32), null=True, blank=True)

    class Meta:
        ordering = ('created',)

    @property
    def default_password(self):
        if self.default_password_users is not None:
            return bool(self.default_password_users)
        elif not hasattr(self, 'deviceinfo'):
            return None
        else:
            return self.deviceinfo.default_password

    @property
    def payment_status(self):
        """
        Guess if the device is 'free', 'paid' or 'unpaid'.
        """
        if self.pk and self.owner:
            devices = self.owner.devices.order_by('pk')
            if self.pk == devices[0].pk:
                return 'free'
            # For `unlimited` customer all nodes are paid regardless of his subscription status.
            if hasattr(self.owner, 'profile') and self.owner.profile.unlimited_customer:
                return 'paid'
            if hasattr(self.owner, 'profile') and \
                    self.pk in devices[1:self.owner.profile.paid_nodes_number + 1].values_list('pk', flat=True):
                return 'paid'
            else:
                return 'unpaid'
        return

    @property
    def eol_info(self):
        """
        Return a dict with an info about current device distro's EOL.
        """
        eol_info_dict = {'eol': None, 'passed': None}
        codename = self.os_release.get('codename')
        if codename:
            distro = Distro.objects.filter(os_release_codename=codename).first()
            if distro is not None:
                eol_info_dict['eol'] = distro.end_of_life
                eol_info_dict['passed'] = distro.end_of_life <= timezone.now().date()
        return eol_info_dict

    def snooze_action(self, action_id, snoozed, duration=None):
        action, _ = RecommendedAction.objects.get_or_create(action_id=action_id, device=self)
        action.status = snoozed
        if snoozed == RecommendedAction.Status.SNOOZED_UNTIL_TIME:
            action.snoozed_until = timezone.now() + datetime.timedelta(hours=duration)
        elif snoozed == RecommendedAction.Status.NOT_AFFECTED:
            action.resolved_at = timezone.now()
        else:
            action.snoozed_until = None
        action.save()

    KERNEL_CPU_CVES = [
        'CVE-2017-5753',
        'CVE-2017-5715',
        'CVE-2017-5754',
        'CVE-2018-3615',  # (intel-microcode only)
        'CVE-2018-3620',
        'CVE-2018-3639',
        'CVE-2018-3640',  # (intel-microcode only)
        'CVE-2018-3646',
        'CVE-2018-12126',
        'CVE-2018-12130',
        'CVE-2018-12127',
        'CVE-2019-11091',
        'CVE-2019-1125'
    ]

    @property
    def cpu_vulnerable(self):
        if not self.cpu or not self.kernel_deb_package:
            # Either no data or the running kernel wasn't installed as a deb package.
            return None
        if self.cpu['vendor'] != 'GenuineIntel':
            # AMD and ARM CPUs, being theoretically vulnerable, were not shown to be vulnerable in practice.
            return False

        is_vulnerable = self.cpu.get('vulnerable')
        if is_vulnerable is None:
            # Agent couldn't confidently tell whether the kernel has mitigations compiled in -
            # meaning we need additional checks. If the kernel package is affected by any of the listed CVEs
            # then it's vulnerable. If the kernel is not affected by any of these CVEs - this means it has
            # mitigations compiled in. But if any of them are disabled at boot time (in kernel cmdline) then
            # the kernel is again vulnerable.
            return self.kernel_deb_package.vulnerabilities.filter(name__in=self.KERNEL_CPU_CVES).exists() or \
                   self.cpu.get('mitigations_disabled')
        else:
            return is_vulnerable

    @property
    def heartbleed_vulnerable(self):
        openssl_packages = self.deb_packages.filter(source_name='openssl')
        if not openssl_packages.exists():
            return None
        return openssl_packages.filter(vulnerabilities__name='CVE-2014-0160').exists()

    @property
    def auto_upgrades_enabled(self):
        if self.os_release.get('distro') == 'ubuntu-core':
            return True
        elif self.os_release.get('distro') == 'debian' or self.os_release.get('distro_root') == 'debian':
            return self.auto_upgrades and self.deb_packages.filter(name='unattended-upgrades').exists()

    @property
    def distribution(self):
        if self.os_release:
            full_version = self.os_release['full_version']
            distro = self.os_release['distro']
            if distro == 'ubuntu-core':
                distro_name = 'Ubuntu Core'
            else:
                distro_name = distro.capitalize()
            return f"{distro_name} {full_version}"

    @property
    def sshd_issues(self):
        if self.audit_files:
            for file_info in self.audit_files:
                if 'sshd' in file_info['name']:
                    return {k: self.SshdIssueItem(unsafe_value=v, safe_value=SSHD_CONFIG_PARAMS_INFO[k].safe_value,
                                                  doc_url=SSHD_CONFIG_PARAMS_INFO[k].doc_url)
                            for k, v in file_info['issues'].items()}

    @property
    def certificate_expired(self):
        return self.certificate_expires < timezone.now()

    @property
    def insecure_services(self):
        """
        Get a list of deb packages which are marked "insecure", i.e. their names are in INSECURE_SERVICES list.
        :return: list of DebPackage or None if set_deb_packages() wasn't called before.
        """
        if not self.deb_packages_hash:
            return None
        return self.deb_packages.filter(name__in=[service.name for service in INSECURE_SERVICES])

    def set_deb_packages(self, packages, os_info):
        """
        Assign the list of installed deb packages to this device.
        :param packages: list of dicts with the following values: 'name': str, 'version': str, 'arch': DebPackage.Arch.
        :param os_info: a dict with the `os_release` data from agent.
        """
        os_release_codename = os_info.get('codename', '')

        # Update packages with empty source_name and source_version.
        if DebPackage.objects.filter(source_name='').exists():
            affected_packages_qs = DebPackage.objects.filter(source_name='')
            affected_packages = []
            for package in packages:
                if 'source_name' not in package:
                    continue  # Old agent version, nothing to do.
                try:
                    package_obj = affected_packages_qs.get(name=package['name'], version=package['version'],
                                                           arch=package['arch'],
                                                           os_release_codename=os_release_codename)
                except ObjectDoesNotExist:
                    continue
                package_obj.source_name = package['source_name']
                package_obj.source_version = package['source_version']
                package_obj.processed = False
                affected_packages.append(package_obj)
            DebPackage.objects.bulk_update(affected_packages, ['source_name', 'source_version', 'processed'],
                                           batch_size=10000)

        # Save new packages to DB.
        DebPackage.objects.bulk_create([DebPackage(name=package['name'], version=package['version'],
                                                   source_name=package.get('source_name', ''),
                                                   source_version=package.get('source_version', ''),
                                                   arch=package['arch'],
                                                   os_release_codename=os_release_codename) for package in packages],
                                       batch_size=10000,
                                       ignore_conflicts=True)
        # Get packages qs.
        q_objects = models.Q()
        for package in packages:
            q_objects.add(models.Q(name=package['name'], version=package['version'], arch=package['arch'],
                                   os_release_codename=os_release_codename), models.Q.OR)

        # Set deb_packages.
        self.deb_packages.set(DebPackage.objects.filter(q_objects).only('pk'))

    def get_name(self):
        if self.name:
            return self.name
        fqdn = self.hostname
        if fqdn:
            return fqdn[:36]
        else:
            return 'device_%d' % self.pk

    @staticmethod
    def get_active_inactive(user):
        devices = Device.objects.filter(owner=user)
        device_count = devices.count()
        day_ago = timezone.now() - datetime.timedelta(hours=24)
        active = devices.filter(last_ping__gte=day_ago).count()
        inactive = device_count - active
        return [active, inactive]

    def __str__(self):
        return self.device_id

    @property
    def claimed(self):
        return bool(self.owner)

    @property
    def has_valid_hostname(self):
        self.device_id.endswith(settings.COMMON_NAME_PREFIX)

    @property
    def hostname(self):
        if not hasattr(self, 'deviceinfo'):
            return ''
        return self.deviceinfo.fqdn if self.deviceinfo else ''

    @property
    def actions_count(self):
        return self.recommendedaction_set.filter(RecommendedAction.get_affected_query()).count()

    def _get_listening_sockets(self, port):
        return [r for r in self.portscan.scan_info if
                int(r['port']) == port and r['proto'] == 'tcp' and
                ((int(r['ip_version']) == 4 and r['host'] == IPV4_ANY) or
                 (int(r['ip_version']) == 6 and r['host'] == IPV6_ANY))]

    @property
    def is_ftp_public(self):
        if hasattr(self, 'portscan'):
            return bool(self._get_listening_sockets(FTP_PORT))

    @property
    def public_services(self):
        """
        Looks for open ports and known services (declared in PUBLIC_SERVICE_PORTS) listening on them.
        :return: a set of service names (keys from PUBLIC_SERVICE_PORTS) which are listening.
        """
        if not hasattr(self, 'deviceinfo'):
            return
        processes = self.deviceinfo.processes
        found = set()
        for p in processes.values():
            if len(found) == len(PUBLIC_SERVICE_PORTS):
                break
            service = p[0]
            if service not in found and service in PUBLIC_SERVICE_PORTS:
                port = PUBLIC_SERVICE_PORTS[service][0]

                # Get all sockerts listening to port
                listening = self._get_listening_sockets(port)

                # See which processes are listening. We need to find either the service or 'docker-proxy'
                found_service = found_docker = False
                for sock in listening:
                    listening_process = processes.get(str(sock.get('pid')))
                    if not listening_process:
                        continue
                    name = listening_process[0]
                    if name == service:
                        found_service = listening_process
                        break
                    elif name == 'docker-proxy':
                        found_docker = listening_process

                # If it is docker-proxy listening on the port and the service is running in container,
                # or it is the service listening on the port - recommend an action.
                if (found_docker
                    and any(len(p) > 3 and p[3] == 'docker' and p[0] == service for p in processes.values())) \
                        or found_service:
                    found.add(service)
        return found

    COEFFICIENTS = {
        'app_armor_enabled': .5,
        'firewall_enabled': 1.5,
        'selinux_enabled': .5,
        'selinux_enforcing': .5,
        'default_password': 1.0,
        'failed_logins': 1.0,
        'port_score': .3,
        'cve_score': 1.0
    }
    MAX_FAILED_LOGINS = 10
    MIN_FAILED_LOGINS = 1
    CVE_POINTS = 40
    CVE_LOW_POINTS = 1
    CVE_MED_POINTS = 2
    CVE_HIGH_POINTS = 3

    def get_trust_score(self):
        if not hasattr(self, 'deviceinfo') or not hasattr(self, 'firewallstate') or not hasattr(self, 'portscan'):
            return None

        selinux = self.deviceinfo.selinux_state
        logins = self.deviceinfo.logins
        failed_logins = sum([u['failed'] for u in logins.values()])
        if failed_logins <= self.MIN_FAILED_LOGINS:
            failed_logins = 1.0
        elif failed_logins >= self.MAX_FAILED_LOGINS:
            failed_logins = 0.0
        else:
            failed_logins = 1.0 - ((failed_logins - self.MIN_FAILED_LOGINS) /
                                   (self.MAX_FAILED_LOGINS - self.MIN_FAILED_LOGINS + 1))

        vulns = Vulnerability.objects.filter(debpackage__device=self).distinct()
        vulns_low = vulns.filter(urgency__in=[Vulnerability.Urgency.NONE, Vulnerability.Urgency.LOW])
        vulns_medium = vulns.filter(urgency=Vulnerability.Urgency.MEDIUM)
        vulns_high = vulns.filter(urgency=Vulnerability.Urgency.HIGH)
        cve_score = self.CVE_POINTS
        score_table = (
            (vulns_low, self.CVE_LOW_POINTS),
            (vulns_medium, self.CVE_MED_POINTS),
            (vulns_high, self.CVE_HIGH_POINTS)
        )
        for vuln_qs, vuln_score in score_table:
            total = vuln_qs.count()
            remote = vuln_qs.filter(remote=True).count()
            non_remote = total - remote
            cve_score -= (remote * vuln_score * 2) + (non_remote * vuln_score)
        if cve_score < 0:
            cve_score = 0
        cve_score = cve_score / float(self.CVE_POINTS)

        def zero_if_none(x):
            return 0 if x is None else x

        return self.calculate_trust_score(
            app_armor_enabled=zero_if_none(self.deviceinfo.app_armor_enabled),
            firewall_enabled=self.firewallstate.policy == FirewallState.POLICY_ENABLED_BLOCK,
            selinux_enabled=selinux.get('enabled', False),
            selinux_enforcing=(selinux.get('mode') == 'enforcing'),
            failed_logins=failed_logins,
            port_score=self.portscan.get_score(),
            default_password=not self.default_password,
            cve_score=cve_score
        )

    @classmethod
    def calculate_trust_score(cls, **kwargs):
        return sum([v * cls.COEFFICIENTS[k] for k, v in kwargs.items()]) / \
               sum(cls.COEFFICIENTS.values())

    def trust_score_percent(self):
        if self.trust_score:
            return round(self.trust_score * 100)
        else:
            return 0

    def trust_score_minus100(self):
        return 100 - self.trust_score_percent()

    def trust_score_color(self):
        return get_bootstrap_color(self.trust_score_percent())

    def update_trust_score_now(self):
        self.trust_score = self.get_trust_score()
        self.save(update_fields=['trust_score'])

    def set_meta_tags(self):
        """
        Add proper meta tags in accordance with the device's hardware type.
        Since we use OR-based filtering of credentials all RPI-based devices
         should have both  `Hardware: All` and `Hardware: Raspberry Pi` tags.
         The rest of devices - only `Hardware: All`.
        """
        all_devices_tag = Tag.objects.get(name='Hardware: All')
        raspberry_pi_tag = Tag.objects.get(name='Hardware: Raspberry Pi')
        if all_devices_tag not in self.tags:
            self.tags.add(all_devices_tag)
        if self.deviceinfo.get_hardware_type() == 'Raspberry Pi' and raspberry_pi_tag not in self.tags:
            self.tags.add(raspberry_pi_tag)

    @property
    def vulnerable_packages(self):
        if self.deb_packages_hash and self.deb_packages.exists() and self.os_release and \
                self.os_release.get('codename') in DEBIAN_SUITES + UBUNTU_SUITES:
            return self.deb_packages.filter(vulnerabilities__isnull=False).distinct().order_by('name')

    @property
    def cve_count(self):
        """
        Count the number of high, medium and low severity CVEs for the device.
        :return: A dict of {'high': N1, 'med': N2, 'low': N3} or None if no deb packages or unsupported OS.
        """

        # We have no vulnerability data for OS other than Debian and Ubuntu flavors.
        if not (self.deb_packages_hash and self.deb_packages.exists() and self.os_release
                and self.os_release.get('codename') in DEBIAN_SUITES + UBUNTU_SUITES):
            return

        # For every CVE name detected for this device, find its maximal urgency among the whole CVE database.
        # This will include CVEs with the same name from different sources (Denian and Ubuntu trackers currently).
        # Then count the number of distinct CVE names grouped by urgency.
        vuln_names = Vulnerability.objects.filter(debpackage__device=self, fix_available=True) \
            .values('name').distinct()
        urgency_counts = Vulnerability.objects.filter(name__in=vuln_names) \
            .values('name').distinct() \
            .annotate(max_urgency=Max('urgency')) \
            .annotate(urg_cnt=Window(expression=Count('name'), partition_by='max_urgency')).order_by()\
            .values('max_urgency', 'urg_cnt')

        severities = {
            Vulnerability.Urgency.HIGH: 'high',
            Vulnerability.Urgency.MEDIUM: 'med',
            Vulnerability.Urgency.LOW: 'low'
        }
        result = {s: 0 for s in severities.values()}
        result.update({severities[s['max_urgency']]: s['urg_cnt'] for s in urgency_counts
                       if s['max_urgency'] in severities})
        return result

    @property
    def actions_count_last_week(self):
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1))).date()  # Last week's sunday (just before this monday)
        last_monday = sunday + relativedelta(weekday=MO(-1))  # Last week's monday
        this_monday = sunday + relativedelta(days=1)  # This week's monday

        actions_count = DeviceHistoryRecord.objects.filter(device=self,
                                                           sampled_at__gte=last_monday,
                                                           sampled_at__lt=this_monday)\
                                                   .aggregate(Max('recommended_actions_count'))
        return actions_count['recommended_actions_count__max'] or 0

    @property
    def actions_count_delta(self):
        count = self.actions_count - self.actions_count_last_week
        return {'count': abs(count), 'arrow': 'up' if count >= 0 else 'down'}

    def sample_history(self):
        DeviceHistoryRecord.objects.create(device=self,
                                           recommended_actions_count=self.actions_count)

    def generate_recommended_actions(self, classes=None):
        """
        Generate RAs for this device and store them as RecommendedAction objects in database.

        If a RecommendedAction object exists and it is in snoozed status: if the RA still affects the device
        then it will stay snoozed, otherwise its status changes to NOT_AFFECTED.

        If a RecommendedAction object for some RA does not exist it will be created.
        :param classes: if supplied, limit the scope of this method to this list of BaseAction classes.
        :return:
        """
        ra_all = self.recommendedaction_set.all().values_list('action_id', flat=True)
        ra_affected = self.recommendedaction_set.exclude(status=RecommendedAction.Status.NOT_AFFECTED) \
            .values_list('action_id', flat=True)
        newly_affected = []
        newly_not_affected = []
        added = []
        for action_class in ActionMeta.all_classes() if classes is None else classes:
            is_affected = action_class.is_affected(self)
            if action_class.action_id not in ra_all:
                # If a RecommendedAction object for some RA does not exist it will be created.
                added.append((action_class.action_id, is_affected))
            elif is_affected and action_class.action_id not in ra_affected:
                # A RecommendedAction object is not in AFFECTED status, but the RA affects the device
                newly_affected.append(action_class.action_id)
            elif not is_affected and action_class.action_id in ra_affected:
                # A RecommendedAction object is in AFFECTED or SNOOZED_* status, but the RA doesn't affect the device
                newly_not_affected.append(action_class.action_id)
        n_affected = self.recommendedaction_set.filter(action_id__in=newly_affected) \
            .update(status=RecommendedAction.Status.AFFECTED)
        n_unaffected = self.recommendedaction_set.filter(action_id__in=newly_not_affected) \
            .update(status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=timezone.now())
        ra_new = [RecommendedAction(action_id=action_id, device=self,
                                    status=RecommendedAction.Status.AFFECTED if affected else
                                    RecommendedAction.Status.NOT_AFFECTED) for action_id, affected in added]
        self.recommendedaction_set.bulk_create(ra_new)
        return n_affected, n_unaffected, len(ra_new)


class DeviceInfo(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    device_manufacturer = models.CharField(blank=True, null=True, max_length=128)
    device_model = models.CharField(blank=True, null=True, max_length=128)
    device_architecture = models.CharField(blank=True, null=True, max_length=32)
    device_operating_system = models.CharField(blank=True, null=True, max_length=128)
    device_operating_system_version = models.CharField(blank=True, null=True, max_length=128)
    fqdn = models.CharField(blank=True, null=True, max_length=128)
    ipv4_address = models.GenericIPAddressField(
        protocol="IPv4",
        null=True,
        blank=True
    )
    selinux_state = JSONField(blank=True, default=dict)
    app_armor_enabled = models.BooleanField(null=True, blank=True)
    logins = JSONField(blank=True, default=dict)
    processes = JSONField(blank=True, default=dict)
    default_password = models.BooleanField(null=True, blank=True)

    # We need this for the YC demo.
    detected_mirai = models.BooleanField(default=False, blank=True)
    device_metadata = JSONField(blank=True, default=dict)

    def __str__(self):
        return self.device.device_id

    def get_model(self):
        if self.device_manufacturer == 'Raspberry Pi':
            return self.device_model

    def get_hardware_type(self):
        if self.device_manufacturer == 'Raspberry Pi':
            return 'Raspberry Pi'

    @property
    def beautified_logins(self):
        if self.logins:
            logins = self.logins
            if '' in logins:
                logins['<unknown>'] = self.logins['']
                del (logins[''])
            return yaml.dump(logins)
        return "none"

    def save(self, *args, **kwargs):
        with transaction.atomic():
            super().save(*args, **kwargs)
            self.device.set_meta_tags()


class PortScan(models.Model):
    GOOD_PORTS = [22, 443]
    BAD_PORTS = [21, 23, 25, 53, 80, 161, 162, 512, 513]
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now=True)
    scan_info = JSONField(blank=True, default=list)  # Ports open for incoming connection to.
    netstat = JSONField(blank=True, default=list)  # Currently open network connections.
    block_ports = JSONField(blank=True, default=list)
    block_networks = JSONField(blank=True, default=list)

    def get_process_info_html(self, port_record):
        if 'pid' in port_record and hasattr(self.device, 'deviceinfo') and self.device.deviceinfo and \
                self.device.deviceinfo.processes:
            pid = port_record['pid']
            process_info = self.device.deviceinfo.processes.get(str(pid))
            if process_info:
                process_info_html = '<b>Name:</b> %s<br><b>User:</b> %s' % (process_info[0],
                                                                            process_info[1])
                if len(process_info[2]) > 1:  # 1 element cmdline is useless, skip it.
                    process_info_html += '<br><b>Command line:</b> %s' % ' '.join(process_info[2])
                return process_info_html
        return None

    def get_score(self):
        score = 1
        ports = [port['port'] for port in self.scan_info if port['proto'] == 'tcp']
        for port in ports:
            if port in PortScan.GOOD_PORTS:
                score -= 0.1
            if port in PortScan.BAD_PORTS:
                score -= 0.3
        return max(round(score, 1), 0)

    def ports_form_data(self):
        """
        Build 3 lists:
        1) list of choices for the ports form:
         [(0, ''), (1, '')]
        2) list of initial values for the ports form:
         [0, 1]
        3) list of choices for saving to the block list:
         [['::ffff:192.168.1.178', 22, 'tcp', True], ['192.168.1.178', 33, 'udp', False]]
        and 1 dict:
        1) dictionary of choices' extra data:
         {0: ('192.168.1.178', 33, 'UDP', 4, 'html for process info popover(optional)'),
          1: ('::ffff:192.168.1.178', 22, 'TCP', 6, None)}
        """
        choices_data = []
        initial_data = []
        ports_data = []
        choices_extra_data = {}

        port_record_index = 0
        # 1st - take ports from the block list.
        for port_record in self.block_ports:
            choices_data.append((port_record_index, ''))
            choices_extra_data[port_record_index] = (port_record[0], port_record[2], port_record[1].upper(),
                                                     6 if port_record[3] else 4, None)
            ports_data.append(port_record)
            initial_data.append(port_record_index)
            port_record_index += 1
        # 2nd - take ports from the open ports list (only the ones missing in the block list).
        for port_record in self.scan_info:
            if [port_record['host'], port_record['proto'], port_record['port'], port_record['ip_version'] == 6] \
                    not in self.block_ports:
                choices_data.append((port_record_index, ''))
                choices_extra_data[port_record_index] = (port_record['host'], port_record['port'],
                                                         port_record['proto'].upper(), port_record['ip_version'],
                                                         self.get_process_info_html(port_record))
                ports_data.append([port_record['host'], port_record['proto'], port_record['port'],
                                   port_record['ip_version'] == 6])
                port_record_index += 1
        return choices_data, initial_data, ports_data, choices_extra_data

    def connections_form_data(self):
        """
        Build 3 lists:
        1) list of choices for the open connections form
         (gonna be split in a template by '/' separator)::
         [[0, '192.168.1.20/4567/192.168.1.178/80/4/TCP/open/3425']]
        2) list of initial values for the open connections form:
         [0]
        3) list of choices for saving to the block list:
         [['192.168.1.20', False], ['::ffff:192.168.1.25', True]]
        """
        initial_data = []
        choices_data = []
        connections_data = []
        connection_record_index = 0
        unique_addresses = set()

        # 1st - take addresses from the block list.
        for connection_record in self.block_networks:
            if tuple(connection_record) not in unique_addresses:
                unique_addresses.add(tuple(connection_record))
                choices_data.append((connection_record_index, '%s////%d///' % (connection_record[0],
                                                                               6 if connection_record[1] else 4)))
                connections_data.append(connection_record)
                initial_data.append(connection_record_index)
                connection_record_index += 1

        # 2nd - take addresses from the open connections list (only the ones missing in the block list).
        for connection_record in self.netstat:
            if connection_record['remote_address'] and (connection_record['remote_address'][0],
                                                        connection_record['ip_version'] == 6) not in unique_addresses:
                unique_addresses.add((connection_record['remote_address'][0], connection_record['ip_version'] == 6))
                choices_data.append((
                    connection_record_index, '%s/%s/%s/%s/%d/%s/%s/%s' %
                    (connection_record['remote_address'][0], connection_record['remote_address'][1],
                     connection_record['local_address'][0] if connection_record['local_address'] else '',
                     connection_record['local_address'][1] if connection_record['local_address'] else '',
                     connection_record['ip_version'], connection_record['type'].upper(),
                     connection_record['status'], connection_record['pid'])))
                connections_data.append([connection_record['remote_address'][0],
                                         connection_record['ip_version'] == 6])
                connection_record_index += 1
        return choices_data, initial_data, connections_data


class FirewallState(models.Model):
    POLICY_ENABLED_ALLOW = 1
    POLICY_ENABLED_BLOCK = 2
    POLICY_CHOICES = (
        (POLICY_ENABLED_ALLOW, 'Allow by default'),
        (POLICY_ENABLED_BLOCK, 'Block by default')
    )
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(null=True, auto_now_add=True)
    rules = JSONField(blank=True, default=dict)
    policy = models.PositiveSmallIntegerField(choices=POLICY_CHOICES, default=POLICY_ENABLED_ALLOW)
    global_policy = models.ForeignKey('GlobalPolicy', on_delete=models.SET_NULL, blank=True, null=True)

    @property
    def policy_string(self):
        if self.policy == self.POLICY_ENABLED_ALLOW:
            return 'allow'
        elif self.policy == self.POLICY_ENABLED_BLOCK:
            return 'block'
        else:
            raise NotImplementedError

    @property
    def ports_field_name(self):
        if self.policy == self.POLICY_ENABLED_ALLOW:
            return 'block_ports'
        elif self.policy == self.POLICY_ENABLED_BLOCK:
            return 'allow_ports'
        else:
            raise NotImplementedError

    @property
    def beautified_rules(self):
        return yaml.dump(self.rules) if self.rules else "none"


class Credential(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='credentials', on_delete=models.CASCADE)
    name = models.CharField(
        max_length=64,
        validators=[UnicodeNameValidator()])
    tags = tagulous.models.TagField(to=Tag, blank=True)
    linux_user = models.CharField(
        max_length=32,
        blank=True,
        validators=[LinuxUserNameValidator()])
    data = JSONField(blank=True, default=dict)

    class Meta:
        unique_together = ['owner', 'name', 'linux_user']
        verbose_name = 'credentials record'
        verbose_name_plural = 'credentials records'

    def __str__(self):
        return f'{self.name}: {self.data}'

    def clean_name(self):
        return self.cleaned_data["name"].lower()

    def save(self, *args, **kwargs):
        self.full_clean()
        self.name = self.name.lower()
        super(Credential, self).save(*args, **kwargs)


class PairingKey(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='pairing_keys',
        on_delete=models.CASCADE,
    )
    key = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True, db_index=True)
    comment = models.CharField(blank=True, max_length=512)

    class Meta:
        ordering = ('created',)


class GlobalPolicy(models.Model):
    POLICY_ALLOW = 1
    POLICY_BLOCK = 2
    POLICY_CHOICES = (
        (POLICY_ALLOW, 'Allow by default'),
        (POLICY_BLOCK, 'Block by default')
    )
    name = models.CharField(max_length=32)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='global_policies', on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    policy = models.PositiveSmallIntegerField(choices=POLICY_CHOICES, verbose_name='firewall ports policy')
    ports = JSONField(blank=True, default=list)
    networks = JSONField(blank=True, default=list)

    @property
    def policy_string(self):
        if self.policy == self.POLICY_ALLOW:
            return 'allow'
        elif self.policy == self.POLICY_BLOCK:
            return 'block'
        else:
            raise NotImplementedError

    @property
    def ports_field_name(self):
        if self.policy == self.POLICY_ALLOW:
            return 'block_ports'
        elif self.policy == self.POLICY_BLOCK:
            return 'allow_ports'
        else:
            raise NotImplementedError

    def __str__(self):
        return self.name or f'global_policy_{self.pk}'

    def get_devices_nr(self):
        return self.firewallstate_set.count()

    class Meta:
        verbose_name = 'global policy'
        verbose_name_plural = 'global policies'
        ordering = ['-pk']
        constraints = [models.UniqueConstraint(fields=['name', 'owner'], name='unique_name')]


class Vulnerability(models.Model):
    class Meta:
        unique_together = ['os_release_codename', 'name', 'package']

    class Version:
        """Version class which uses the original APT comparison algorithm."""

        def __init__(self, version):
            """Creates a new Version object."""
            assert version != ""
            self.__asString = version

        def __str__(self):
            return self.__asString

        def __repr__(self):
            return 'Version({})'.format(repr(self.__asString))

        def __lt__(self, other):
            return apt_pkg.version_compare(self.__asString, other.__asString) < 0

        def __eq__(self, other):
            return apt_pkg.version_compare(self.__asString, other.__asString) == 0

    class Urgency(IntEnum):
        NONE = 0
        LOW = 1
        MEDIUM = 2
        HIGH = 3

    os_release_codename = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=64)
    package = models.CharField(max_length=64, db_index=True)
    is_binary = models.BooleanField()
    unstable_version = models.CharField(max_length=64, blank=True)
    other_versions = ArrayField(models.CharField(max_length=64), blank=True)
    urgency = models.PositiveSmallIntegerField(choices=[(tag, tag.value) for tag in Urgency])
    remote = models.BooleanField(null=True)
    fix_available = models.BooleanField()
    pub_date = models.DateField(null=True)

    def is_vulnerable(self, src_ver):
        if self.unstable_version:
            unstable_version = Vulnerability.Version(self.unstable_version)
        else:
            unstable_version = None
        other_versions = map(Vulnerability.Version, self.other_versions)
        src_ver = Vulnerability.Version(src_ver)

        if self.unstable_version:
            return src_ver < unstable_version and src_ver not in other_versions
        else:
            return src_ver not in other_versions


class Distro(models.Model):
    os_release_codename = models.CharField(max_length=64, unique=True)
    end_of_life = models.DateField()


class RecommendedAction(models.Model):
    class Meta:
        unique_together = ['device', 'action_id']

    class Status(IntEnum):
        AFFECTED = 0
        SNOOZED_UNTIL_PING = 1
        SNOOZED_UNTIL_TIME = 2
        SNOOZED_FOREVER = 3
        NOT_AFFECTED = 4

    @staticmethod
    def get_affected_query():
        return Q(status=RecommendedAction.Status.AFFECTED) | \
               Q(status=RecommendedAction.Status.SNOOZED_UNTIL_TIME,
                 snoozed_until__lt=timezone.now())

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    action_id = models.PositiveSmallIntegerField()
    status = models.PositiveSmallIntegerField(choices=[(tag, tag.value) for tag in Status],
                                              default=Status.AFFECTED.value)
    snoozed_until = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def update_all_devices(cls, classes=None):
        """
        Generate RAs for all devices which don't have them. Tries to do this in bulk by using .affected_devices()
        therefore if it's written properly this method will execute quickly.
        It is to be used during migration when a new RA is added.
        If classes is supplied the scope of this method will be limited to this list of RA classes.
        :param classes: a list of BaseAction child classes.
        :return: a number of new RecommendedAction objects created.
        """
        created = []
        if classes is None:
            classes = ActionMeta.all_classes()
        for action_class in classes:
            # Select devices which were not yet processed with this RA.
            qs = Device.objects.exclude(Q(recommendedaction__action_id=action_class.action_id) |
                                        Q(owner__isnull=True)).only('pk')
            if not qs.exists():
                continue
            all_devices = set(qs)
            affected = set(action_class.affected_devices(qs))
            not_affected = all_devices.difference(affected)
            created += [cls(device=d, action_id=action_class.action_id, status=cls.Status.NOT_AFFECTED)
                        for d in not_affected] + \
                       [cls(device=d, action_id=action_class.action_id, status=cls.Status.AFFECTED)
                        for d in affected]
        cls.objects.bulk_create(created)
        return len(created)


class HistoryRecord(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='history_records', on_delete=models.CASCADE)
    sampled_at = models.DateTimeField(auto_now_add=True)
    recommended_actions_resolved = models.IntegerField(null=True)
    average_trust_score = models.FloatField(null=True)
    cve_high_count = models.IntegerField(null=True)
    cve_medium_count = models.IntegerField(null=True)
    cve_low_count = models.IntegerField(null=True)


class DeviceHistoryRecord(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    recommended_actions_count = models.IntegerField(null=True)
    sampled_at = models.DateTimeField(auto_now_add=True)