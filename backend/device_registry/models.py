from enum import Enum, IntEnum
import datetime
import json
import uuid
from typing import NamedTuple, Tuple, Optional

from dateutil.relativedelta import relativedelta, SU, MO
from django.conf import settings
from django.db import models, transaction
from django.db.models import Q, Max, Window, Count
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.exceptions import ObjectDoesNotExist

import apt_pkg
import rpm
import yaml
import tagulous.models

from .validators import UnicodeNameValidator, LinuxUserNameValidator
from .recommended_actions import ActionMeta, INSECURE_SERVICES, SSHD_CONFIG_PARAMS_INFO, PUBLIC_SERVICE_PORTS, \
    ParamStatus, Severity

apt_pkg.init()

DEBIAN_SUITES = ('jessie', 'stretch', 'buster')  # Supported Debian suite names.
UBUNTU_SUITES = ('xenial', 'bionic')  # Supported Ubuntu suite (16.04, 18.04) names.
UBUNTU_KERNEL_PACKAGES_RE_PATTERN = r'linux-(?:(?:|aws-|oem-|gcp-|kvm-|oracle-|azure-|raspi2-|gke-|oem-osp1-)headers|' \
                                    r'image|modules)-.+'
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
    name = models.CharField(max_length=128, db_index=True)
    version = models.CharField(max_length=128)
    source_name = models.CharField(max_length=128, db_index=True)
    source_version = models.CharField(max_length=128)
    arch = models.CharField(max_length=16, choices=[(tag, tag.value) for tag in Arch])
    processed = models.BooleanField(default=False, db_index=True)
    vulnerabilities = models.ManyToManyField('Vulnerability')

    class Meta:
        unique_together = ['name', 'version', 'arch', 'os_release_codename']

    def __str__(self):
        return f'{self.name}:{self.version}:{self.arch}:{self.os_release_codename}'


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
    claimed_at = models.DateTimeField(blank=True, null=True, db_index=True)
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
    reboot_required = models.BooleanField(null=True, blank=True, db_index=True)
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

    def snooze_action(self, action_class, action_param, snoozed, duration=None):
        ra = RecommendedAction.objects.get(action_class=action_class, action_param=action_param)
        action, _ = RecommendedActionStatus.objects.get_or_create(device=self, ra=ra)
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

    def claim(self, user, claim_token=''):
        self.owner = user
        self.claim_token = claim_token
        fields = ['owner', 'claim_token']
        if user is not None:
            self.claimed_at = timezone.now()
            fields.append('claimed_at')
        self.save(update_fields=fields)

    @property
    def cpu_vulnerable(self):
        if not self.cpu or not self.kernel_deb_package:
            # Either no data or the running kernel wasn't installed as a deb package.
            return None
        if self.cpu['vendor'] != 'GenuineIntel':
            # AMD and ARM CPUs, being theoretically vulnerable, were not shown to be vulnerable in practice.
            return False

        return self.kernel_deb_package.vulnerabilities.filter(name__in=self.KERNEL_CPU_CVES).exists() or \
            self.cpu.get('mitigations_disabled', False)

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
        else:
            return self.auto_upgrades

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
        return self.recommendedactionstatus_set.filter(RecommendedActionStatus.get_affected_query()).count()

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
            firewall_enabled=bool(self.firewallstate.global_policy
                                  and self.firewallstate.global_policy.policy == GlobalPolicy.POLICY_BLOCK),
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
        if all_devices_tag not in self.tags:
            self.tags.add(all_devices_tag)

    @property
    def cve_count(self):
        """
        Count the number of high, medium and low severity CVEs for the device.
        :return: A dict of {'high': N1, 'med': N2, 'low': N3} or None if no deb packages or unsupported OS.
        """

        # We have no vulnerability data for OS other than Debian and Ubuntu flavors.
        if not(self.deb_packages_hash and self.deb_packages.exists() and self.os_release
               and self.os_release.get('codename') in DEBIAN_SUITES + UBUNTU_SUITES + ('amzn2',)):
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
        sunday = (now + relativedelta(days=-1, weekday=SU(-1)))  # Last week's sunday (just before this monday)
        sunday = sunday.combine(sunday, datetime.time(0), sunday.tzinfo)  # Reset time to midnight
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
        from .tasks import file_github_issues

        ra_all = self.recommendedactionstatus_set\
            .values_list('ra__action_class', 'ra__action_param')
        ra_affected = self.recommendedactionstatus_set\
            .exclude(status=RecommendedAction.Status.NOT_AFFECTED)\
            .values_list('ra__action_class', 'ra__action_param')
        newly_affected = []
        newly_not_affected = []
        added = []
        for action_class in ActionMeta.all_classes() if classes is None else classes:
            action_class_name = action_class.__name__
            affected_params = action_class.affected_params(self)
            if action_class.has_param:
                # if a param was removed -> counts as fixed
                were_affected = set(p for c, p in ra_affected if c == action_class_name)
                now_affected = set(p for p, v in affected_params if v)
                not_affected_anymore = were_affected.difference(now_affected)
                affected_params.extend(ParamStatus(p, False) for p in not_affected_anymore)
            for param, is_affected in affected_params:
                if (action_class_name, param) not in ra_all:
                    # If a RecommendedAction object for some RA does not exist it will be created.
                    added.append((action_class_name, param, is_affected))
                elif is_affected and (action_class_name, param) not in ra_affected:
                    # A RecommendedAction object is not in AFFECTED status, but the RA affects the device
                    newly_affected.append((action_class_name, param))
                elif not is_affected and (action_class_name, param) in ra_affected:
                    # A RecommendedAction object is in AFFECTED or SNOOZED_ status, but the RA doesn't affect the device
                    newly_not_affected.append((action_class_name, param))

        if newly_affected:
            newly_affected_q = Q()
            for name, param in newly_affected:
                newly_affected_q.add(Q(ra__action_class=name, ra__action_param=param), Q.OR)
            n_affected = self.recommendedactionstatus_set\
                .filter(newly_affected_q)\
                .update(status=RecommendedAction.Status.AFFECTED)
        else:
            n_affected = 0

        if newly_not_affected:
            newly_not_affected_q = Q()
            for name, param in newly_not_affected:
                newly_not_affected_q.add(Q(ra__action_class=name, ra__action_param=param), Q.OR)
            n_unaffected = self.recommendedactionstatus_set\
                .filter(newly_not_affected_q)\
                .update(status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=timezone.now())
        else:
            n_unaffected = 0

        ra_status_new = []
        for action_class_name, param, is_affected in added:
            ra = RecommendedAction.objects.filter(action_class=action_class_name, action_param=param)
            if ra.exists():
                ra = ra.first()
            else:
                action_class = ActionMeta.get_class(action_class_name)
                ra = RecommendedAction.objects.create(
                    action_class=action_class_name, action_param=param,
                    action_context=action_class.get_context(param),
                    action_severity=action_class.severity(param))
            status = (RecommendedAction.Status.AFFECTED if is_affected else RecommendedAction.Status.NOT_AFFECTED)
            ra_status_new.append(RecommendedActionStatus(ra=ra, device=self, status=status))
        self.recommendedactionstatus_set.bulk_create(ra_status_new)

        if settings.GITHUB_IMMEDIATE_SYNC and (n_affected or n_unaffected or ra_status_new) and self.owner:
            file_github_issues.delay(self.owner.profile.pk)

        return n_affected, n_unaffected, len(ra_status_new)


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


class FirewallState(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(null=True, auto_now_add=True)
    rules = JSONField(blank=True, default=dict)
    global_policy = models.ForeignKey('GlobalPolicy', on_delete=models.SET_NULL, blank=True, null=True)

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
        """
        Version comparator to be used for comparing package versions.
        Subclasses should define __eq__() and __lt__().
        """
        def __init__(self, version):
            assert version != ""
            self.__asString = version

        def __str__(self):
            return self.__asString

        def __repr__(self):
            return 'Version({})'.format(repr(self.__asString))

    class DebVersion(Version):
        """
        Version comparator for deb packages. Uses python-apt which in turn uses native code to compare versions.
        """
        def __lt__(self, other):
            return apt_pkg.version_compare(str(self), str(other)) < 0

        def __eq__(self, other):
            return apt_pkg.version_compare(str(self), str(other)) == 0

    class RpmVersion(Version):
        """
        Version comparator for rpm packages. Uses python-rpm which in turn uses native code to compare version.
        """
        @staticmethod
        def stringToVersion(verstring) -> Tuple[Optional[str], Optional[str], Optional[str]]:
            """
            Adapted from python2 version. Produces a tuple which can be used in rpm.labelCompare().
            https://github.com/rpm-software-management/yum/blob/master/rpmUtils/miscutils.py#L391
            :param verstring: A full version string [epoch:]<version>[.release]
            :return: (epoch, version, release), any of those may be None
            """
            if verstring in [None, '']:
                return (None, None, None)
            i = verstring.find(':')
            if i != -1:
                try:
                    epoch = str(int(verstring[:i]))
                except ValueError:
                    # look, garbage in the epoch field, how fun, kill it
                    epoch = '0'  # this is our fallback, deal
            else:
                epoch = '0'
            j = verstring.find('-')
            if j != -1:
                if verstring[i + 1:j] == '':
                    version = None
                else:
                    version = verstring[i + 1:j]
                release = verstring[j + 1:]
            else:
                if verstring[i + 1:] == '':
                    version = None
                else:
                    version = verstring[i + 1:]
                release = None
            return epoch, version, release

        def __init__(self, version):
            super().__init__(version)
            self._version_tuple = self.stringToVersion(version)

        def __lt__(self, other):
            return rpm.labelCompare(self._version_tuple, other._version_tuple) < 0

        def __eq__(self, other):
            return rpm.labelCompare(self._version_tuple, other._version_tuple) == 0

    class Urgency(IntEnum):
        NONE = 0
        LOW = 1
        MEDIUM = 2
        HIGH = 3

    os_release_codename = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=64, db_index=True)
    package = models.CharField(max_length=64, db_index=True)
    is_binary = models.BooleanField()
    unstable_version = models.CharField(max_length=64, blank=True)
    other_versions = ArrayField(models.CharField(max_length=64), blank=True)
    urgency = models.PositiveSmallIntegerField(choices=[(tag, tag.value) for tag in Urgency])
    remote = models.BooleanField(null=True)
    fix_available = models.BooleanField(db_index=True)
    pub_date = models.DateField(null=True)

    def is_vulnerable(self, src_ver):
        if self.os_release_codename in DEBIAN_SUITES + UBUNTU_SUITES + ('amzn2',):
            VersionClass = self.DebVersion if self.os_release_codename in DEBIAN_SUITES + UBUNTU_SUITES \
                else self.RpmVersion
            if self.unstable_version:
                unstable_version = VersionClass(self.unstable_version)
            else:
                unstable_version = None
            other_versions = map(VersionClass, self.other_versions)
            src_ver = VersionClass(src_ver)

            if self.unstable_version:
                return src_ver < unstable_version and src_ver not in other_versions
            else:
                return src_ver not in other_versions
        else:
            return False


class Distro(models.Model):
    os_release_codename = models.CharField(max_length=64, unique=True)
    end_of_life = models.DateField()


class RecommendedAction(models.Model):
    class Meta:
        unique_together = ['action_class', 'action_param']

    class Status(IntEnum):
        AFFECTED = 0
        SNOOZED_UNTIL_PING = 1
        SNOOZED_UNTIL_TIME = 2
        SNOOZED_FOREVER = 3
        NOT_AFFECTED = 4

    action_class = models.CharField(max_length=64)
    action_param = models.CharField(max_length=128, null=True, blank=True)
    action_context = JSONField(blank=True, default=dict)
    action_severity = models.PositiveSmallIntegerField(choices=[(tag, tag.value) for tag in Severity],
                                                       default=Severity.LO.value)


class RecommendedActionStatus(models.Model):
    class Meta:
        unique_together = ['device', 'ra']

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    ra = models.ForeignKey(RecommendedAction, on_delete=models.CASCADE)
    status = models.PositiveSmallIntegerField(choices=[(tag, tag.value) for tag in RecommendedAction.Status],
                                              default=RecommendedAction.Status.AFFECTED.value)
    snoozed_until = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    @staticmethod
    def get_affected_query():
        return Q(status=RecommendedAction.Status.AFFECTED) | \
               Q(status=RecommendedAction.Status.SNOOZED_UNTIL_TIME,
                 snoozed_until__lt=timezone.now())

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
        updated = []
        if classes is None:
            classes = ActionMeta.all_classes()
        for action_class in classes:
            # Select devices which were not yet processed with this RA.
            qs = Device.objects.exclude(Q(owner__isnull=True)).only('pk')
            if not qs.exists():
                continue
            affected = action_class.affected_devices(qs)
            for param, devices in affected:
                ra = RecommendedAction.objects.filter(action_class=action_class.__name__,
                                                      action_param=param)
                if not ra.exists():
                    # This is a new RA.
                    ra = RecommendedAction(action_class=action_class.__name__,
                                           action_param=param,
                                           action_context=action_class.get_context(param),
                                           action_severity=action_class.severity(param))
                    created.append((ra, [d for d in set(devices)]))
                else:
                    # This RA already exists, but it needs status update.
                    ra = ra.first()
                    ra.action_context = action_class.get_context(param)
                    ra.action_severity = action_class.severity(param)
                    updated.append((ra, devices))

        statuses = []
        if created:
            created_ras = RecommendedAction.objects.bulk_create([ra for ra, _ in created])
            statuses += [(new_ra, ra_devices[1]) for new_ra, ra_devices in zip(created_ras, created)]
        if updated:
            RecommendedAction.objects.bulk_update([u[0] for u in updated], fields=['action_context', 'action_severity'])
            statuses += [(ra, devices) for ra, devices in updated]
        if statuses:
            ra_statuses = [[RecommendedActionStatus(ra=ra, device=d, status=RecommendedAction.Status.AFFECTED)
                            for d in devices] for ra, devices in statuses]
            ra_statuses = sum(ra_statuses, [])  # Flatten the list
            cls.objects.bulk_create(ra_statuses, ignore_conflicts=True)
            return len(ra_statuses), len(created), len(updated)
        else:
            return 0


class GithubIssue(models.Model):
    ra = models.ForeignKey(RecommendedAction, on_delete=models.CASCADE)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    url = models.URLField(blank=True, null=True)
    number = models.PositiveIntegerField(default=0)
    closed = models.BooleanField(default=False)
    affected = models.ManyToManyField(Device, related_name='github_issues_affected')
    resolved = models.ManyToManyField(Device, related_name='github_issues_resolved')


class HistoryRecord(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='history_records', on_delete=models.CASCADE,
                              unique_for_date="sampled_at")
    sampled_at = models.DateTimeField(auto_now_add=True, db_index=True)
    recommended_actions_resolved = models.IntegerField(null=True)
    average_trust_score = models.FloatField(null=True)
    cve_high_count = models.IntegerField(null=True)
    cve_medium_count = models.IntegerField(null=True)
    cve_low_count = models.IntegerField(null=True)


class DeviceHistoryRecord(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    recommended_actions_count = models.IntegerField(null=True)
    sampled_at = models.DateTimeField(auto_now_add=True)
