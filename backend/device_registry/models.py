import datetime
from statistics import mean
import json

from django.conf import settings
from django.db import models
from django.db.models import F
from django.utils import timezone
from django.contrib.postgres.fields import JSONField

import yaml

from device_registry import ca_helper


def get_bootstrap_color(val):
    if val <= 33:
        return 'danger'
    elif val < 66:
        return 'warning'
    else:
        return 'success'

class JsonFieldTransitionHelper(JSONField):
    def from_db_value(self, value, expression, connection, context):
        if isinstance(value, str):
            return json.loads(value)
        return value


class Device(models.Model):
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
    claim_token = models.CharField(editable=False, max_length=128)
    fallback_token = models.CharField(editable=False, max_length=128, default='')
    name = models.CharField(max_length=36, blank=True)

    def get_name(self):
        if self.name:
            return self.name
        fqdn = self.deviceinfo.fqdn
        if fqdn:
            original_length = len(fqdn)
            fqdn = fqdn[:36]
            appendix = ''
            if self.__class__.objects.exclude(pk=self.pk).filter(
                    owner=self.owner, deviceinfo__fqdn__startswith=fqdn).exists():
                appendix = '_%d' % self.pk
                if len(fqdn) + len(appendix) > 36:
                    appendix = '..._%d' % self.pk
            else:
                if original_length > 36:
                    appendix = '...'
            fqdn = fqdn[:36 - len(appendix)] + appendix
            return fqdn
        else:
            return 'device_%d' % self.pk


    @staticmethod
    def get_active_inactive(user):
        devices = get_device_list(user)
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

    def get_cert_expiration_date(self):
        try:
            return ca_helper.get_certificate_expiration_date(self.certificate)
        except ValueError:
            pass

    def get_cert_url(self):
        if settings.IS_DEV:
            cert_url = f'http://localhost:8001/api/v0.2/device-cert/{self.device_id}'
        else:
            cert_url = f'https://api.wott.io/v0.2/device-cert/{self.device_id}'
        return cert_url

    @property
    def actions_count(self):
        return sum((self.deviceinfo.default_password is True,
                self.firewallstate.enabled is False,
                self.__class__.objects.filter(pk=self.pk, portscan__scan_info__contains=[{'port': 23}]).exclude(
                    portscan__block_ports__contains=[[23]]).exists()
                ))

    @property
    def has_actions(self):
        return self.actions_count > 0

    COEFFICIENTS = {
        'app_armor_enabled': .5,
        'firewall_enabled': 1.0,
        'selinux_enabled': .5,
        'selinux_enforcing': .5,
        'default_password': .5,
        'failed_logins': 1.0,
        'port_score': 1.0,
    }
    MAX_FAILED_LOGINS = 10
    MIN_FAILED_LOGINS = 1

    @property
    def trust_score(self):
        if not hasattr(self, 'firewallstate') or not hasattr(self, 'portscan'):
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

        def zero_if_none(x):
            return 0 if x is None else x

        return self.calculate_trust_score(
            app_armor_enabled=zero_if_none(self.deviceinfo.app_armor_enabled),
            firewall_enabled=zero_if_none(self.firewallstate.enabled),
            selinux_enabled=selinux.get('enabled', False),
            selinux_enforcing=(selinux.get('mode') == 'enforcing'),
            failed_logins=failed_logins,
            port_score=self.portscan.get_score(),
            default_password=not self.deviceinfo.default_password
        )

    @classmethod
    def calculate_trust_score(cls, **kwargs):
        return sum([v*cls.COEFFICIENTS[k] for k,v in kwargs.items()]) / \
               sum(cls.COEFFICIENTS.values())

    def trust_score_percent(self):
        return int(self.trust_score * 100)

    def trust_score_color(self):
        return get_bootstrap_color(self.trust_score_percent())

    class Meta:
        ordering = ('created',)


class DeviceInfo(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    device_manufacturer = models.CharField(blank=True, null=True, max_length=128)
    device_model = models.CharField(blank=True, null=True, max_length=128)
    device_architecture = models.CharField(blank=True, null=True, max_length=32)
    device_operating_system = models.CharField(blank=True, null=True, max_length=128)
    device_operating_system_version = models.CharField(blank=True, null=True, max_length=128)
    distr_id = models.CharField(blank=True, null=True, max_length=32)
    distr_release = models.CharField(blank=True, null=True, max_length=32)
    trust_score = models.FloatField(blank=True, null=True)
    fqdn = models.CharField(blank=True, null=True, max_length=128)
    ipv4_address = models.GenericIPAddressField(
        protocol="IPv4",
        null=True,
        blank=True
    )
    selinux_state = JSONField(default=dict)
    app_armor_enabled = models.BooleanField(null=True, blank=True)
    logins = JSONField(default=dict)
    default_password = models.BooleanField(null=True, blank=True)

    # We need this for the YC demo.
    detected_mirai = models.BooleanField(default=False, blank=True)

    RASPBERRY_MODEL_MAP = {
        '0002': 'Model B Rev 1',
        '0003': 'Model B Rev 1',
        '0004': 'Model B Rev 2',
        '0005': 'Model B Rev 2',
        '0006': 'Model B Rev 2',
        '0007': 'Model A',
        '0008': 'Model A',
        '0009': 'Model A',
        '000d': 'Model B Rev 2',
        '000e': 'Model B Rev 2',
        '000f': 'Model B Rev 2',
        '0010': 'Model B+',
        '0013': 'Model B+',
        '900032': 'Model B+',
        '0011': 'Compute Module',
        '0014': 'Compute Module',
        '0012': 'Model A+',
        '0015': 'Model A+',
        'a01041': 'Pi 2 Model B v1.1',
        'a21041': 'Pi 2 Model B v1.1',
        'a22042': 'Pi 2 Model B v1.2',
        '900092': 'Pi Zero v1.2',
        '900093': 'Pi Zero v1.3',
        '9000c1': 'Pi Zero W',
        'a02082': 'Pi 3 Model B',
        'a22082': 'Pi 3 Model B',
        'a020d3': 'Pi 3 Model B+'
    }

    def __str__(self):
        return self.device.device_id

    def get_model(self):
        model = None
        if self.device_manufacturer == 'Raspberry Pi':
            model = DeviceInfo.RASPBERRY_MODEL_MAP.get(self.device_model.lower(), None)
        return model

    def get_hardware_type(self):
        if self.device_manufacturer == 'Raspberry Pi':
            return 'Raspberry Pi'

    @property
    def beautified_logins(self):
        if self.logins:
            logins = self.logins
            if '' in logins:
                logins['<unknown>'] = self.logins['']
                del(logins[''])
            return yaml.dump(logins)
        return "none"


class PortScan(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now=True)
    scan_info = JSONField(default=list)  # Ports open for incoming connection to.
    netstat = JSONField(default=list)  # Currently open network connections.
    block_ports = JSONField(default=list)
    block_networks = JSONField(default=list)
    GOOD_PORTS = [22, 443]
    BAD_PORTS = [21, 23, 25, 53, 80, 161, 162, 512, 513]

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
        1) list of choices for the ports form
         (gonna be split in a template by '/' separator):
         [[0, '::ffff:192.168.1.178/22/TCP/6'], [0, '192.168.1.178/33/UDP/4']]
        2) list of initial values for the ports form:
         [0, 1]
        3) list of choices for saving to the block list:
         [['::ffff:192.168.1.178', 22, 'tcp', True], ['192.168.1.178', 33, 'udp', False]]
        """
        initial_data = []
        choices_data = []
        ports_data = []
        port_record_index = 0
        # 1st - take ports from the block list.
        for port_record in self.block_ports:
            choices_data.append((port_record_index, '%s/%s/%s/%d' % (
                port_record[0], port_record[2], port_record[1].upper(), 6 if port_record[3] else 4)))
            ports_data.append(port_record)
            initial_data.append(port_record_index)
            port_record_index += 1
        # 2nd - take ports from the open ports list (only the ones missing in the block list).
        for port_record in self.scan_info:
            if [port_record['host'], port_record['proto'], port_record['port'], port_record['ip_version'] == 6] \
                    not in self.block_ports:
                choices_data.append((port_record_index, '%s/%s/%s/%d' % (
                    port_record['host'], port_record['port'], port_record['proto'].upper(),
                    port_record['ip_version'])))
                ports_data.append([port_record['host'], port_record['proto'], port_record['port'],
                                   port_record['ip_version'] == 6])
                port_record_index += 1
        return choices_data, initial_data, ports_data

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
    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    enabled = models.BooleanField(null=True, blank=True)
    scan_date = models.DateTimeField(null=True, auto_now_add=True)
    rules = JSONField(default=dict)

    @property
    def beautified_rules(self):
        return yaml.dump(self.rules) if self.rules else "none"


class Credential(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='credentials', on_delete=models.CASCADE)
    name = models.CharField(max_length=64)
    key = models.CharField(max_length=64)
    value = models.CharField(max_length=1024)

    class Meta:
        unique_together = ['owner', 'key', 'name']
        verbose_name = 'credentials record'
        verbose_name_plural = 'credentials records'

    def __str__(self):
        return f'{self.name}: {self.key}={self.value}'


# Temporary POJO to showcase recommended actions template.
class Action:
    def __init__(self, action_id, title, description, actions):
        """
        Args:
            action_id: Action Id.
            title: Actions title.
            description: Action description.
            actions (str[]): List of available actions.
        """
        self.id = action_id
        self.title = title
        self.description = description
        self.actions = actions


def get_device_list(user):
    """Get list of devices ordered by last ping.
    """
    return Device.objects.filter(owner=user).order_by(F('last_ping').desc(nulls_last=True))


def average_trust_score(user):
    scores = [p.trust_score for p in Device.objects.filter(owner=user).all()]
    scores = [s for s in scores if s is not None]
    return mean(scores) if scores else None
