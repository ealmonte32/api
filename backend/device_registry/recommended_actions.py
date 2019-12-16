import itertools
from datetime import timedelta
from enum import Enum

from django.conf import settings
from django.db.models import Q
from django.urls import reverse

import markdown
from django.utils import timezone


class Severity(Enum):
    LO = ('Low', 'secondary')
    MED = ('Medium', 'warning')
    HI = ('High', 'danger')


INSECURE_SERVICES = [
    ('fingerd', 1, Severity.MED),
    ('tftpd', 2, Severity.MED),
    ('telnetd', 3, Severity.HI),
    ('snmpd', 4, Severity.MED),
    ('xinetd', 5, Severity.MED),
    ('nis', 6, Severity.MED),
    ('atftpd', 7, Severity.MED),
    ('tftpd-hpa', 8, Severity.MED),
    ('rsh-server', 9, Severity.HI),
    ('rsh-redone-server', 10, Severity.HI)
]

SSHD_CONFIG_PARAMS_INFO = {
    'PermitEmptyPasswords': ('no', None, 1, Severity.HI),
    'PermitRootLogin': ('no', 'https://wott.io/documentation/faq#openssh-perminrootlogin', 2, Severity.MED),
    'PasswordAuthentication': ('no', 'https://wott.io/documentation/faq#openssh-password-authentication', 3, Severity.HI),
    'AllowAgentForwarding': ('no', 'https://wott.io/documentation/faq#openssh-passwordauthentication', 4, Severity.MED),
    'Protocol': ('2', None, 5, Severity.HI)
}

PUBLIC_SERVICE_PORTS = {
    'mongod': (27017, 'MongoDB', 1),
    'mysqld': (3306, 'MySQL/MariaDB', 2),
    'memcached': (11211, 'Memcached', 3),
    'redis-server': (6379, 'Redis', 4)
}


class Action:
    """
    Action class.

    Its only purpose is to store particular actions info and be passed from a
     view to a template.
    """
    def __init__(self, title, description, action_id, devices, severity: Severity, doc_url="/", issue_url=None):
        """

        :param title: Title text
        :param description: Body text
        :param action_id: the value of action_id field of BaseAction subclasses
        :param devices: list of device ids
        :param severity: one of 'low', 'medium', 'high'
        :param doc_url: "Learn more" URL
        :param issue_url: Github issue URL, optional
        """
        self.title = title
        self.description = markdown.markdown(description)
        self.action_id = action_id
        self.devices = devices
        self.issue_url = issue_url
        self.doc_url = doc_url
        self.severity = severity


def device_link(device, absolute=False):
    """Create a device's page html link code"""
    url = reverse('device-detail', kwargs={'pk': device.pk})
    if absolute:
        url = settings.DASH_URL + url
    return f'[{device.get_name()}]({url})'


class BaseAction:
    """
    Common base action class.

    It's a parent for all specific base action classes.
    Contains the code supposed to fit *all* actions.
    """
    severity = Severity.LO
    doc_url = 'https://wott.io/documentation/faq'

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import RecommendedAction
        if exclude_snoozed:
            devices = user.devices.exclude(Q(recommendedaction__action_id=cls.action_id) &
                                           (Q(recommendedaction__snoozed__in=[RecommendedAction.Snooze.FOREVER,
                                                                              RecommendedAction.Snooze.UNTIL_PING]) |
                                            Q(recommendedaction__snoozed=RecommendedAction.Snooze.UNTIL_TIME,
                                              recommendedaction__snoozed_until__gte=timezone.now())))
        else:
            devices = user.devices.all()
        if device_pk is not None:
            devices = devices.filter(pk=device_pk)
        return devices

    @classmethod
    def get_action_description_context(cls, devices_qs, device_pk=None):
        """
        Method for producing a tuple of values used (as string formatting parameters)
         for action description text rendering.
        :param devices: queryset for Device model instances affected by the action;
        :param device_pk: int/None - single affected device id;
        :return: iterable (tuple/list);
        """
        return {}

    @classmethod
    def _create_action(cls, profile, context, devices_list) -> Action:
        """
        Create an Action object with title and description supplied by this class (cls), action description context,
        devices list and profile's github issue info (which can be empty).
        :param profile: Profile
        :param context: a format dict for action_description
        :param devices_list: list of Device ids
        :return: Action
        """
        if hasattr(cls, 'group_action'):
            issue_number = profile.github_issues.get(str(cls.group_action.action_id))
        else:
            issue_number = profile.github_issues.get(str(cls.action_id))
        issue_url = f'{profile.github_repo_url}/issues/{issue_number}' if issue_number else None
        return Action(
            cls.action_title.format(**context),
            cls.action_description.format(**context),
            cls.action_id, devices_list,
            cls.severity,
            issue_url=issue_url,
            doc_url=cls.doc_url
        )

    @classmethod
    def actions(cls, user, device_pk=None):
        actions_list = []
        devices = cls.affected_devices(user, device_pk)
        if devices.exists():
            context = cls.get_action_description_context(devices_qs=devices, device_pk=device_pk)
            context['devices'] = ', '.join([device_link(dev) for dev in devices]) if device_pk is None else 'this node'
            actions_list.append(cls._create_action(user.profile, context, list(devices.values_list('pk', flat=True))))
        return actions_list

    @classmethod
    def action_blocks_count(cls, user):
        return int(cls.affected_devices(user).exists())

    @classmethod
    def get_description(cls, user, body=None, **kwargs):
        day_ago = timezone.now() - timedelta(hours=24)
        affected_devices = cls.affected_devices(user, exclude_snoozed=False).filter(last_ping__gte=day_ago)
        if not affected_devices.exists():
            return
        affected_list = '\n'.join([f'- {device_link(d, absolute=True)}' for d in affected_devices])
        context = cls.get_action_description_context(affected_devices)
        context.update(kwargs)
        if 'subject' in context:
            # Workaround for AutoUpdatesAction three-way logic
            context['subject'] = ''
        body_text = cls.action_description if body is None else body
        action_text = body_text.format(**context) + f"\n\n#### Affected nodes: ####\n{affected_list}"
        return cls.action_title, action_text


class GroupedAction:
    @classmethod
    def get_description(cls, user, **kwargs):
        action_text = ''
        for subclass in cls.subclasses:
            description = subclass.get_description(user, body=subclass.group_action_section_body, **kwargs)
            if description:
                action_text += f"\n\n### {subclass.group_action_section_title} ###\n\n" + description[1]
        if not action_text:
            return
        return cls.group_action_title, cls.group_action_main + action_text


class ActionMeta(type):
    _action_classes = {}
    _grouped_action_classes = set()
    _ungrouped_action_classes = {}

    def __new__(meta, name, bases, class_dict):
        cls = type.__new__(meta, name, bases, class_dict)
        if cls.action_id in meta._action_classes:
            raise ValueError('This action_id already exists')
        if hasattr(cls, 'group_action'):
            group_action = cls.group_action
            meta._ungrouped_action_classes[cls.action_id] = cls
            if not hasattr(group_action, 'subclasses'):
                setattr(group_action, 'subclasses', [])
            group_action.subclasses.append(cls)
            meta._grouped_action_classes.add(group_action)
        else:
            meta._action_classes[cls.action_id] = cls
        return cls

    @classmethod
    def unregister(meta, cls):
        del meta._action_classes[cls.action_id]

    @classmethod
    def all_classes(meta, grouped=False):
        regular = list(meta._action_classes.values())
        return regular + (list(meta._grouped_action_classes) if grouped
                          else list(meta._ungrouped_action_classes.values()))

    @classmethod
    def is_action_id(meta, id):
        return id in meta._action_classes or id in meta._ungrouped_action_classes


# Below is the code for real actions classes.
# Don't forget to add metaclass=ActionMeta.

# Default username/password used action.
class DefaultCredentialsAction(BaseAction, metaclass=ActionMeta):
    action_id = 1
    action_title = 'Default credentials detected'
    action_description = \
        'We found default credentials present on {devices}. Please consider changing them as soon as possible.'
    severity = Severity.HI

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        return super().affected_devices(user, device_pk, exclude_snoozed).filter(deviceinfo__default_password=True)


# Firewall disabled action.
class FirewallDisabledAction(BaseAction, metaclass=ActionMeta):
    action_id = 2
    action_title = 'Permissive firewall policy detected'
    action_description = \
        'We found permissive firewall policy present on {devices}. Please consider change it to more restrictive one.'
    severity = Severity.MED

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import FirewallState, GlobalPolicy
        return super().affected_devices(user, device_pk, exclude_snoozed).exclude(
            (Q(firewallstate__global_policy=None) & Q(firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)) |
            Q(firewallstate__global_policy__policy=GlobalPolicy.POLICY_BLOCK))


# Vulnerable packages found action.
class VulnerablePackagesAction(BaseAction, metaclass=ActionMeta):
    action_id = 3
    action_title = 'Vulnerable packages found'
    action_description = \
        'We found vulnerable packages on {devices}. These packages could be used by an attacker to either gain ' \
        'access to your node, or escalate permission. It is recommended that you address this at your earliest ' \
        'convenience.\n\n' \
        'Run `sudo apt-get update && sudo apt-get upgrade` to bring your system up to date.\n\n' \
        'Please note that there might be vulnerabilities detected that are yet to be fixed by the operating system ' \
        'vendor.'
    severity = Severity.MED

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        return super().affected_devices(user, device_pk, exclude_snoozed).filter(deb_packages__vulnerabilities__isnull=False).distinct()


class InsecureServicesGroupAction(GroupedAction):
    group_action_title = 'Insecure services found'
    group_action_main = 'We found insecure services installed on your nodes. Because these services are ' \
                        'considered insecure, we recommend you to uninstall them.'
    action_id = 1000


# Insecure services found action.
class BaseInsecureServicesAction(BaseAction):
    action_title = 'Insecure service found'
    group_action = InsecureServicesGroupAction

    @classmethod
    def get_action_description_context(cls, devices_qs, device_pk=None):
        return {'service': cls.service_name}

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        return super().affected_devices(user, device_pk, exclude_snoozed).exclude(deb_packages_hash='').filter(
            deb_packages__name=cls.service_name).distinct()


for name, sub_id, severity in INSECURE_SERVICES:
    class ConcreteInsecureServicesAction(BaseInsecureServicesAction, metaclass=ActionMeta):
        action_id = sub_id + InsecureServicesGroupAction.action_id
        action_description = \
            'We found {service} installed on {devices}. Because this service is considered insecure, it is ' \
            'recommended that you uninstall it.\n\n' \
            'Run `sudo apt-get remove {service}` to remove it.'
        group_action_section_title = name
        group_action_section_body = 'Run `sudo apt-get remove {service}` to remove it.'
        severity = severity
        service_name = name


# OpenSSH configuration issues found action.
class OpensshIssueGroupAction(GroupedAction):
    action_id = 2000
    group_action_title = 'Insecure configuration for OpenSSH found'
    group_action_main = \
        'We found insecure configuration issues with OpenSSH on your nodes. To improve the security posture of your ' \
        'node, please consider making the following changes:'


class BaseOpensshIssueAction(BaseAction):
    group_action = OpensshIssueGroupAction
    action_title = 'Insecure configuration for OpenSSH found'
    action_description = \
        'We found insecure configuration issue with OpenSSH on {devices}: insecure parameter {param_name}. To improve ' \
        'the security posture of your node, please consider changing {param_name} to "{safe_value}".'

    @classmethod
    def get_action_description_context(cls, devices_qs, device_pk=None):
        safe_value, doc_url, _, _ = SSHD_CONFIG_PARAMS_INFO[cls.sshd_param]
        return dict(param_name=cls.sshd_param,
                    safe_value=safe_value,
                    doc_url=doc_url)

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import Device
        dev_ids = []
        devices = super().affected_devices(user, device_pk, exclude_snoozed).exclude(audit_files__in=('', []))
        for dev in devices:
            if cls.sshd_param in dev.sshd_issues:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


for param_name, param_info in SSHD_CONFIG_PARAMS_INFO.items():
    class ConcreteOpensshIssueAction(BaseOpensshIssueAction, metaclass=ActionMeta):
        _, doc_url, sub_id, severity = param_info
        action_id = OpensshIssueGroupAction.action_id + sub_id
        sshd_param = param_name
        group_action_section_title = param_name
        group_action_section_body = \
            'Please consider changing {param_name} to "{safe_value}".' \
            + (f'\n\nYou can learn more [here]({doc_url}).' if doc_url else '')


# Automatic security update disabled action.
class AutoUpdatesAction(BaseAction, metaclass=ActionMeta):
    action_id = 6
    action_title = 'Consider enable automatic security updates'
    action_description = \
        'We found that {subject}{devices} {verb} not configured to automatically install security updates. Consider ' \
        'enabling this feature.\n\n' \
        'Details for how to do this can be found [here]({doc_url})'
    severity = Severity.HI

    @classmethod
    def get_doc_url(cls, devices):
        debian_url = 'https://wiki.debian.org/UnattendedUpgrades'
        ubuntu_url = 'https://help.ubuntu.com/lts/serverguide/automatic-updates.html'
        if devices.count() > 1:
            # Provide Debian's link if more than 1 device.
            return debian_url
        else:
            if devices.first().os_release.get('distro') == 'ubuntu':
                return ubuntu_url
            else:  # Everything besides Ubuntu is Debian.
                return debian_url

    @classmethod
    def get_action_description_context(cls, devices_qs, device_pk=None):
        if device_pk is None:
            if devices_qs.count() > 1:
                subject, verb = 'your nodes ', 'are'
            else:
                subject, verb = 'your node ', 'is'
        else:
            subject, verb = '', 'is'
        return {
            'subject': subject,
            'verb': verb,
            'doc_url': cls.get_doc_url(devices_qs)
        }

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        return super().affected_devices(user, device_pk, exclude_snoozed).filter(auto_upgrades=False)


# FTP listening on port 21 action.
class FtpServerAction(BaseAction, metaclass=ActionMeta):
    action_id = 7
    action_title = 'Consider moving to SFTP'
    action_description = \
        'There appears to be an FTP server running on {devices}. FTP is generally considered insecure as the ' \
        'credentials are sent unencrypted over the internet. Consider switching to an encrypted service, such as ' \
        '[SFTP](https://www.ssh.com/ssh/sftp).'
    severity = Severity.MED

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk, exclude_snoozed):
            if dev.is_ftp_public:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


# MySQL root default password action.
class MySQLDefaultRootPasswordAction(BaseAction, metaclass=ActionMeta):
    action_id = 10
    action_title = 'No root password set for the MySQL/MariaDB server'
    action_description = \
        'We detected that there is no root password set for MySQL/MariaDB on {devices}. Not having a root password ' \
        'set makes it easy for anyone with access to the service to copy all information from the database. It is ' \
        'recommended that you change the password as soon as possible. There are multiple ways to do this, ' \
        'including using mysqladmin as follows:\n\n' \
        '`mysqladmin -u root password NEWPASSWORD`\n\n' \
        'Tip: If you are using mysqladmin as per above, make sure to add a space before the command to avoid it ' \
        'being stored in your shell\'s history.'
    severity = Severity.HI

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        return super().affected_devices(user, device_pk, exclude_snoozed).filter(mysql_root_access=True)


class PubliclyAccessibleServiceGroupAction(GroupedAction):
    group_action_title = 'Your services may be publicly accessible'
    group_action_main = 'We detected that the following services on your nodes may be accessible remotely.'
    action_id = 3000


class BasePubliclyAccessibleServiceAction(BaseAction):
    group_action = PubliclyAccessibleServiceGroupAction
    action_title = 'Your {service} instance may be publicly accessible'
    action_description = \
        'We detected that a {service} instance on {devices} may be accessible remotely. Consider either blocking '\
        'port {port} through the WoTT firewall management tool, or re-configure {service} to only listen on localhost.'
    group_action_section_body = action_description
    severity = Severity.HI

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk, exclude_snoozed):
            if cls.service in dev.public_services:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)

    @classmethod
    def get_action_description_context(cls, devices_qs, device_pk=None):
        return dict(service=cls.service_name, port=cls.port)


for service, service_info in PUBLIC_SERVICE_PORTS.items():
    class ConcretePubliclyAccessibleServiceAction(BasePubliclyAccessibleServiceAction, metaclass=ActionMeta):
        port, service_name, sub_id = service_info
        action_id = sub_id + PubliclyAccessibleServiceGroupAction.action_id
        service = service
        group_action_section_title = service_name


class CpuVulnerableAction(BaseAction, metaclass=ActionMeta):
    action_id = 12
    action_title = 'Your system is vulnerable to Meltdown and/or Spectre attacks'
    action_description = \
        'We detected that {devices} is vulnerable to Meltdown/Spectre. You can learn more about these issues ' \
        '[here](https://meltdownattack.com/). To fix the issue, please run `apt-get update && apt-get upgrade`'
    severity = Severity.HI

    @classmethod
    def affected_devices(cls, user, device_pk=None, exclude_snoozed=True):
        from .models import Device
        return Device.objects.filter(pk__in=[
            dev.pk for dev in super().affected_devices(user, device_pk, exclude_snoozed) if dev.cpu_vulnerable
        ])
