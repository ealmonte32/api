from datetime import timedelta
from enum import Enum
from typing import NamedTuple, List, Union
from urllib.parse import urljoin

from django.conf import settings
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone

import markdown


class Severity(Enum):
    LO = ('Low', 'secondary')
    MED = ('Medium', 'warning')
    HI = ('High', 'danger')


class InsecureService(NamedTuple):
    """
    name: Process name (e.g. fingerd, tftpd).
    sub_id: Action subclass id starting with 1. Should be unique across all InsecureService's.
    severity: Action severity.
    """
    name: str
    sub_id: int
    severity: Severity


class OpenSSHConfigParam(NamedTuple):
    """
    safe_value: The value of the config parameter which is considered safe.
    doc_url: "Learn More" URL or None.
    sub_id: Action subclass id starting with 1. Should be unique across all OpenSSHConfigParam's.
    severity: Action severity.
    """
    safe_value: str
    doc_url: str
    sub_id: int
    severity: Severity


class PubliclyAccessiblePort(NamedTuple):
    """
    port: TCP port number. Should ideally be a valid port number, i.e. in [0, 65535].
    name: Display name of the service listening on this port.
    sub_id: Action subclass id starting with 1. Should be unique across all PubliclyAccessiblePort's.
    """
    port: int
    name: str
    sub_id: int


class Action(NamedTuple):
    """
    :param title: Title text
    :param description: Body text
    :param action_id: the value of action_id field of BaseAction subclasses
    :param devices: list of device ids
    :param severity: Action severity (Severity)
    :param doc_url: "Learn more" URL, optional
    :param issue_url: Github issue URL, optional
    """
    title: str
    description: str
    action_id: int
    devices: List[int]
    severity: Severity
    doc_url: str = '/'
    issue_url: str = None

    @property
    def html(self):
        return markdown.markdown(self.description)


INSECURE_SERVICES = [
    InsecureService('fingerd', 1, Severity.MED),
    InsecureService('tftpd', 2, Severity.MED),
    InsecureService('telnetd', 3, Severity.HI),
    InsecureService('snmpd', 4, Severity.MED),
    InsecureService('xinetd', 5, Severity.MED),
    InsecureService('nis', 6, Severity.MED),
    InsecureService('atftpd', 7, Severity.MED),
    InsecureService('tftpd-hpa', 8, Severity.MED),
    InsecureService('rsh-server', 9, Severity.HI),
    InsecureService('rsh-redone-server', 10, Severity.HI)
]

SSHD_CONFIG_PARAMS_INFO = {
    'PermitEmptyPasswords': OpenSSHConfigParam(
        'no', None, 1, Severity.HI),
    'PermitRootLogin': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-perminrootlogin', 2, Severity.MED),
    'PasswordAuthentication': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-password-authentication', 3, Severity.HI),
    'AllowAgentForwarding': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-passwordauthentication', 4, Severity.MED),
    'Protocol': OpenSSHConfigParam(
        '2', None, 5, Severity.HI)
}

PUBLIC_SERVICE_PORTS = {
    'mongod': PubliclyAccessiblePort(27017, 'MongoDB', 1),
    'mysqld': PubliclyAccessiblePort(3306, 'MySQL/MariaDB', 2),
    'memcached': PubliclyAccessiblePort(11211, 'Memcached', 3),
    'redis-server': PubliclyAccessiblePort(6379, 'Redis', 4)
}


def device_link(device, absolute=False):
    """Create a device's page html link code"""
    url = reverse('device-detail', kwargs={'pk': device.pk})
    if absolute:
        url = urljoin(settings.DASH_URL, url)
    return f'[{device.get_name()}]({url})'


class BaseAction:
    """
    Common base action class.

    It's a parent for all specific base action classes.
    """
    severity = Severity.LO
    doc_url = 'https://wott.io/documentation/faq'

    @classmethod
    def affected_devices(cls, qs: QuerySet) -> QuerySet:
        """
        Select all devices which are affected by this recommended action.
        This method is to be used during migration when a new RA is added. It is supposed to be optimized for quick
        selection of devices, preferably with a single request. However the default implementation provided here is
        suboptimal because it calls is_affected() for every device.
        :param qs: QuerySet of Device which will be additionally filtered.
        :return: QuerySet
        """
        from .models import Device
        return Device.objects.filter(pk__in=[
            dev.pk for dev in qs if cls.is_affected(dev)
        ])

    @classmethod
    def is_affected(cls, device) -> bool:
        """
        Whether the supplied device is affected by this RA.
        :param device: a Device
        :return: bool
        """
        raise NotImplementedError

    @classmethod
    def get_context(cls, devices, device_pk=None) -> dict:
        """
        Method for producing a tuple of values used (as string formatting parameters)
         for action description text rendering.
        :param devices: list of Device model instances affected by the action;
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
    def action(cls, user, devices, device_pk=None) -> Action:
        """
        Generate a list of Action objects for the user. Excludes snoozed actions.
        :param user: the owner of the processed devices.
        :param devices: a list of Device
        :param device_pk: if given, then only one device with this pk is processed.
        :return:
        """
        context = cls.get_context(devices=devices, device_pk=device_pk)
        context['devices'] = ', '.join([device_link(dev) for dev in devices]) if device_pk is None else 'this node'
        return cls._create_action(user.profile, context, [d.pk for d in devices])

    @classmethod
    def get_description(cls, user, body=None, additional_context=None) -> (str, str):
        """
        Generate a Markdown-formatted descriptive text for this recommended action.
        Mainly used for filing Github issues. Does not exclude snoozed actions. Uses
        cls.action_description as a template and formats it using cls.get_context().
        :param user: the owner of the processed devices.
        :param body: if given, will be used as template instead of cls.action_description.
        :param additional_context: additional context for formatting the body.
        :return: (title, text)
        """
        from .models import RecommendedAction
        day_ago = timezone.now() - timedelta(hours=24)
        actions = RecommendedAction.objects.filter(device__owner=user, action_id=cls.action_id,
                                                   device__last_ping__gte=day_ago)\
                                           .exclude(status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=None)
        affected_devices = [action.device for action in actions]
        if not affected_devices or not any(a.status != RecommendedAction.Status.NOT_AFFECTED for a in actions):
            return
        affected_list = ['- [{x}] {device}'
                         .format(x='x' if a.status == RecommendedAction.Status.NOT_AFFECTED else ' ',
                                 device=device_link(a.device, absolute=True))
                         for a in actions]
        resolved = '\n'.join(affected_list)
        context = cls.get_context(affected_devices)
        if additional_context is not None:
            context.update(additional_context)
        if 'subject' in context:
            # Workaround for AutoUpdatesAction three-way logic
            context['subject'] = ''
        body_text = cls.action_description if body is None else body
        action_text = body_text.format(**context) + f"\n\n#### Resolved on: ####\n{resolved}"
        return cls.action_title, action_text


class GroupedAction:
    """
    Recommended Action which has subclasses. Can produce grouped description by merging descriptions of subclasses.
    A BaseAction class will be registered as a GroupedAction subclass if: it specifies grouped_action field and
    is has ActionMeta metaclass. Example:

        class Grouped(GroupedAction):
            group_action_main = "group main"
            group_action_title = "group title"

        class SomeBaseAction(BaseAction, metaclass=ActionMeta):
            grouped_action = Grouped

        class SomeConcreteAction(SomeBaseAction, metaclass=ActionMeta):
            group_action_section_title = "concrete title"
            group_action_section_body = "concrete body"

    Here, SomeConcreteAction will be registered subclass for Grouped. Then the result of Grouped.get_description()
    will be:
        "group title"
        group main

        concrete title
        concrete body
    It is designed for easy addition of subclasses. If you declare a number of classes similar to SomeConcreteAction
    they will be registered automatically.

    GroupedAction classes must have group_action_main and group_action_title declared. The registered subclasses must
    have group_action_section_title and group_action_section_body declared.
    """
    @classmethod
    def get_description(cls, user, **kwargs):
        """
        Behaves like BaseAction.get_description(), but merges descriptions from all subclasses, prepending
        group_action_main. The result looks like this:
          group_action_main

          group_action_section_title
          description

          group_action_section_title
          description

          ...
        """
        action_text = ''
        for subclass in cls.subclasses:
            description = subclass.get_description(user, body=subclass.group_action_section_body, **kwargs)
            if description:
                action_text += f"\n\n### {subclass.group_action_section_title} ###\n\n" + description[1]
        if not action_text:
            return
        return cls.group_action_title, cls.group_action_main + action_text


class ActionMeta(type):
    """
    Automatically registers action classes and divides them into regular, grouped and ungrouped (which are subclasses).
    A class is regular if it's neither grouped (i.e. subclass of GroupedAction), nor a subclass of grouped (doesn't have
    grouped_action field).
    """
    _action_classes = {}
    _grouped_action_classes = set()
    _ungrouped_action_classes = {}

    def __new__(meta, *args, **kwargs):
        """
        Called when a new class is declared with metaclass=ActionMeta. Registers the class.
        :return: The declared class type.
        """
        cls = type.__new__(meta, *args, **kwargs)  # Create the class type
        if cls.action_id in meta._action_classes or cls.action_id in meta._ungrouped_action_classes:
            raise ValueError('This action_id already exists')
        if hasattr(cls, 'group_action'):
            # If the class has this attribute then it should be registered as a subclass to the grouped action class
            # specified by group_action.
            group_action = cls.group_action
            meta._ungrouped_action_classes[cls.action_id] = cls
            if not hasattr(group_action, 'subclasses'):
                # The GroupedAction class does not have 'subclasses' declared initially because then it would be the
                # same for all its child classes.
                setattr(group_action, 'subclasses', [])
            group_action.subclasses.append(cls)
            meta._grouped_action_classes.add(group_action)
        else:
            meta._action_classes[cls.action_id] = cls
        return cls

    @classmethod
    def unregister(meta, cls):
        """
        Unregister the regular class. Mainly used in tests.
        :param cls:
        :return:
        """
        del meta._action_classes[cls.action_id]

    @classmethod
    def all_classes(meta, grouped=False) -> List[Union[BaseAction, GroupedAction]]:
        """
        Get a list of all registered action classes. Depending on value of "grouped", will return either
        regular and grouped classes, or regular and subclasses.
        :param grouped:
        :return:
        """
        regular = list(meta._action_classes.values())
        return regular + (list(meta._grouped_action_classes) if grouped
                          else list(meta._ungrouped_action_classes.values()))

    @classmethod
    def is_action_id(meta, id) -> bool:
        """
        Whether the provided action id is registered (has metaclass=ActionMeta)
        :param id:
        :return:
        """
        return id in meta._action_classes or id in meta._ungrouped_action_classes

    @classmethod
    def get_class(meta, id):
        return meta._action_classes.get(id) or meta._ungrouped_action_classes.get(id)


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
    def affected_devices(cls, qs):
        return qs.filter(deviceinfo__default_password=True)

    @classmethod
    def is_affected(cls, device) -> bool:
        return hasattr(device, 'deviceinfo') and device.deviceinfo.default_password is True


# Firewall disabled action.
class FirewallDisabledAction(BaseAction, metaclass=ActionMeta):
    action_id = 2
    action_title = 'Permissive firewall policy detected'
    action_description = \
        'We found permissive firewall policy present on {devices}. Please consider change it to more restrictive one.'
    severity = Severity.MED

    @classmethod
    def affected_devices(cls, qs):
        from .models import FirewallState, GlobalPolicy
        return qs.exclude(
            (Q(firewallstate__global_policy=None) & Q(firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)) |
            Q(firewallstate__global_policy__policy=GlobalPolicy.POLICY_BLOCK))

    @classmethod
    def is_affected(cls, device) -> bool:
        from .models import FirewallState, GlobalPolicy
        firewallstate = getattr(device, 'firewallstate', None)
        return firewallstate is not None and \
               (firewallstate.policy != FirewallState.POLICY_ENABLED_BLOCK \
                if firewallstate.global_policy is None \
                else firewallstate.global_policy.policy != GlobalPolicy.POLICY_BLOCK)


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
    def affected_devices(cls, qs):
        return qs.filter(deb_packages__vulnerabilities__isnull=False).distinct()

    @classmethod
    def is_affected(cls, device) -> bool:
        return device.deb_packages.filter(vulnerabilities__isnull=False).exists()


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
    def get_context(cls, devices, device_pk=None):
        return {'service': cls.service_name}

    @classmethod
    def affected_devices(cls, qs):
        return qs.exclude(deb_packages_hash='').filter(
            deb_packages__name=cls.service_name).distinct()

    @classmethod
    def is_affected(cls, device) -> bool:
        return device.deb_packages.filter(name=cls.service_name).exists()


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
    def get_context(cls, devices, device_pk=None):
        safe_value, doc_url, _, _ = SSHD_CONFIG_PARAMS_INFO[cls.sshd_param]
        return dict(param_name=cls.sshd_param,
                    safe_value=safe_value,
                    doc_url=doc_url)

    @classmethod
    def is_affected(cls, device) -> bool:
        issues = device.sshd_issues
        return cls.sshd_param in issues if issues is not None else False


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
        if len(devices) > 1:
            # Provide Debian's link if more than 1 device.
            return debian_url
        else:
            if devices[0].os_release.get('distro') == 'ubuntu':
                return ubuntu_url
            else:  # Everything besides Ubuntu is Debian.
                return debian_url

    @classmethod
    def get_context(cls, devices, device_pk=None):
        if device_pk is None:
            if len(devices) > 1:
                subject, verb = 'your nodes ', 'are'
            else:
                subject, verb = 'your node ', 'is'
        else:
            subject, verb = '', 'is'
        return {
            'subject': subject,
            'verb': verb,
            'doc_url': cls.get_doc_url(devices)
        }

    @classmethod
    def affected_devices(cls, qs):
        return qs.filter(auto_upgrades=False)

    @classmethod
    def is_affected(cls, device) -> bool:
        return device.auto_upgrades is False


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
    def is_affected(cls, device) -> bool:
        return device.is_ftp_public is True


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
    def affected_devices(cls, qs):
        return qs.filter(mysql_root_access=True)

    @classmethod
    def is_affected(cls, device) -> bool:
        return device.mysql_root_access is True


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
    def get_context(cls, devices, device_pk=None):
        return dict(service=cls.service_name, port=cls.port)

    @classmethod
    def is_affected(cls, device) -> bool:
        services = device.public_services
        return cls.service in services if services is not None else False


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
    def is_affected(cls, device) -> bool:
        return device.cpu_vulnerable is True
