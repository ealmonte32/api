from collections import defaultdict
from datetime import timedelta
from enum import Enum
from typing import NamedTuple, List, Union
from urllib.parse import urljoin

from django.conf import settings
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone

import yaml
import markdown


class Severity(Enum):
    LO = ('Low', 'secondary', 1)
    MED = ('Medium', 'warning', 2)
    HI = ('High', 'danger', 3)


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
    subtitle: str
    short: str
    long: str
    action_class: str
    action_param: str
    devices: List[int]
    severity: Severity
    fleet_wide: bool
    terminal_title: str = None
    terminal_code: str = None
    doc_url: str = '/'
    issue_url: str = None
    resolved: bool = None
    id: int = 0

    @property
    def short_html(self):
        return markdown.markdown(self.short)

    @property
    def long_html(self):
        return markdown.markdown(self.long)

    @property
    def terminal_title_html(self):
        return markdown.markdown(self.terminal_title)


class ParamStatus(NamedTuple):
    param: str
    affected: bool


class ParamStatusQS(NamedTuple):
    param: str
    affected: QuerySet


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
        'no', '', 1, Severity.HI),
    'PermitRootLogin': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-perminrootlogin', 2, Severity.MED),
    'PasswordAuthentication': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-passwordauthentication', 3, Severity.HI),
    'AllowAgentForwarding': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-allowagentforwarding', 4, Severity.MED),
    'Protocol': OpenSSHConfigParam(
        '2', '', 5, Severity.HI)
}

PUBLIC_SERVICE_PORTS = {
    'mongod': PubliclyAccessiblePort(27017, 'MongoDB', 1),
    'mysqld': PubliclyAccessiblePort(3306, 'MySQL/MariaDB', 2),
    'memcached': PubliclyAccessiblePort(11211, 'Memcached', 3),
    'redis-server': PubliclyAccessiblePort(6379, 'Redis', 4)
}

SUBTITLES = {
    Severity.HI: 'Please consider changing this as soon as possible',
    Severity.MED: 'This could put you at risk',
    Severity.LO: 'Resolve this to improve your security posture'
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
    doc_url = 'https://wott.io/documentation/faq'
    has_param = False

    @classmethod
    def severity(cls, param=None):
        raise NotImplementedError

    @classmethod
    def affected_devices(cls, qs: QuerySet) -> List[ParamStatusQS]:
        """
        Select all devices which are affected by this recommended action.
        This method is to be used during migration when a new RA is added. It is supposed to be optimized for quick
        selection of devices, preferably with a single request. However the default implementation provided here is
        suboptimal because it calls is_affected() for every device.
        :param qs: QuerySet of Device which will be additionally filtered.
        :return: QuerySet
        """
        raise NotImplementedError

    @classmethod
    def is_affected(cls, device) -> List[ParamStatus]:
        """
        Whether the supplied device is affected by this RA.
        :param device: a Device
        :return: bool
        """
        raise NotImplementedError

    @classmethod
    def get_context(cls, param) -> dict:
        return cls._get_context(param)

    @classmethod
    def _get_context(cls, param) -> dict:
        """
        Method for producing a tuple of values used (as string formatting parameters)
         for action description text rendering.
        :param devices: list of Device model instances affected by the action;
        :param device_pk: int/None - single affected device id;
        :return: iterable (tuple/list);
        """
        return {}

    @classmethod
    def _create_action(cls, context, devices_list, param=None) -> Action:
        """
        Create an Action object with title and description supplied by this class (cls), action description context,
        devices list and profile's github issue info (which can be empty).
        :param profile: Profile
        :param context: a format dict for action_description
        :param devices_list: list of Device ids
        :return: Action
        """
        if param is not None and param in cls.action_config:
            action_config = cls.action_config[param]
        else:
            action_config = cls.action_config
        return Action(
            title=action_config['title'].format(**context),
            subtitle=action_config.get('subtitle', SUBTITLES[cls.severity(param)]).format(**context),
            short=action_config['short'].format(**context),
            long=action_config['long'].format(**context),
            terminal_title=action_config.get('terminal_title', '').format(**context),
            terminal_code=action_config.get('terminal_code', '').format(**context),
            action_class=cls.__name__,
            action_param=param,
            devices=devices_list,
            severity=cls.severity(param),
            doc_url=cls.doc_url,
            fleet_wide=getattr(cls, 'is_user_action', False)
        )

    @classmethod
    def action(cls, devices, param=None) -> Action:
        """
        Generate a list of Action objects for the user. Excludes snoozed actions.
        :param user: the owner of the processed devices.
        :param devices: a list of Device
        :param device_pk: if given, then only one device with this pk is processed.
        :return:
        """
        context = cls.get_context(param)
        return cls._create_action(context, devices, param)

    @classmethod
    def _get_description(cls, user, param, action_config) -> (str, str):
        """
        Generate a Markdown-formatted descriptive text for this recommended action.
        Mainly used for filing Github issues. Does not exclude snoozed actions. Uses
        cls.action_description as a template and formats it using cls.get_context().
        :param user: the owner of the processed devices.
        :return: (title, text)
        """
        from .models import RecommendedAction, RecommendedActionStatus
        day_ago = timezone.now() - timedelta(hours=24)
        actions = RecommendedActionStatus.objects.filter(device__owner=user,
                                                   ra__action_class=cls.__name__,
                                                   ra__action_param=param,
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
        context = cls.get_context(param)
        body_text = action_config['long']
        action_text = body_text.format(**context) + f"\n\n#### Resolved on: ####\n{resolved}"
        return action_config['title'], action_text


class SimpleAction(BaseAction):
    @classmethod
    def severity(cls, param=None):
        return cls._severity

    @classmethod
    def get_description(cls, user, param=None):
        return super()._get_description(user, param, cls.action_config)

    @classmethod
    def _affected_devices(cls, qs) -> List:
        return [dev for dev in qs if cls._is_affected(dev)]

    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        return [ParamStatusQS(None, cls._affected_devices(qs))]

    @classmethod
    def is_affected(cls, device) -> List[ParamStatus]:
        return [ParamStatus(None, cls._is_affected(device))]


class ParamAction(BaseAction):
    has_param = True

    @classmethod
    def get_description(cls, user, param):
        if param in cls.action_config:
            action_config = cls.action_config[param]
        else:
            action_config = cls.action_config
        return super()._get_description(user, param, action_config)

    @classmethod
    def get_context(cls, param):
        if param is None:
            raise NotImplementedError
        return cls._get_context(param)

    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        result = defaultdict(list)
        for dev in qs:
            for param, val in cls.is_affected(dev):
                if val:
                    result[param].append(dev)
        return [ParamStatusQS(param, devices) for param, devices in result.items()]


class ActionMeta(type):
    """
    Automatically registers action classes and divides them into regular, grouped and ungrouped (which are subclasses).
    A class is regular if it's neither grouped (i.e. subclass of GroupedAction), nor a subclass of grouped (doesn't have
    grouped_action field).
    """
    _action_classes = {}
    _config = {}

    def __new__(meta, *args, **kwargs):
        """
        Called when a new class is declared with metaclass=ActionMeta. Registers the class.
        :return: The declared class type.
        """
        cls = type.__new__(meta, *args, **kwargs)  # Create the class type
        if hasattr(cls, 'action_class'):
            cls.__name__ = cls.action_class
        if cls.__name__ in meta._action_classes:
            raise ValueError('This action class already exists')
        meta._action_classes[cls.__name__] = cls

        if not meta._config:
            meta.load_config()
        if not hasattr(cls, 'action_config'):
            # If action_cofig is specified as a class attribute it won't be loaded from the config file.
            # Mostly makes sense for testing.
            cls.action_config = meta._config.get(cls.__name__)
        return cls

    @classmethod
    def load_config(meta):
        config = yaml.load(open('recommended_actions.yaml'), Loader=yaml.FullLoader)
        for e in config:
            cls = e['class']
            param = e.get('param')
            if param:
                if not cls in meta._config:
                    meta._config[cls] = {}
                meta._config[cls][param] = e
            else:
                meta._config[cls] = e

    @classmethod
    def unregister(meta, cls):
        """
        Unregister the regular class. Mainly used in tests.
        :param cls:
        :return:
        """
        del meta._action_classes[cls.__name__]

    @classmethod
    def all_classes(meta) -> List[BaseAction]:
        """
        Get a list of all registered action classes. Depending on value of "grouped", will return either
        regular and grouped classes, or regular and subclasses.
        :param grouped:
        :return:
        """

        # Classes with action_id < 0 are "special": they are for a user, not for device(s).
        # We don't store those in database.
        return [c for c in meta._action_classes.values() if not getattr(c, 'is_user_action', False)]

    @classmethod
    def is_action_class(meta, id) -> bool:
        """
        Whether the provided action id is registered (has metaclass=ActionMeta)
        :param id:
        :return:
        """
        return id in meta._action_classes

    @classmethod
    def get_class(meta, id):
        return meta._action_classes.get(id)


# Below is the code for real actions classes.
# Don't forget to add metaclass=ActionMeta.

# Firewall disabled action.
class FirewallDisabledAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _affected_devices(cls, qs):
        from .models import FirewallState, GlobalPolicy
        return qs.exclude(
            (Q(firewallstate__global_policy=None) & Q(firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)) |
            Q(firewallstate__global_policy__policy=GlobalPolicy.POLICY_BLOCK))

    @classmethod
    def _is_affected(cls, device) -> bool:
        from .models import FirewallState, GlobalPolicy
        firewallstate = getattr(device, 'firewallstate', None)
        return firewallstate is not None and \
               (firewallstate.policy != FirewallState.POLICY_ENABLED_BLOCK
                if firewallstate.global_policy is None
                else firewallstate.global_policy.policy != GlobalPolicy.POLICY_BLOCK)

    @classmethod
    def severity(cls, param=None):
        return Severity.MED


# Vulnerable packages found action.
class VulnerablePackagesAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _affected_devices(cls, qs):
        return qs.filter(deb_packages__vulnerabilities__isnull=False).distinct()

    @classmethod
    def _is_affected(cls, device) -> bool:
        return device.deb_packages.filter(vulnerabilities__isnull=False).exists()

    @classmethod
    def severity(cls, param=None):
        return Severity.MED


# Automatic security update disabled action.
class AutoUpdatesAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _affected_devices(cls, qs):
        return qs.filter(auto_upgrades=False)

    @classmethod
    def _is_affected(cls, device) -> bool:
        return device.auto_upgrades is False

    @classmethod
    def severity(cls, param=None):
        return Severity.HI


# FTP listening on port 21 action.
class FtpServerAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _is_affected(cls, device) -> bool:
        return device.is_ftp_public is True

    @classmethod
    def severity(cls, param=None):
        return Severity.MED


# MySQL root default password action.
class MySQLDefaultRootPasswordAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _affected_devices(cls, qs):
        return qs.filter(mysql_root_access=True)

    @classmethod
    def _is_affected(cls, device) -> bool:
        return device.mysql_root_access is True

    @classmethod
    def severity(cls, param=None):
        return Severity.HI


class PubliclyAccessibleServiceAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def _get_context(cls, param):
        service_info = PUBLIC_SERVICE_PORTS[param]
        port, service_name, sub_id = service_info
        return dict(service=service_name, port=port)

    @classmethod
    def is_affected(cls, device):
        services = device.public_services
        return [ParamStatus(service, service in services if services is not None else False)
                for service in PUBLIC_SERVICE_PORTS.keys()]

    @classmethod
    def severity(cls, param=None):
        return Severity.HI


class CpuVulnerableAction(SimpleAction, metaclass=ActionMeta):
    @classmethod
    def _is_affected(cls, device):
        return device.cpu_vulnerable is True

    @classmethod
    def severity(cls, param=None):
        return Severity.HI


# --- Parameterized actions ---

# Default username/password used action.
class DefaultCredentialsAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        all_users = defaultdict(list)
        for d in qs.filter(default_password_users__isnull=False, default_password_users__len__gt=0):
            for u in d.default_password_users:
                all_users[u].append(d)
        return [ParamStatusQS(p, d) for p, d in all_users.items()]

    @classmethod
    def is_affected(cls, device) -> List[ParamStatus]:
        return [ParamStatus(u, True) for u in device.default_password_users] if device.default_password_users else []

    @classmethod
    def severity(cls, param=None):
        return Severity.HI

    @classmethod
    def _get_context(cls, param) -> dict:
        return {'username': param}


class InsecureServicesAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def _get_context(cls, param):
        return {'service': param}

    @classmethod
    def affected_devices(cls, qs):
        return [ParamStatusQS(name, qs.exclude(deb_packages_hash='').filter(
                deb_packages__name=name).distinct()) for name, _, _ in INSECURE_SERVICES]

    @classmethod
    def is_affected(cls, device) -> List[ParamStatus]:
        return [ParamStatus(name, device.deb_packages.filter(name=name).exists()) for name, _, _ in INSECURE_SERVICES]

    @classmethod
    def severity(cls, param):
        return next(s.severity for s in INSECURE_SERVICES if s.name == param)


class OpensshIssueAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def _get_context(cls, param):
        safe_value, doc_url, _, _ = SSHD_CONFIG_PARAMS_INFO[param]
        return dict(param_name=param,
                    safe_value=safe_value,
                    doc_url=doc_url)

    @classmethod
    def is_affected(cls, device):
        affected = []
        for param in cls.action_config.keys():
            issues = device.sshd_issues
            affected.append(ParamStatus(param, param in issues if issues is not None else False))
        return affected

    @classmethod
    def severity(cls, param):
        return SSHD_CONFIG_PARAMS_INFO[param].severity


# --- Fleet-wide actions ---

class GithubAction(BaseAction, metaclass=ActionMeta):
    is_user_action = True

    @classmethod
    def severity(cls, param=None):
        return Severity.LO


class EnrollAction(BaseAction, metaclass=ActionMeta):
    is_user_action = True

    @classmethod
    def get_user_context(cls, user):
        context = {'key': user.profile.pairing_key.key}
        return EnrollAction._create_action(context, [])

    @classmethod
    def severity(cls, param=None):
        return Severity.LO
