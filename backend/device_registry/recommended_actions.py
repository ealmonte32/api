from collections import defaultdict
from datetime import timedelta
from enum import IntEnum
from typing import NamedTuple, List
from urllib.parse import urljoin

from django.conf import settings
from django.db.models import Q, QuerySet, Max, F
from django.urls import reverse
from django.utils import timezone

import yaml
import markdown


class Severity(IntEnum):
    LO = 1
    MED = 2
    HI = 3


class InsecureService(NamedTuple):
    """
    name: Process name (e.g. fingerd, tftpd).
    severity: Action severity.
    """
    name: str
    severity: Severity


class OpenSSHConfigParam(NamedTuple):
    """
    safe_value: The value of the config parameter which is considered safe.
    doc_url: "Learn More" URL or None.
    severity: Action severity.
    """
    safe_value: str
    doc_url: str
    severity: Severity


class PubliclyAccessiblePort(NamedTuple):
    """
    port: TCP port number. Should ideally be a valid port number, i.e. in [0, 65535].
    name: Display name of the service listening on this port.
    """
    port: int
    name: str


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
    severity_dict = {
        Severity.LO: ('Low', 'secondary'),
        Severity.MED: ('Medium', 'warning'),
        Severity.HI: ('High', 'danger')
    }

    @staticmethod
    def _html(md: str):
        return markdown.markdown(md, extensions=['attr_list'])

    @property
    def short_html(self):
        return self._html(self.short)

    @property
    def long_html(self):
        return self._html(self.long)

    @property
    def terminal_title_html(self):
        return self._html(self.terminal_title)

    @property
    def severity_info(self):
        return self.severity_dict[self.severity]


class ParamStatus(NamedTuple):
    param: str
    affected: bool


class ParamStatusQS(NamedTuple):
    param: str
    affected: QuerySet


INSECURE_SERVICES = [
    InsecureService('fingerd', Severity.MED),
    InsecureService('tftpd', Severity.MED),
    InsecureService('telnetd', Severity.HI),
    InsecureService('snmpd', Severity.MED),
    InsecureService('xinetd', Severity.MED),
    InsecureService('nis', Severity.MED),
    InsecureService('atftpd', Severity.MED),
    InsecureService('tftpd-hpa', Severity.MED),
    InsecureService('rsh-server', Severity.HI),
    InsecureService('rsh-redone-server', Severity.HI)
]

SSHD_CONFIG_PARAMS_INFO = {
    'PermitEmptyPasswords': OpenSSHConfigParam(
        'no', '', Severity.HI),
    'PermitRootLogin': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-perminrootlogin', Severity.MED),
    'PasswordAuthentication': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-passwordauthentication', Severity.HI),
    'AllowAgentForwarding': OpenSSHConfigParam(
        'no', 'https://wott.io/documentation/faq#openssh-allowagentforwarding', Severity.MED),
    'Protocol': OpenSSHConfigParam(
        '2', '', Severity.HI),
    'ClientAliveInterval': OpenSSHConfigParam(
        '300', '', Severity.MED),
    'ClientAliveCountMax': OpenSSHConfigParam(
        '3', '', Severity.MED),
    'HostbasedAuthentication': OpenSSHConfigParam(
        'no', '', Severity.MED),
    'IgnoreRhosts': OpenSSHConfigParam(
        'yes', '', Severity.MED),
    'LogLevel': OpenSSHConfigParam(
        'INFO', '', Severity.MED),
    'LoginGraceTime': OpenSSHConfigParam(
        '60', '', Severity.MED),
    'MaxAuthTries': OpenSSHConfigParam(
        '4', '', Severity.MED),
    'PermitUserEnvironment': OpenSSHConfigParam(
        'no', '', Severity.MED),
    'X11Forwarding': OpenSSHConfigParam(
        'no', '', Severity.MED)
}

PUBLIC_SERVICE_PORTS = {
    'mongod': PubliclyAccessiblePort(27017, 'MongoDB'),
    'mysqld': PubliclyAccessiblePort(3306, 'MySQL/MariaDB'),
    'memcached': PubliclyAccessiblePort(11211, 'Memcached'),
    'redis-server': PubliclyAccessiblePort(6379, 'Redis')
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
        suboptimal because it calls affected_params() for every device.
        :param qs: QuerySet of Device which will be additionally filtered.
        :return: list of ParamStatusQS (param, affected_list) for every possible param (which may be None).
        """
        raise NotImplementedError

    @classmethod
    def affected_params(cls, device) -> List[ParamStatus]:
        """
        Whether the supplied device is affected by this RA.
        :param device: a Device
        :return: list of ParamStatus (param, affected) for every possible param (which may be None).
        """
        raise NotImplementedError

    @classmethod
    def get_context(cls, param) -> dict:
        """
        Get a dict with replacements for action texts (long text, short text, title, terminal_title, terminal_code).
        Calls _get_context(), subclasses may add additional checks.
        :return: a dict;
        """
        return cls._get_context(param)

    @classmethod
    def _get_context(cls, param) -> dict:
        """
        Same as get_context(), but without any additional input checks.
        :param param:
        :return:
        """
        return {}

    @classmethod
    def create_action(cls, context, severity, devices_list, param=None) -> Action:
        """
        Create an Action object with title and description supplied by this class (cls), action description context,
        devices list and profile's github issue info (which can be empty).
        :param context: a dict obtained by get_context()
        :param devices_list: list of Device ids
        :param param: action param (if supported)
        :return: Action
        """
        if param is not None and param in cls.action_config:
            action_config = cls.action_config[param]
        else:
            action_config = cls.action_config
        return Action(
            title=action_config['title'].format(**context),
            subtitle=action_config.get('subtitle', SUBTITLES[severity]).format(**context),
            short=action_config['short'].format(**context),
            long=action_config['long'].format(**context),
            terminal_title=action_config.get('terminal_title', '').format(**context),
            terminal_code=action_config.get('terminal_code', '').format(**context),
            action_class=cls.__name__,
            action_param=param,
            devices=devices_list,
            severity=severity,
            doc_url=cls.doc_url,
            fleet_wide=getattr(cls, 'is_user_action', False)
        )

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
        terminal_title, terminal_code = action_config.get('terminal_title'), action_config.get('terminal_code')
        if terminal_title is not None and terminal_code is not None:
            terminal_block = f"{terminal_title.format(**context)}\n\n" \
                             f"```\n{terminal_code.format(**context).strip()}\n```\n\n"
        else:
            terminal_block = ""
        action_text = f"{action_config['short'].format(**context)}\n\n" \
                      f"{terminal_block}" \
                      f"{action_config['long'].format(**context)}\n\n" \
                      f"#### Resolved on: ####\n{resolved}\n\n" \
                      f"*Last modified: {timezone.datetime.now().strftime('%m-%d-%Y %H:%M')} UTC*"
        action_text = action_text.replace('{: target="_blank"}', '')

        resolved = [a.device for a in actions if a.status == RecommendedAction.Status.NOT_AFFECTED]
        affected = [a.device for a in actions if a.status != RecommendedAction.Status.NOT_AFFECTED]
        return action_config['title'].format(**context), action_text, affected, resolved


class SimpleAction(BaseAction):
    """
    An action with no params (meaning it has one param which is None). Subclasses should implement:
    _severity field;
    _is_affected(Device).
    """

    @classmethod
    def _is_affected(cls, device) -> bool:
        """
        Tell if the provided device is affected. Subclasses should implement this method.
        :param device: Device
        :return: single boolean value
        """
        raise NotImplementedError

    @classmethod
    def severity(cls, param=None):
        return cls._severity

    @classmethod
    def get_description(cls, user, param=None):
        return super()._get_description(user, param, cls.action_config)

    @classmethod
    def _affected_devices(cls, qs) -> List:
        """
        A simple param-less implementation which tests the supplied devices with _is_affected().
        Subclasses may override this for a more efficient batch check.
        :param qs: QuerySet or List
        :return: list of affected devices
        """
        return [dev for dev in qs if cls._is_affected(dev)]

    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        """
        Simply calls _affected_devices().
        """
        return [ParamStatusQS(None, cls._affected_devices(qs))]

    @classmethod
    def affected_params(cls, device) -> List[ParamStatus]:
        """
        Simply calls _is_affected().
        """
        return [ParamStatus(None, cls._is_affected(device))]


class ParamAction(BaseAction):
    """
    Parametrized action. Adds some checks for methods which accept param to make sure it is supplied.
    Subclasses may override _get_context() or affected_devices().
    """

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
        """
        A simple implementation which returns all devices returned by affected_params().
        Subclasses may override this for a more efficient batch check.
        """
        result = defaultdict(list)
        for dev in qs:
            for param, val in cls.affected_params(dev):
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
                if cls not in meta._config:
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
    _severity = Severity.MED

    @classmethod
    def _affected_devices(cls, qs):
        from .models import GlobalPolicy
        return qs.exclude(firewallstate__global_policy__policy=GlobalPolicy.POLICY_BLOCK)

    @classmethod
    def _is_affected(cls, device) -> bool:
        from .models import GlobalPolicy
        firewallstate = getattr(device, 'firewallstate', None)
        if firewallstate and firewallstate.global_policy and firewallstate.global_policy.policy \
                == GlobalPolicy.POLICY_BLOCK:
            return False
        return True


# OS reboot required action.
class RebootRequiredAction(SimpleAction, metaclass=ActionMeta):
    _severity = Severity.MED

    @classmethod
    def _affected_devices(cls, qs):
        return qs.filter(reboot_required=True)

    @classmethod
    def _is_affected(cls, device) -> bool:
        return device.reboot_required is True


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
        port, service_name = service_info
        return dict(service=service_name, port=port)

    @classmethod
    def affected_params(cls, device):
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


class AuditdNotInstalledAction(SimpleAction, metaclass=ActionMeta):
    _severity = Severity.MED

    @classmethod
    def _is_affected(cls, device) -> bool:
        from .models import DEBIAN_SUITES, UBUNTU_SUITES
        if device.os_release.get('codename') in DEBIAN_SUITES + UBUNTU_SUITES:
            return not device.deb_packages.filter(name='auditd').exists()
        elif device.os_release.get('codename') == 'amzn2':
            return not device.deb_packages.filter(name='audit').exists()
        return False

    @classmethod
    def _affected_devices(cls, qs):
        from .models import DEBIAN_SUITES, UBUNTU_SUITES
        return qs.filter(
            (Q(os_release__codename__in=DEBIAN_SUITES + UBUNTU_SUITES) & ~Q(deb_packages__name='auditd')) |
            (Q(os_release__codename='amzn2') & ~Q(deb_packages__name='audit'))
        ).distinct()


# --- Parameterized actions ---

# Default username/password used action.
class DefaultCredentialsAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        all_users = defaultdict(list)
        for d in qs.filter(default_password_users__len__gt=0):
            for u in d.default_password_users:
                all_users[u].append(d)
        return [ParamStatusQS(p, d) for p, d in all_users.items()]

    @classmethod
    def affected_params(cls, device) -> List[ParamStatus]:
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
                deb_packages__name=name).distinct()) for name, _  in INSECURE_SERVICES]

    @classmethod
    def affected_params(cls, device) -> List[ParamStatus]:
        return [ParamStatus(name, device.deb_packages.filter(name=name).exists()) for name, _ in INSECURE_SERVICES]

    @classmethod
    def severity(cls, param):
        # Find an item in INSECURE_SERVICES by service name
        return next(s.severity for s in INSECURE_SERVICES if s.name == param)


class OpensshIssueAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def _get_context(cls, param):
        safe_value, doc_url, _ = SSHD_CONFIG_PARAMS_INFO[param]
        return dict(param_name=param,
                    safe_value=safe_value,
                    doc_url=doc_url)

    @classmethod
    def affected_params(cls, device):
        affected = []
        for param in cls.action_config.keys():
            issues = device.sshd_issues
            affected.append(ParamStatus(param, param in issues if issues is not None else False))
        return affected

    @classmethod
    def severity(cls, param):
        return SSHD_CONFIG_PARAMS_INFO[param].severity


class CVEAction(ParamAction, metaclass=ActionMeta):
    @classmethod
    def _get_context(cls, param):
        from .models import DebPackage
        packages = DebPackage.objects.filter(vulnerabilities__name=param, vulnerabilities__fix_available=True) \
            .values_list('name', flat=True).distinct().order_by('name')
        packages_spaced = ' '.join(packages)
        packages_list = '\n'.join(f'* {p}' for p in packages)
        n = len(packages)
        if n == 0:
            raise RuntimeError
        if n == 1:
            short_packages_list = f'package {packages[0]}'
        elif n == 2:
            short_packages_list = f'packages {packages[0]} and {packages[1]}'
        elif n == 3:
            short_packages_list = f'packages {packages[0]}, {packages[1]} and  {packages[2]}'
        else:
            short_packages_list = f'packages {packages[0]}, {packages[1]}, {packages[2]} and more'
        return {'packages': packages_spaced,
                'packages_list': packages_list,
                'short_packages_list': short_packages_list,
                'cve_name': param,
                'cve_link': 'http://cve.mitre.org/cgi-bin/cvename.cgi?name='+param}

    @classmethod
    def affected_devices(cls, qs) -> List[ParamStatusQS]:
        from .models import Vulnerability, Device
        severity_none = Vulnerability.objects.values('name').annotate(max_urgency=Max('urgency')) \
            .filter(max_urgency=Vulnerability.Urgency.NONE).values('name')
        vv = Vulnerability.objects.filter(debpackage__device__in=qs, fix_available=True)\
                                  .annotate(device=F('debpackage__device'))\
                                  .values('name', 'device').distinct()\
                                  .exclude(name__in=severity_none)\
                                  .order_by('name')
        name = None
        devices = []
        result = []
        for v in vv:
            devices.append(v['device'])
            if name != v['name']:
                if name is not None:
                    result.append(ParamStatusQS(v['name'], Device.objects.filter(pk__in=devices)))
                    devices = []
                name = v['name']

        return result

    @classmethod
    def affected_params(cls, device):
        from .models import Vulnerability
        severity_none = Vulnerability.objects.values('name').annotate(max_urgency=Max('urgency'))\
            .filter(max_urgency=Vulnerability.Urgency.NONE).values('name')
        vulns = Vulnerability.objects.filter(debpackage__device=device, fix_available=True)\
                                     .values_list('name', flat=True).distinct()\
                                     .exclude(name__in=severity_none)
        return [ParamStatus(name, True) for name in vulns]

    @classmethod
    def severity(cls, param):
        from .models import Vulnerability
        severity = Vulnerability.objects.filter(name=param).aggregate(Max('urgency'))['urgency__max']
        return Severity(severity or 1)

# --- Fleet-wide actions ---

class GithubAction(BaseAction, metaclass=ActionMeta):
    is_user_action = True

    @classmethod
    def severity(cls, param=None):
        return Severity.LO

    @classmethod
    def create_action(cls):
        return super().create_action({}, cls.severity(), [])

class EnrollAction(BaseAction, metaclass=ActionMeta):
    is_user_action = True

    @classmethod
    def create_action(cls, user):
        context = {'key': user.profile.pairing_key.key}
        return super().create_action(context, cls.severity(), [])

    @classmethod
    def severity(cls, param=None):
        return Severity.LO
