from django.db.models import Q
from django.urls import reverse

import markdown


class Action:
    """
    Action class.

    It's only purpose is to store particular actions info and be passed from a
     view to a template.
    """

    def __init__(self, title, description, snoozing_info, issue_url=None):
        """
        Args:
            title: Actions title.
            description: Action description.
            snoozing_info: a 2-elements list with an action id as a 1st element
             and the list of affected device ids as a 2nd element.
        """
        self.title = title
        self.description = markdown.markdown(description)
        self.snoozing_info = snoozing_info
        self.issue_url = issue_url


def device_link(device):
    """Create a device's page html link code"""
    url = reverse('device-detail', kwargs={'pk': device.pk})
    return f'[{device.get_name()}]({url})'


# A list for storing all available recommended actions classes for further usage.
# All newly added classes should be appended to it explicitly after the declaration.
# Otherwise they'll be inaccessible for the system.
action_classes = []


class BaseAction:
    """
    Common base action class.

    It's a parent for all specific base action classes.
    Contains the code supposed to fit *all* actions.
    """

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        devices = user.devices.exclude(snoozed_actions__contains=cls.action_id)
        if device_pk is not None:
            devices = devices.filter(pk=device_pk)
        return devices

    @classmethod
    def get_action_description_context(cls, device=None, devices_qs=None, device_pk=None):
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
        issue_number = profile.github_issues.get(str(cls.action_id))
        issue_url = f'{profile.github_repo_url}/issues/{issue_number}' if issue_number else None
        return Action(
            cls.action_title,
            cls.action_description.format(**context),
            [cls.action_id, devices_list],
            issue_url
        )


class ActionMultiDevice(BaseAction):
    """
    Specific base action class for actions able to store info for *multiple* devices.
    """

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


class ActionPerDevice(BaseAction):
    """
    Specific base action class for actions able to store info for only *single* device.
    """

    @classmethod
    def actions(cls, user, device_pk=None):
        actions_list = []
        devices = cls.affected_devices(user, device_pk)
        for dev in devices:
            context = cls.get_action_description_context(device=dev, device_pk=device_pk)
            context['devices'] = device_link(dev) if device_pk is None else 'this node'
            actions_list.append(cls._create_action(user.profile, context, [dev.pk]))
        return actions_list

    @classmethod
    def action_blocks_count(cls, user):
        return cls.affected_devices(user).count()


# Below is the code for real actions classes.
# Don't forget to explicitly append a newly created action class to `action_classes` list
# right after its declaration.

# Default username/password used action.
class DefaultCredentialsAction(ActionMultiDevice):
    action_id = 1
    action_title = 'Default credentials detected'
    action_description = \
        'We found default credentials present on {devices}. Please consider changing them as soon as possible.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(deviceinfo__default_password=True)


action_classes.append(DefaultCredentialsAction)


# Firewall disabled action.
class FirewallDisabledAction(ActionMultiDevice):
    action_id = 2
    action_title = 'Permissive firewall policy detected'
    action_description = \
        'We found permissive firewall policy present on {devices}. Please consider change it to more restrictive one.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import FirewallState, GlobalPolicy
        return super().affected_devices(user, device_pk).exclude(
            (Q(firewallstate__global_policy__isnull=True) & Q(firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)) |
            Q(firewallstate__global_policy__policy=GlobalPolicy.POLICY_BLOCK))


action_classes.append(FirewallDisabledAction)


# Vulnerable packages found action.
class VulnerablePackagesAction(ActionMultiDevice):
    action_id = 3
    action_title = 'Vulnerable packages found'
    action_description = \
        'We found vulnerable packages on {devices}. These packages could be used by an attacker to either gain ' \
        'access to your node, or escalate permission. It is recommended that you address this at your earliest ' \
        'convenience.\n\n' \
        'Run `sudo apt-get update && sudo apt-get upgrade` to bring your system up to date.\n\n' \
        'Please note that there might be vulnerabilities detected that are yet to be fixed by the operating system ' \
        'vendor.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(deb_packages__vulnerabilities__isnull=False).distinct()


action_classes.append(VulnerablePackagesAction)


# Insecure services found action.
class InsecureServicesAction(ActionPerDevice):
    action_id = 4
    action_title = 'Insecure services found'
    action_description = \
        'We found insecure services installed on {devices}. Because these services are considered insecure, it is ' \
        'recommended that you uninstall them.\n\n' \
        'Run `sudo apt-get purge {services}`to disable all insecure services.'

    @classmethod
    def get_action_description_context(cls, device=None, devices_qs=None, device_pk=None):
        from device_registry.models import Device
        if devices_qs is not None:
            services = devices_qs.filter(deb_packages__name__in=Device.INSECURE_SERVICES)
        else:
            services = device.insecure_services
        services_str = ' '.join(services.values_list('name', flat=True))
        return {'services': services_str}

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        return super().affected_devices(user, device_pk).exclude(deb_packages_hash='').filter(
            deb_packages__name__in=Device.INSECURE_SERVICES).distinct()


action_classes.append(InsecureServicesAction)


# OpenSSH configuration issues found action.
class OpensshConfigurationIssuesAction(ActionPerDevice):
    action_id = 5
    action_title = 'Insecure configuration for OpenSSH found'
    action_description = \
        'We found insecure configuration issues with OpenSSH on {devices}. To improve the security posture of your ' \
        'node, please consider making the following changes:\n\n{changes}'

    @classmethod
    def get_action_description_context(cls, device=None, devices_qs=None, device_pk=None):
        recommendations = ''
        if devices_qs is not None:
            for device in devices_qs:
                for issue in device.sshd_issues:
                    recommendations += f'- Change "**{issue[0]}**" from "**{issue[1]}**" to "' \
                                       f'**{issue[2][0]}**" on {device_link(device)}.\n'
                    if issue[2][1]:  # Documentation link available.
                        recommendations += f' Learn more [here]({issue[2][1]})\n'
        else:
            for issue in device.sshd_issues:
                recommendations += f'- Change "**{issue[0]}**" from "**{issue[1]}**" to "' \
                                   f'**{issue[2][0]}**".\n'
                if issue[2][1]:  # Documentation link available.
                    recommendations += f' Learn more [here]({issue[2][1]})\n'
        return {'changes': recommendations}

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        dev_ids = []
        devices = super().affected_devices(user, device_pk).exclude(audit_files__in=('', []))
        for dev in devices:
            if dev.sshd_issues:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


action_classes.append(OpensshConfigurationIssuesAction)


# Automatic security update disabled action.
class AutoUpdatesAction(ActionMultiDevice):
    action_id = 6
    action_title = 'Consider enable automatic security updates'
    action_description = \
        'We found that {subject}{devices} {verb} not configured to automatically install security updates. Consider ' \
        'enabling this feature.\n\n' \
        'Details for how to do this can be found [here]({doc_url})'

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
    def get_action_description_context(cls, device=None, devices_qs=None, device_pk=None):
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
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(auto_upgrades=False)


action_classes.append(AutoUpdatesAction)


# FTP listening on port 21 action.
class FtpServerAction(ActionPerDevice):
    action_id = 7
    action_title = 'Consider moving to SFTP'
    action_description = \
        'There appears to be an FTP server running on {devices}. FTP is generally considered insecure as the ' \
        'credentials are sent unencrypted over the internet. Consider switching to an encrypted service, such as ' \
        '[SFTP](https://www.ssh.com/ssh/sftp).'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk):
            if dev.is_ftp_public:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


action_classes.append(FtpServerAction)


# Insecure MongoDB action.
class MongodbAction(ActionPerDevice):
    action_id = 8
    action_title = 'Your MongoDB instance may be publicly accessible'
    action_description = \
        'We detected that a MongoDB instance on {devices} may be accessible remotely. Consider either blocking port ' \
        '27017 through the WoTT firewall management tool, or re-configure MongoDB to only listen on localhost.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk):
            if 'mongod' in dev.public_services:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


action_classes.append(MongodbAction)


# Insecure MySQL/MariaDB action.
class MysqlAction(ActionPerDevice):
    action_id = 9
    action_title = 'Your MySQL instance may be publicly accessible'
    action_description = \
        'We detected that a MySQL instance on {devices} may be accessible remotely. Consider either blocking port ' \
        '3306 through the WoTT firewall management tool, or re-configure MySQL to only listen on localhost.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk):
            if 'mysqld' in dev.public_services:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


action_classes.append(MysqlAction)


# MySQL root default password action.
class MySQLDefaultRootPasswordAction(ActionPerDevice):
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

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(mysql_root_access=True)


action_classes.append(MySQLDefaultRootPasswordAction)


# Insecure Memcached action.
class MemcachedAction(ActionPerDevice):
    action_id = 11
    action_title = 'Your Memcached instance may be publicly accessible'
    action_description = \
        'We detected that a Memcached instance on {devices} may be accessible remotely. Consider either blocking ' \
        'port 11211 through the WoTT firewall management tool, or re-configure Memcached to only listen on localhost.'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        dev_ids = []
        for dev in super().affected_devices(user, device_pk):
            if 'memcached' in dev.public_services:
                dev_ids.append(dev.pk)
        return Device.objects.filter(pk__in=dev_ids)


action_classes.append(MemcachedAction)


class CpuVulnerableAction(ActionPerDevice):
    action_id = 12
    action_title = 'Your system is vulnerable to Meltdown and/or Spectre attacks'
    action_description = \
        'We detected that {devices} is vulnerable to Meltdown/Spectre. You can learn more about these issues ' \
        '[here](https://meltdownattack.com/). To fix the issue, please run `apt-get update && apt-get upgrade`'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        return Device.objects.filter(pk__in=[
            dev.pk for dev in super().affected_devices(user, device_pk) if dev.cpu_vulnerable
        ])


action_classes.append(CpuVulnerableAction)

# Check for `action_id` property uniqueness among all action classes.
if len({action_class.action_id for action_class in action_classes}) < len(action_classes):
    raise ValueError('`action_classes` contains class(es) with non-unique `action_id` property.')
