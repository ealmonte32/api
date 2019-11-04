from django.urls import reverse


class Action:
    """
    Action class.

    It's only purpose is to store particular actions info and be passed from a
     view to a template.
    """

    def __init__(self, title, description, snoozing_info):
        """
        Args:
            title: Actions title.
            description: Action description.
            snoozing_info: a 2-elements list with an action id as a 1st element
             and the list of affected device ids as a 2nd element.
        """
        self.title = title
        self.description = description
        self.snoozing_info = snoozing_info


def device_link(device):
    """Create a device's page html link code"""
    url = reverse('device-detail', kwargs={'pk': device.pk})
    return f'<a href="{url}">{device.get_name()}</a>'


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
    def get_action_description_context(cls, devices, device_pk):
        """
        Method for producing a tuple of values used (as string formatting parameters)
         for action description text rendering.
        :param devices: queryset for Device model instances affected by the action;
        :param device_pk: int/None - single affected device id;
        :return: iterable (tuple/list);
        """
        raise NotImplementedError


class ActionMultiDevice(BaseAction):
    """
    Specific base action class for actions able to store info for *multiple* devices.
    """

    @classmethod
    def get_action_description_context(cls, devices, device_pk):
        if device_pk is None:
            return (', '.join([device_link(dev) for dev in devices]),)
        else:
            return ('this node',)

    @classmethod
    def actions(cls, user, device_pk=None):
        actions_list = []
        devices = cls.affected_devices(user, device_pk)
        if devices.exists():
            action = Action(
                cls.action_title,
                cls.action_description % cls.get_action_description_context(devices, device_pk),
                [cls.action_id, list(devices.values_list('pk', flat=True))]
            )
            actions_list.append(action)
        return actions_list


class ActionPerDevice(BaseAction):
    """
        Specific base action class for actions able to store info for only *single* device.
    """

    @classmethod
    def get_action_description_context(cls, device, device_pk):
        if device_pk is None:
            return (device_link(device),)
        else:
            return ('this node',)

    @classmethod
    def actions(cls, user, device_pk=None):
        actions_list = []
        devices = cls.affected_devices(user, device_pk)
        for dev in devices:
            action = Action(
                cls.action_title,
                cls.action_description % cls.get_action_description_context(dev, device_pk),
                [cls.action_id, [dev.pk]]
            )
            actions_list.append(action)
        return actions_list


# Below is the code for real actions classes.
# Don't forget to explicitly append a newly created action class to `action_classes` list
# right after its declaration.

# Default username/password used action.
class DefaultCredentialsAction(ActionMultiDevice):
    action_id = 1
    action_title = 'Default credentials detected'
    action_description = '<p>We found default credentials present on %s. Please consider changing them as soon as ' \
                         'possible.</p>'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(deviceinfo__default_password=True)


action_classes.append(DefaultCredentialsAction)


# Firewall disabled action.
class FirewallDisabledAction(ActionMultiDevice):
    action_id = 2
    action_title = 'Permissive firewall policy detected'
    action_description = '<p>We found permissive firewall policy present on %s. Please consider change it to more ' \
                         'restrictive one.</p>'

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import FirewallState
        return super().affected_devices(user, device_pk).exclude(
            firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)


action_classes.append(FirewallDisabledAction)


# Vulnerable packages found action.
class VulnerablePackagesAction(ActionMultiDevice):
    action_id = 3
    action_title = 'Vulnerable packages found'
    action_description = """<p>We found vulnerable packages on %s. These packages could be used by an attacker to 
    either gain access to your node, or escalate permission. It is recommended that you address this at your earliest 
    convenience.</p>
    <p>Run <code>sudo apt-get update && sudo apt-get upgrade</code> to bring your system up to date.</p>
    <p>Please note that there might be vulnerabilities detected that are yet to be fixed by the operating system 
    vendor.</p>"""

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(deb_packages__vulnerabilities__isnull=False).distinct()


action_classes.append(VulnerablePackagesAction)


# Insecure services found action.
class InsecureServicesAction(ActionPerDevice):
    action_id = 4
    action_title = 'Insecure services found'
    action_description = '<p>We found insecure services installed on %s. Because these services are considered ' \
                         'insecure, it is recommended that you uninstall them.</p><p>Run <code>sudo apt-get purge %s' \
                         '</code> to disable all insecure services.</p>'

    @classmethod
    def get_action_description_context(cls, device, device_pk):
        if device_pk is None:
            dev_str = device_link(device)
        else:
            dev_str = 'this node'
        services_str = ' '.join(device.insecure_services.values_list('name', flat=True))
        return dev_str, services_str

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        from .models import Device
        return super().affected_devices(user, device_pk).exclude(deb_packages_hash='').filter(
            deb_packages__name__in=Device.INSECURE_SERVICES).distinct()


action_classes.append(InsecureServicesAction)


# OpenSSH configuration issues found action.
class OpensshConfigurationIssuesAction(ActionPerDevice):
    action_id = 5
    action_title = 'Insecure configuration for <strong>OpenSSH</strong> found'
    action_description = '<p>We found insecure configuration issues with OpenSSH on %s. To improve the security ' \
                         'posture of your node, please consider making the following changes:%s</p>'

    @classmethod
    def get_action_description_context(cls, device, device_pk):
        if device_pk is None:
            dev_str = device_link(device)
        else:
            dev_str = 'this node'
        recommendations = ''
        for issue in device.sshd_issues:
            recommendations += f'<li>Change "<strong>{issue[0]}</strong>" from "<strong>{issue[1]}</strong>" to "' \
                               f'<strong>{issue[2]}</strong>"</li>'
        recommendations = '<ul>%s</ul>' % recommendations
        return dev_str, recommendations

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
    action_description = '<p>We found that %s not configured to automatically install security updates. Consider ' \
                         'enabling this feature.</p>' \
                         '<p>Details for how to do this can be found <a href="%s" target="_blank">here</a>.</p>'

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
    def get_action_description_context(cls, devices, device_pk):
        if device_pk is None:
            dev_list = [device_link(dev) for dev in devices]
            full_string = ', '.join(dev_list)
            if len(dev_list) > 1:
                dev_str = f'your nodes {full_string} are'
            else:
                dev_str = f'your node {full_string} is'
        else:
            dev_str = 'this node is'
        return dev_str, cls.get_doc_url(devices)

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(auto_upgrades=False)


action_classes.append(AutoUpdatesAction)


# FTP listening on port 21 action.
class FtpServerAction(ActionPerDevice):
    action_id = 7
    action_title = 'Consider moving to SFTP'
    action_description = 'There appears to be an FTP server running on %s. FTP is generally considered insecure as ' \
                         'the credentials are sent unencrypted over the internet. Consider switching to an ' \
                         'encrypted service, such as SFTP (https://www.ssh.com/ssh/sftp/)'

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
    action_description = 'We detected that a MongoDB instance on %s may be accessible remotely. ' \
                         'Consider either blocking port 27017 through the WoTT firewall management tool, or ' \
                         're-configure MongoDB to only listen on localhost.'

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
    action_description = 'We detected that a MySQL instance on %s may be accessible remotely. ' \
                         'Consider either blocking port 3306 through the WoTT firewall management tool, or ' \
                         're-configure MySQL to only listen on localhost.'

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
    action_description = """We detected that there is no root password set for MySQL/MariaDB on %s.
            Not having a root password set makes it easy for anyone with access to the
            service to copy all information from the database. It is recommended that 
            you change the password as soon as possible. There are multiple ways to do
            this, including using mysqladmin as follows:

            <pre>mysqladmin -u root password NEWPASSWORD</pre>

            Tip: If you are using mysqladmin as per above, make sure to add a space 
            before the command to avoid it being stored in your shell's history."""

    @classmethod
    def affected_devices(cls, user, device_pk=None):
        return super().affected_devices(user, device_pk).filter(mysql_root_access=True)


action_classes.append(MySQLDefaultRootPasswordAction)

# Check for `action_id` property uniqueness among all action classes.
if len({action_class.action_id for action_class in action_classes}) < len(action_classes):
    raise ValueError('`action_classes` contains class(es) with non-unique `action_id` property.')
