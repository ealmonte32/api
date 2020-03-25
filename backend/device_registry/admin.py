from django.contrib import admin
from django_json_widget.widgets import JSONEditorWidget
from django.contrib.postgres.fields import JSONField

from .models import Device, DeviceInfo, PortScan, FirewallState, Credential, GlobalPolicy, Distro, Vulnerability


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = [
        'device_id',
        'created',
        'last_ping',
        'owner',
        'claimed'
    ]

    list_filter = (
        'last_ping',
    )

    ordering = ('last_ping',)
    readonly_fields = ('claim_token', 'fallback_token')


@admin.register(DeviceInfo)
class DeviceInfoAdmin(admin.ModelAdmin):
    list_display = [
        'device',
        'device_manufacturer',
        'device_model',
        'device_architecture',
        'device_operating_system',
        'device_operating_system_version',
        'selinux_state',
        'app_armor_enabled'
    ]

    formfield_overrides = {
        JSONField: {'widget': JSONEditorWidget},
    }


@admin.register(PortScan)
class PortscanAdmin(admin.ModelAdmin):
    list_display = ['device', 'scan_date']

    formfield_overrides = {
        JSONField: {'widget': JSONEditorWidget},
    }

    ordering = ('scan_date',)


@admin.register(FirewallState)
class FirewallStateAdmin(admin.ModelAdmin):
    list_display = [
        'device',
        'scan_date',
    ]

    ordering = ('scan_date',)


@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = ['owner', 'name', 'data', 'linux_user']
    list_filter = ['owner']

    formfield_overrides = {
        JSONField: {'widget': JSONEditorWidget},
    }


@admin.register(GlobalPolicy)
class GlobalPolicyAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'owner', 'name', 'policy', 'created']
    list_filter = ['owner']
    readonly_fields = ['created']


@admin.register(Distro)
class DistroAdmin(admin.ModelAdmin):
    list_display = ['os_release_codename', 'end_of_life']
    search_fields = ['os_release_codename']
    list_filter = ['end_of_life']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['os_release_codename', 'name', 'package', 'unstable_version', 'other_versions', 'urgency']
    list_filter = ['os_release_codename']
