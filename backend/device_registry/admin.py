from django.contrib import admin
from django_json_widget.widgets import JSONEditorWidget
from jsonfield_compat.fields import JSONField
from device_registry.models import Device, DeviceInfo, PortScan, FirewallState


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = [
        'device_id',
        'created',
        'last_ping',
        'owner',
        'claimed',
    ]

    list_filter = (
        'last_ping',
    )

    ordering = ('last_ping',)
    readonly_fields = (
        'claim_token',
    )


@admin.register(DeviceInfo)
class DeviceInfoAdmin(admin.ModelAdmin):
    list_display = [
        'device',
        'device_manufacturer',
        'device_model',
        'device_architecture',
        'device_operating_system',
        'device_operating_system_version',
    ]


@admin.register(PortScan)
class PortscanAdmin(admin.ModelAdmin):
    list_display = [
        'device',
        'scan_date',
        'scan_info'
    ]

    formfield_overrides = {
        JSONField: {'widget': JSONEditorWidget},
    }

    ordering = ('scan_date',)


@admin.register(FirewallState)
class FirewallStateAdmin(admin.ModelAdmin):
    list_display = [
        'device',
        'scan_date',
        'enabled',
    ]

    ordering = ('scan_date',)
