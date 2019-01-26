from django.contrib import admin
from device_registry.models import Device, DeviceInfo


class DeviceAdmin(admin.ModelAdmin):
    model = Device

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

    ordering = ('-last_ping',)
    readonly_fields = (
        'claim_token',
    )


class DeviceInfoAdmin(admin.ModelAdmin):
    model = DeviceInfo

    list_display = [
        'device',
        'device_manufacturer',
        'device_model',
        'device_architecture',
        'device_operating_system',
        'device_operating_system_version',
    ]


admin.site.register(Device, DeviceAdmin)
admin.site.register(DeviceInfo, DeviceInfoAdmin)
