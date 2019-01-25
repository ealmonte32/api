from django.contrib import admin
from device_registry.models import Device


class DeviceAdmin(admin.ModelAdmin):
    model = Device

    list_display = [
        'device_id',
        'created',
        'last_ping',
        'owner',
    ]

    ordering = ('-last_ping',)
    readonly_fields = (
        'claim_token',
    )


admin.site.register(Device, DeviceAdmin)
