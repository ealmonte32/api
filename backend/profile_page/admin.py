from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User


class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'date_joined', 'last_login',
                    'nodes_count')

    def nodes_count(self, obj):
        return obj.devices.count()


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
