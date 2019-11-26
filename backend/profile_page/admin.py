from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.db.models import Count


class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'date_joined', 'last_login',
                    'node_count')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(_node_count=Count('devices'))
        return qs

    def node_count(self, obj):
        return obj._node_count

    node_count.admin_order_field = '_node_count'


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
