from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.contrib.auth.forms import ReadOnlyPasswordHashField, UsernameField
from django.db.models import Count
from django import forms
from django.utils.translation import gettext_lazy as _

import djstripe.models

from .models import Profile


class UserChangeForm(forms.ModelForm):
    """
    The standard `UserChangeForm` form overwritten in order to add the new
     (`is_unlimited`) custom field support.
    """
    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_(
            "Raw passwords are not stored, so there is no way to see this "
            "user's password, but you can change the password using "
            "<a href=\"{}\">this form</a>."
        ),
    )
    is_unlimited = forms.BooleanField(required=False, initial=False)

    class Meta:
        model = User
        fields = '__all__'
        field_classes = {'username': UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        password = self.fields.get('password')
        if password:
            password.help_text = password.help_text.format('../password/')
        user_permissions = self.fields.get('user_permissions')
        if user_permissions:
            user_permissions.queryset = user_permissions.queryset.select_related('content_type')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial.get('password')

    def save(self, commit=True):
        """
        Overwritten in order to save the `is_unlimited` custom field's value.
        """
        is_unlimited = self.cleaned_data.get('is_unlimited')
        if is_unlimited is not None:
            profile, created = Profile.objects.get_or_create(user=self.instance)
            profile.unlimited_customer = is_unlimited
            profile.save(update_fields=['unlimited_customer'])
        return super().save(commit)


class CustomUserAdmin(UserAdmin):
    form = UserChangeForm
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'is_unlimited',
                    'date_joined', 'last_login', 'node_count')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'is_unlimited', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(_node_count=Count('devices'))
        return qs

    def node_count(self, obj):
        return obj._node_count

    node_count.admin_order_field = '_node_count'

    def is_unlimited(self, obj):
        if hasattr(obj, 'profile'):
            return obj.profile.unlimited_customer
        else:
            return False

    is_unlimited.boolean = True
    is_unlimited.admin_order_field = '-profile__unlimited_customer'

    def get_form(self, request, obj=None, **kwargs):
        """
        The standard `get_form` method overwritten in order to set proper initial value
         of the `is_unlimited` custom field.
        """
        form = super().get_form(request, obj, **kwargs)
        if kwargs.get('change') and obj and hasattr(obj, 'profile'):
            form.base_fields['is_unlimited'].initial = obj.profile.unlimited_customer
        return form


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

# Disable useless djstripe admin subsections.
admin.site.unregister(djstripe.models.Account)
admin.site.unregister(djstripe.models.Charge)
admin.site.unregister(djstripe.models.Coupon)
admin.site.unregister(djstripe.models.Dispute)
admin.site.unregister(djstripe.models.Event)
admin.site.unregister(djstripe.models.FileUpload)
admin.site.unregister(djstripe.models.IdempotencyKey)
admin.site.unregister(djstripe.models.PaymentIntent)
admin.site.unregister(djstripe.models.Refund)
admin.site.unregister(djstripe.models.SetupIntent)
admin.site.unregister(djstripe.models.Source)
admin.site.unregister(djstripe.models.WebhookEventTrigger)
