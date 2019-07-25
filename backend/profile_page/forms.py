from django import forms

from registration.forms import RegistrationFormUniqueEmail

from .models import Profile


class ProfileForm(forms.Form):
    username = forms.CharField(disabled=True)
    payment_plan = forms.CharField(disabled=True)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=150, required=False)
    company = forms.CharField(max_length=128, required=False)


class RegistrationForm(RegistrationFormUniqueEmail):
    """Registration form extended with a new `payment_plan` field."""
    payment_plan = forms.ChoiceField(choices=Profile.PAYMENT_PLAN_CHOICES)
