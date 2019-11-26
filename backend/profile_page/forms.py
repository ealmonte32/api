from django import forms
from django.contrib.auth.forms import AuthenticationForm as DjangoAuthenticationForm

from registration.forms import RegistrationFormUniqueEmail, User

from phonenumber_field.formfields import PhoneNumberField

from .models import Profile


class ProfileForm(forms.Form):
    username = forms.CharField(disabled=True)
    payment_plan = forms.CharField(disabled=True)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=150, required=False)
    company = forms.CharField(max_length=128, required=False)
    phone = PhoneNumberField(required=False)


class RegistrationForm(RegistrationFormUniqueEmail):
    """Registration form extended with few optional extra fields
    and with the `username` field disabled.
    """
    first_name = forms.CharField(max_length=30, required=False, label='First name (optional)')
    last_name = forms.CharField(max_length=150, required=False, label='Last name (optional)')
    company = forms.CharField(max_length=128, required=False, label='Company (optional)')
    phone = PhoneNumberField(required=False, label='Phone (optional)')
    payment_plan = forms.ChoiceField(choices=Profile.PAYMENT_PLAN_CHOICES)

    class Meta:
        model = User
        fields = ["email"]


class AuthenticationForm(DjangoAuthenticationForm):
    """
    A form class based on the standard Django's AuthenticationForm with rewritten
    error message in order to make the `username` form field look like e-mail.
    """
    error_messages = {
        'invalid_login': "Please enter a correct e-mail and password. Note that both fields may be case-sensitive."
        ,
        'inactive': "This account is inactive.",
    }

    def clean_username(self):
        return self.cleaned_data['username'].lower()


class GithubForm(forms.Form):
    repo = forms.ChoiceField(required=False)

    def __init__(self, *args, **kwargs):
        repo_choices = kwargs.pop('repo_choices')
        super().__init__(*args, **kwargs)
        self.fields['repo'].choices = [(None, '')] + repo_choices
