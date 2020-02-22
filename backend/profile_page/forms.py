from django import forms
from django.contrib.auth.forms import AuthenticationForm as DjangoAuthenticationForm
from django.contrib.auth.forms import PasswordChangeForm as DjangoPasswordChangeForm
from django.conf import settings

from registration.forms import RegistrationFormUniqueEmail, User

from phonenumber_field.formfields import PhoneNumberField

from .models import Profile


class ProfilePaymentPlanForm(forms.ModelForm):
    subscription_status = forms.CharField(required=False, label='Subscription status', disabled=True,
                                          widget=forms.TextInput(attrs={'placeholder': ''}))
    current_period_ends = forms.DateTimeField(required=False, label='Current billing period ends', disabled=True,
                                              widget=forms.DateTimeInput(attrs={'placeholder': ''}),
                                              input_formats=['%Y-%m-%d %H:%M:%S %Z'])
    nodes_number = forms.IntegerField(required=False, min_value=1, widget=forms.NumberInput(attrs={'placeholder': ''}),
                                      label='Paid nodes (In addition to the first free node)', disabled=True)
    nodes_number_hidden = forms.IntegerField(min_value=1, widget=forms.HiddenInput())
    payment_method_id = forms.CharField(required=False, max_length=255, widget=forms.HiddenInput())
    total_sum = forms.IntegerField(required=False, disabled=True, label="Monthly charge",
                                   widget=forms.NumberInput(attrs={'placeholder': ''}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['payment_plan'].choices = Profile.PAYMENT_PLAN_CHOICES[:2]
        for field_name in self.fields:
            self.fields[field_name].widget.attrs['placeholder'] = ''

    class Meta:
        model = Profile
        fields = ['payment_plan']


class PasswordChangeForm(DjangoPasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in self.fields:
            self.fields[field_name].widget.attrs['placeholder'] = ''


class ProfileForm(forms.Form):
    username = forms.CharField(disabled=True)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=150, required=False)
    company = forms.CharField(max_length=128, required=False)
    phone = PhoneNumberField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in self.fields:
            self.fields[field_name].widget.attrs['placeholder'] = ''


class RegistrationForm(RegistrationFormUniqueEmail):
    """Registration form extended with few optional extra fields
    and with the `username` field disabled.
    """
    first_name = forms.CharField(max_length=30, required=False, label='First name')
    last_name = forms.CharField(max_length=150, required=False, label='Last name')
    company = forms.CharField(max_length=128, required=False, label='Company')
    phone = PhoneNumberField(required=False, label='Phone')
    payment_plan = forms.ChoiceField(choices=Profile.PAYMENT_PLAN_CHOICES[:2])
    nodes_number = forms.IntegerField(min_value=1, initial=1,
                                      label='Nodes number (In addition to the first free node)')
    payment_method_id = forms.CharField(max_length=255, widget=forms.HiddenInput(), required=False)
    total_sum = forms.IntegerField(required=False, initial=settings.WOTT_PRICE_PER_NODE, disabled=True,
                                   label="You'll be charged (USD, after the 30 days free trial period end)",
                                   widget=forms.NumberInput(attrs={'placeholder': ''}))
    # the function bellow is duplicated with line 92, @Roman please check if we can remove it
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     for field_name in self.fields:
    #         self.fields[field_name].widget.attrs['placeholder'] = ''

    def clean(self):
        self._validate_unique = True
        # Validate `payment_method_id` field's value if chosen plan is not free.
        if int(self.cleaned_data['payment_plan']) != Profile.PAYMENT_PLAN_FREE:
            payment_method_id = self.cleaned_data.get('payment_method_id', '').strip()
            if not payment_method_id or not payment_method_id.startswith('pm_'):
                raise forms.ValidationError('Wrong card info provided.')
        return self.cleaned_data

    class Meta:
        model = User
        fields = ["email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in ['email', 'password1', 'password2']:
            self.fields[name].widget.attrs['placeholder'] = self.fields[name].label
        for name in ['first_name', 'last_name', 'company', 'phone']:
            self.fields[name].widget.attrs['placeholder'] = self.fields[name].label + ' (optional)'
        self.fields['payment_plan'].widget.attrs['class'] = 'custom-select'


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
