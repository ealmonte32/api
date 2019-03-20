from django import forms


class ProfileForm(forms.Form):
    username = forms.CharField()
    email = forms.CharField()
    first_name = forms.CharField(required=False)
    last_name = forms.CharField(required=False)
    company = forms.CharField(required=False)
