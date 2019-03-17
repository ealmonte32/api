from django import forms


class ProfileForm(forms.Form):
    username = forms.CharField()
    email = forms.CharField()
