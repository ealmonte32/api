from django import forms


class ProfileForm(forms.Form):
    username = forms.CharField(disabled=True)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=150, required=False)
    company = forms.CharField(max_length=128, required=False)
