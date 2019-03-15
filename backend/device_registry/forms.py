from django import forms


class ClaimDeviceForm(forms.Form):
    device_id = forms.CharField()
    claim_token = forms.CharField()


class DeviceCommentsForm(forms.Form):
    comment = forms.CharField()
