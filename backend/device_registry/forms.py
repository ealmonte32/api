from django import forms

from .models import Device, PortScan


class ClaimDeviceForm(forms.Form):
    device_id = forms.CharField()
    claim_token = forms.CharField()


class DeviceCommentsForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['comment']
        widgets = {'comment': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Comment'})}


class PortsForm(forms.Form):
    open_ports = forms.MultipleChoiceField(required=False, widget=forms.CheckboxSelectMultiple)

    def __init__(self, *args, **kwargs):
        open_ports_choices = kwargs.pop('open_ports_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_ports'].choices = open_ports_choices


class NetworksForm(forms.Form):
    open_connections = forms.MultipleChoiceField(required=False, widget=forms.CheckboxSelectMultiple)

    def __init__(self, *args, **kwargs):
        open_connections_choices = kwargs.pop('open_connections_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_connections'].choices = open_connections_choices
