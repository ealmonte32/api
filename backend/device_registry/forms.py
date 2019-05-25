from django import forms

from .models import Device


class ClaimDeviceForm(forms.Form):
    device_id = forms.CharField()
    claim_token = forms.CharField()


class DeviceAttrsForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['name', 'comment']
        widgets = {'comment': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Comment', 'class': 'form-control'}),
                   'name': forms.TextInput(attrs={'style': 'width:100%'})}


class PortsForm(forms.Form):
    open_ports = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'list-unstyled'}))
    is_ports_form = forms.CharField(widget=forms.HiddenInput, initial='true')

    def __init__(self, *args, **kwargs):
        open_ports_choices = kwargs.pop('open_ports_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_ports'].choices = open_ports_choices


class ConnectionsForm(forms.Form):
    open_connections = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'list-unstyled'}))
    is_connections_form = forms.CharField(widget=forms.HiddenInput, initial='true')

    def __init__(self, *args, **kwargs):
        open_connections_choices = kwargs.pop('open_connections_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_connections'].choices = open_connections_choices
