from django import forms

from .models import Device


class ClaimDeviceForm(forms.Form):
    device_id = forms.CharField()
    claim_token = forms.CharField()


class DeviceAttrsForm(forms.ModelForm):

    def clean_name(self):
        data = self.cleaned_data['name'].strip()
        if data:
            model_class = self.instance.__class__
            owner = self.instance.owner
            if model_class.objects.exclude(pk=self.instance.pk).filter(owner=owner, name__iexact=data):
                raise forms.ValidationError("You already have a device with such name!")
        return data

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


class CredentialsForm(forms.Form):
    name = forms.CharField(max_length=64)
    key = forms.CharField(max_length=64)
    value = forms.CharField(max_length=1024)
