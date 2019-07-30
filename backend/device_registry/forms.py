from django import forms

import tagulous.forms

from .models import Device, FirewallState, DeviceInfo


class ClaimDeviceForm(forms.Form):
    device_id = forms.CharField()
    claim_token = forms.CharField()


class DeviceMetadataForm(forms.ModelForm):
    class Meta:
        model = DeviceInfo
        fields = ['device_metadata']


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
        fields = ['name', 'comment', 'tags']
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Comment', 'class': 'form-control'}),
            'name': forms.TextInput(attrs={'style': 'width:100%'}),
            'tags': tagulous.forms.TagWidget(attrs={'style': 'width:100%', 'maxlength': 36})
        }


class PortsForm(forms.Form):
    policy = forms.ChoiceField(choices=FirewallState.POLICY_CHOICES,
                               widget=forms.Select(attrs={'class': 'form-control'}))
    open_ports = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'list-unstyled'}))
    is_ports_form = forms.CharField(widget=forms.HiddenInput, initial='true')

    def __init__(self, *args, **kwargs):
        ports_choices = kwargs.pop('ports_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_ports'].choices = ports_choices


class ConnectionsForm(forms.Form):
    open_connections = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'list-unstyled'}))
    is_connections_form = forms.CharField(widget=forms.HiddenInput, initial='true')

    def __init__(self, *args, **kwargs):
        open_connections_choices = kwargs.pop('open_connections_choices')
        super().__init__(*args, **kwargs)
        self.fields['open_connections'].choices = open_connections_choices


class GlobalPolicyForm(forms.ModelForm):
    class Meta:
        model = FirewallState
        fields = ['global_policy']
        widgets = {
            'global_policy': forms.Select(attrs={'class': 'form-control'}),
        }
