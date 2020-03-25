import ipaddress

from django import forms

import tagulous.forms

from .models import Device, FirewallState, DeviceInfo, GlobalPolicy


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
                raise forms.ValidationError("You already have a node with such name!")
        return data

    class Meta:
        model = Device
        fields = ['name', 'comment', 'tags']
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Comment', 'class': 'form-control'}),
            'name': forms.TextInput(attrs={'style': 'width:100%'}),
            'tags': tagulous.forms.TagWidget(attrs={'style': 'width:100%', 'maxlength': 36})
        }


class FirewallStateGlobalPolicyForm(forms.ModelForm):
    class Meta:
        model = FirewallState
        fields = ['global_policy']
        widgets = {
            'global_policy': forms.Select(attrs={'class': 'wott-form-control custom-select'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['global_policy'].queryset = self.fields['global_policy'].queryset.filter(
            owner=self.instance.device.owner)


class GlobalPolicyForm(forms.ModelForm):
    class Meta:
        model = GlobalPolicy
        fields = ['name', 'policy', 'ports']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['policy'].widget.attrs['class'] = 'custom-select'

    def clean_ports(self):
        data = self.cleaned_data['ports']
        if data:
            keys = {'address': None, 'protocol': None, 'port': None, 'ip_version': None}.keys()
            unique_rules = set()
            for rule in data:
                # Check keys.
                if rule.keys() != keys:
                    raise forms.ValidationError('Wrong or missing fields.')
                # Check rule uniqueness.
                rule_key_info = (rule['address'], rule['port'], rule['protocol'])
                if rule_key_info in unique_rules:
                    raise forms.ValidationError('"%s:%s/%s" is a duplicating/conflicting rule.' % (
                        rule['address'], rule['port'], rule['protocol']))
                else:
                    unique_rules.add(rule_key_info)
                # Check 'address' element.
                try:
                    address_obj = ipaddress.ip_address(rule['address'])
                except ValueError:
                    raise forms.ValidationError('"%s" is not a correct IP address.' % rule['address'])
                # Check 'protocol' element.
                if rule['protocol'] not in ('tcp', 'udp'):
                    raise forms.ValidationError('"%s" is not a valid protocol value.' % rule['protocol'])
                # Check 'port' element.
                if not type(rule['port']) == int or rule['port'] < 0:
                    raise forms.ValidationError('"%s" is not a valid port value.' % rule['port'])
                # Check 'ip_version' element.
                if not type(rule['ip_version']) == bool:
                    raise forms.ValidationError('"%s" is not a valid IP version field value.' % rule['ip_version'])
                # Check 'address' and 'ip_version' elements' conformance.
                if address_obj.version == 4 and rule['ip_version']:
                    raise forms.ValidationError('"%s" is wrong IP address format for IPv6.' % rule['address'])
                if address_obj.version == 6 and not rule['ip_version']:
                    raise forms.ValidationError('"%s" is wrong IP address format for IPv4.' % rule['address'])
        return data
