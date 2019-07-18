import uuid
import json

from django.views.generic import DetailView, ListView
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction

from tagulous.forms import TagWidget

from device_registry.forms import ClaimDeviceForm, DeviceAttrsForm, PortsForm, ConnectionsForm, DeviceMetadataForm
from device_registry.models import Action, Device, get_device_list, average_trust_score, PortScan, FirewallState
from device_registry.models import Credential, PairingKey, get_bootstrap_color
from device_registry.serializers import UpdatePairingKeySrializer


@login_required
def root_view(request):
    avg_trust_score = average_trust_score(request.user)
    return render(request, 'root.html', {
        'avg_trust_score': avg_trust_score,
        'avg_trust_score_percent': int(avg_trust_score * 100) if avg_trust_score is not None else None,
        'avg_trust_score_color': get_bootstrap_color(
            int(avg_trust_score * 100)) if avg_trust_score is not None else None,
        'active_inactive': Device.get_active_inactive(request.user),
        'devices': get_device_list(request.user)
    })


@login_required
def claim_device_view(request):
    # if this is a POST request we need to process the form data
    text = style = None
    if request.method == 'POST':
        form = ClaimDeviceForm(request.POST)

        if form.is_valid():
            try:
                get_device = Device.objects.get(
                    device_id=form.cleaned_data['device_id']
                )
                if get_device.claimed:
                    text, style = 'Device has already been claimed.', 'warning'
                elif not get_device.claim_token == form.cleaned_data['claim_token']:
                    text, style = 'Invalid claim/device id pair.', 'warning'
                else:
                    get_device.owner = request.user
                    get_device.claim_token = ""
                    get_device.save(update_fields=['owner', 'claim_token'])
                    text, style = f'You\'ve successfully claimed {get_device.get_name()}. '\
                                  f'Learn more about the security state of the device by clicking&nbsp;'\
                                  f'<a class="claim-link" href="{reverse("device-detail-security", kwargs={"pk": get_device.pk})}">' \
                                  f'here</a>.', \
                                  'success'
            except Device.DoesNotExist:
                text, style = 'Invalid claim/device id pair.', 'warning'

    # GET with claim_token and device_id set will fill the form.
    # Empty GET or any other request will generate empty form.
    if request.method == 'GET' and \
        'claim_token' in request.GET and \
            'device_id' in request.GET:
        try:
            Device.objects.get(
                device_id=request.GET['device_id']
            )
            form = ClaimDeviceForm(request.GET)
        except Device.DoesNotExist:
            text, style = 'Invalid claim/device id pair.', 'warning'
            form = ClaimDeviceForm()
    else:
        form = ClaimDeviceForm()

    return render(request, 'claim_device.html', {
        'form': form,
        'alert_style': style,
        'alert_text': text
    })


class DeviceDetailView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_overview.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        if 'form' not in context:
            context['form'] = DeviceAttrsForm(instance=self.object)
            context['form_media'] = context['form'].media
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = DeviceAttrsForm(request.POST, instance=self.object)
        if form.is_valid():
            if 'revoke_button' in form.data:
                self.object.owner = None
                self.object.claim_token = uuid.uuid4()
                self.object.save(update_fields=['owner', 'claim_token'])
                return HttpResponseRedirect(reverse('root'))
            else:
                form.save()
                return HttpResponseRedirect(reverse('device-detail', kwargs={'pk': kwargs['pk']}))
        return self.render_to_response(self.get_context_data(form=form))


class DeviceDetailSoftwareView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_software.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        return context


class DeviceDetailSecurityView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_security.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        else:
            ports_form_data = self.object.portscan.ports_form_data()
            context['ports_choices'] = bool(ports_form_data[0])
            context['ports_form'] = PortsForm(ports_choices=ports_form_data[0],
                                              initial={'open_ports': ports_form_data[1],
                                                       'policy': self.object.firewallstate.policy})
            connections_form_data = self.object.portscan.connections_form_data()
            context['connections_choices'] = bool(connections_form_data[0])
            context['connections_form'] = ConnectionsForm(open_connections_choices=connections_form_data[0],
                                                          initial={'open_connections': connections_form_data[1]})
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        portscan = self.object.portscan
        firewallstate = self.object.firewallstate
        if 'is_ports_form' in request.POST:
            ports_form_data = self.object.portscan.ports_form_data()
            form = PortsForm(request.POST, ports_choices=ports_form_data[0])
            if form.is_valid():
                out_data = []
                for element in form.cleaned_data['open_ports']:
                    port_record_index = int(element)
                    out_data.append(ports_form_data[2][port_record_index])
                portscan.block_ports = out_data
                firewallstate.policy = form.cleaned_data['policy']
                with transaction.atomic():
                    portscan.save(update_fields=['block_ports'])
                    firewallstate.save(update_fields=['policy'])

        elif 'is_connections_form' in request.POST:
            connections_form_data = self.object.portscan.connections_form_data()
            form = ConnectionsForm(request.POST, open_connections_choices=connections_form_data[0])
            if form.is_valid():
                out_data = []
                for element in form.cleaned_data['open_connections']:
                    connection_record_index = int(element)
                    out_data.append(connections_form_data[2][connection_record_index])
                portscan.block_networks = out_data
                portscan.save(update_fields=['block_networks'])
        return HttpResponseRedirect(reverse('device-detail-security', kwargs={'pk': kwargs['pk']}))


class DeviceDetailNetworkView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_network.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        return context


class DeviceDetailHardwareView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_hardware.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        return context


class DeviceDetailMetadataView(LoginRequiredMixin, DetailView):
    model = Device
    template_name = 'device_info_metadata.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if hasattr(self.object, 'portscan'):
            context['portscan'] = self.object.portscan
        else:
            context['portscan'] = None
        if hasattr(self.object, 'firewallstate'):
            context['firewall'] = self.object.firewallstate
        else:
            context['firewall'] = None
        if 'dev_md' not in context:
            device_metadata = self.object.deviceinfo.device_metadata
            context['dev_md'] = []
            for key, value in device_metadata.items():
                if isinstance(value, str):
                    context['dev_md'].append([key, value])
                else:
                    context['dev_md'].append([key, json.dumps(value)])
        if 'form' not in context:
            context['form'] = DeviceMetadataForm(instance=self.object.deviceinfo)
            context['form_media'] = context['form'].media
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = DeviceMetadataForm(request.POST, instance=self.object.deviceinfo)
        if form.is_valid() and "device_metadata" in form.cleaned_data:
            self.object.deviceinfo.device_metadata = form.cleaned_data["device_metadata"]
            self.object.deviceinfo.save(update_fields=['device_metadata'])
            return HttpResponseRedirect(reverse('device-detail-metadata', kwargs={'pk': kwargs['pk']}))
        return self.render_to_response(self.get_context_data(form=form))


class CredentialsView(LoginRequiredMixin, ListView):
    model = Credential
    template_name = 'credentials.html'
    pi_credentials_path = '/opt/wott/credentials'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super(CredentialsView, self).get_context_data(**kwargs)
        context['pi_credentials_path'] = self.pi_credentials_path
        context['form_media'] = TagWidget().media
        return context


class PairingKeysView(LoginRequiredMixin, ListView):
    model = PairingKey
    template_name = 'pairing_keys.html'
    context_object_name = 'pairing_key_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get(self, request, *args, **kwargs):
        if 'pk' in self.request.GET:
            return self._save_file_response(
                PairingKey.objects.get(key=self.request.GET['pk'], owner=self.request.user)
            )
        else:
            return super(PairingKeysView, self).get(request, *args, **kwargs)

    def _save_file_response(self, key_object):

        data = "[DEFAULT]\n\nenroll_token = {}".format(key_object.key.hex)
        response = HttpResponse(data, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename = "config.ini"'
        return response


@login_required
def actions_view(request, device_pk=None):
    if device_pk is not None:
        device = get_object_or_404(Device, pk=device_pk)
        device_name = device.get_name()
    else:
        device_name = None
    actions = []

    # Default username/password used action.
    insecure_password_devices = request.user.devices.filter(deviceinfo__default_password=True)
    if device_pk is not None:
        insecure_password_devices = insecure_password_devices.filter(pk=device_pk)
    if insecure_password_devices.exists():
        text_blocks = []
        for dev in insecure_password_devices:
            device_text_block = f'<a href="{ reverse("device-detail", kwargs={"pk": dev.pk}) }">{ dev.get_name() }</a>'
            text_blocks.append(device_text_block)
        full_string = ', '.join(text_blocks)
        action = Action(
            1,
            'Default credentials detected',
            'We found default credentials present on %s. Please consider changing them as soon as possible.' %
            ('this device' if device_name else full_string), []
        )
        actions.append(action)

    # Firewall disabled action.
    disabled_firewall_devices = request.user.devices.exclude(firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK)
    if device_pk is not None:
        disabled_firewall_devices = disabled_firewall_devices.filter(pk=device_pk)
    if disabled_firewall_devices.exists():
        text_blocks = []
        for dev in disabled_firewall_devices:
            device_text_block = f'<a href="{ reverse("device-detail", kwargs={"pk": dev.pk}) }">{ dev.get_name() }</a>'
            text_blocks.append(device_text_block)
        full_string = ', '.join(text_blocks)
        action = Action(
            2,
            'Permissive firewall policy detected',
            'We found permissive firewall policy present on %s. Please consider change it to more restrictive one.' %
            ('this device' if device_name else full_string), []
        )
        actions.append(action)

    # Telnet server running action.
    qs1 = request.user.devices.filter(
        firewallstate__policy=FirewallState.POLICY_ENABLED_ALLOW, portscan__scan_info__contains=[{'port': 23}]).exclude(
        portscan__block_ports__contains=[[23]])
    qs2 = request.user.devices.filter(
        firewallstate__policy=FirewallState.POLICY_ENABLED_BLOCK, portscan__scan_info__contains=[{'port': 23}],
        portscan__block_ports__contains=[[23]])
    enabled_telnet_devices = qs1 | qs2
    if device_pk is not None:
        enabled_telnet_devices = enabled_telnet_devices.filter(pk=device_pk)
    if enabled_telnet_devices.exists():
        text_blocks = []
        for dev in enabled_telnet_devices:
            device_text_block = f'<a href="{reverse("device-detail", kwargs={"pk": dev.pk})}">{dev.get_name()}</a>'
            text_blocks.append(device_text_block)
        full_string = ', '.join(text_blocks)
        action = Action(
            3,
            'Enabled Telnet server detected',
            'We found enabled Telnet server present on %s. Please consider disabling it.' %
            ('this device' if device_name else full_string), []
        )
        actions.append(action)

    return render(request, 'actions.html', {
        'actions': actions,
        'device_name': device_name,
        'device_pk': device_pk
    })
