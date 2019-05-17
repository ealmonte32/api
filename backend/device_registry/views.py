from django.views.generic import DetailView
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required

from device_registry.forms import ClaimDeviceForm, DeviceCommentsForm, PortsForm, ConnectionsForm
from device_registry.models import Action, Device, get_device_list, average_trust_score, PortScan, FirewallState
from profile_page.forms import ProfileForm
from profile_page.models import Profile


@login_required
def root_view(request):
    return render(request, 'root.html', {
        'avg_trust_score': average_trust_score(request.user),
        'active_inactive': Device.get_active_inactive(request.user),
        'devices': get_device_list(request.user)
    })

@login_required
def profile_view(request):
    user = request.user
    profile, _ = Profile.objects.get_or_create(user=user)
    if request.method == 'POST':
        form = ProfileForm(request.POST)

        if form.is_valid():
            user.email = form.cleaned_data['email']
            user.first_name = form.cleaned_data['first_name']
            user.last_name = form.cleaned_data['last_name']
            profile.company_name = form.cleaned_data['company']
            profile.save()
            user.save()
    return render(request, 'profile.html')


@login_required
def claim_device_view(request):
    # if this is a POST request we need to process the form data
    text = style = None
    if request.method == 'POST':
        form = ClaimDeviceForm(request.POST)

        if form.is_valid():
            get_device = get_object_or_404(
                Device,
                device_id=form.cleaned_data['device_id']
            )
            if get_device.claimed:
                text, style = 'Device has already been claimed.', 'warning'
            elif not get_device.claim_token == form.cleaned_data['claim_token']:
                text, style = 'Invalid claim/device id pair.', 'warning'
            else:
                get_device.owner = request.user
                get_device.save()
                text, style = 'Successfully claimed {}.'.format(form.cleaned_data['device_id']), 'success'

    # GET with claim_token and device_id set will fill the form.
    # Empty GET or any other request will generate empty form.
    if request.method == 'GET' and \
        'claim_token' in request.GET and \
            'device_id' in request.GET:
        form = ClaimDeviceForm(request.GET)
    else:
        form = ClaimDeviceForm()

    return render(request, 'claim_device.html', {
        'form': form,
        'alert_style': style,
        'alert_text': text
    })


class DeviceDetailView(DetailView):
    model = Device
    template_name = 'device_info.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['comment_form'] = DeviceCommentsForm(instance=self.object)
        try:
            ports_form_data = self.object.portscan.ports_form_data()
            context['portscan'] = self.object.portscan
            context['ports_choices'] = bool(ports_form_data[0])
            context['ports_form'] = PortsForm(open_ports_choices=ports_form_data[0],
                                              initial={'open_ports': ports_form_data[1]})
            connections_form_data = self.object.portscan.connections_form_data()
            context['connections_choices'] = bool(connections_form_data[0])
            context['connections_form'] = ConnectionsForm(open_connections_choices=connections_form_data[0],
                                                          initial={'open_connections': connections_form_data[1]})
        except PortScan.DoesNotExist:
            context['portscan'] = None

        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None

        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        portscan = self.object.portscan
        if 'is_comments_form' in request.POST:
            form = DeviceCommentsForm(request.POST, instance=self.object)
            if form.is_valid():
                form.save()
        elif 'is_ports_form' in request.POST:
            ports_form_data = self.object.portscan.ports_form_data()
            form = PortsForm(request.POST, open_ports_choices=ports_form_data[0])
            if form.is_valid():
                out_data = []
                for element in form.cleaned_data['open_ports']:
                    port_record_index = int(element)
                    out_data.append(ports_form_data[2][port_record_index])
                portscan.block_ports = out_data
                portscan.save(update_fields=['block_ports'])
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
        return HttpResponseRedirect(reverse('device-detail', kwargs={'pk': kwargs['pk']}))


@login_required
def actions_view(request):
    actions = []

    # Default username/password used action.
    insecure_password_devices = request.user.devices.filter(deviceinfo__default_password=True)
    if insecure_password_devices.exists():
        text_blocks = []
        for dev in insecure_password_devices:
            device_text_block = '<a href="%s">%s</a>' % (reverse('device-detail', kwargs={'pk': dev.pk}), dev.device_id)
            text_blocks.append(device_text_block)
        full_string = ', '.join(text_blocks)
        action = Action(
            1,
            'Default credentials detected',
            'We found default credentials present on %s. Please consider changing them as soon as possible.' %
            full_string,
            [('Ignore', 'danger'), ('Snooze', 'warning')]
        )
        actions.append(action)

    # Farewall disabled action.
    disabled_firewall_devices = request.user.devices.filter(firewallstate__enabled=False)
    if disabled_firewall_devices.exists():
        text_blocks = []
        for dev in disabled_firewall_devices:
            device_text_block = '<a href="%s">%s</a>' % (reverse('device-detail', kwargs={'pk': dev.pk}), dev.device_id)
            text_blocks.append(device_text_block)
        full_string = ', '.join(text_blocks)
        action = Action(
            2,
            'Disabled firewall detected',
            'We found disabled firewall present on %s. Please consider enabling it.' %
            full_string,
            [('Ignore', 'danger'), ('Snooze', 'warning')]
        )
        actions.append(action)

    return render(request, 'actions.html', {
        'actions': actions
    })
