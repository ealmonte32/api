from django.views.generic import DetailView
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required

from device_registry.forms import ClaimDeviceForm, DeviceCommentsForm, PortsForm, ConnectionsForm
from device_registry.models import Action, Device, get_device_list, get_avg_trust_score
from profile_page.forms import ProfileForm
from profile_page.models import Profile


@login_required
def root_view(request):
    return render(request, 'root.html', {
        'avg_trust_score': get_avg_trust_score(request.user),
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
    if request.method == 'POST':
        form = ClaimDeviceForm(request.POST)

        if form.is_valid():
            get_device = get_object_or_404(
                Device,
                device_id=form.cleaned_data['device_id']
            )
            if get_device.claimed():
                return HttpResponse('Device has already been claimed.')

            if not get_device.claim_token == form.cleaned_data['claim_token']:
                return HttpResponse('Invalid claim/device id pair.')

            get_device.owner = request.user
            get_device.save()
            return HttpResponse('Successfully claimed {}.'.format(form.cleaned_data['device_id']))

    else:
        # GET with claim_token and device_id set will fill the form.
        # Empty GET or any other request will generate empty form.
        if request.method == 'GET' and \
            'claim_token' in request.GET and \
                'device_id' in request.GET:
            form = ClaimDeviceForm(request.GET)
        else:
            form = ClaimDeviceForm()

    return render(request, 'claim_device.html', {'form': form})


class DeviceDetailView(DetailView):
    model = Device
    template_name = 'device_info.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['comment_form'] = DeviceCommentsForm(instance=self.object)
        ports_form_data = self.object.portscan.ports_form_data()
        context['ports_choices'] = bool(ports_form_data[0])
        context['ports_form'] = PortsForm(open_ports_choices=ports_form_data[0],
                                          initial={'open_ports': ports_form_data[1]})
        connections_form_data = self.object.portscan.connections_form_data()
        context['connections_choices'] = bool(connections_form_data[0])
        context['connections_form'] = ConnectionsForm(open_connections_choices=connections_form_data[0],
                                                      initial={'open_connections': connections_form_data[1]})
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


def actions_view(request):
    actions = [
        Action(
            1,
            'Abnormal network connection',
            'foobar.d.wott.local attempted to connect to a.b.c.d which is a known end-point for the Marai botnet. What '
            'do you want to do?',
            [('Ignore', 'warning'), ('Block', 'success')]
        ),
        Action(
            2,
            'Suspicious process detected',
            'foobar2.d.woot.local executed the command "nc" which is often used by attackers (but can also be used '
            'for legitimate purposes). Is this expected?',
            [('Expected', 'info'), ('Snooze', 'warning')]
        ),
        Action(
            3,
            'Insecure port open',
            'foobar0.d.woot.local has port 22/tcp (telnet) open. This is usually a security risk.',
            [('Ignore', 'danger'), ('Block', 'success')]
        )
    ]

    return render(request, 'actions.html', {
        'actions': actions
    })
