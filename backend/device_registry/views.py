import json
import uuid
from collections import defaultdict

from django.views.generic import DetailView, ListView, TemplateView, View, UpdateView, CreateView, DeleteView
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Q

from profile_page.mixins import LoginTrackMixin
from .forms import ClaimDeviceForm, DeviceAttrsForm, PortsForm, ConnectionsForm, DeviceMetadataForm
from .forms import FirewallStateGlobalPolicyForm, GlobalPolicyForm
from .models import Device, average_trust_score, PortScan, FirewallState, get_bootstrap_color, PairingKey, \
    RecommendedAction
from .models import GlobalPolicy
from .api_views import DeviceListFilterMixin
from .recommended_actions import ActionMeta, FirewallDisabledAction, Action, Severity


class RootView(LoginRequiredMixin, LoginTrackMixin, DeviceListFilterMixin, ListView):
    model = Device
    template_name = 'root.html'
    context_object_name = 'mirai_devices'  # device list moved to ajax, so only mirai detected devices still here
    filter_dict = None

    def get_queryset(self):
        queryset = super().get_queryset()
        common_query = Q(owner=self.request.user, deviceinfo__detected_mirai=True)
        query = self.get_filter_q(set_filter_dict=True)
        return queryset.filter(common_query & query).distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        avg_trust_score = average_trust_score(self.request.user)
        context.update({
            'avg_trust_score': avg_trust_score,
            'avg_trust_score_percent': int(avg_trust_score * 100) if avg_trust_score is not None else None,
            'avg_trust_score_color': get_bootstrap_color(
                int(avg_trust_score * 100)) if avg_trust_score is not None else None,
            'active_inactive': Device.get_active_inactive(self.request.user),
            'column_names': [
                'Node Name',
                'Hostname',
                'Last Ping',
                'Trust Score',
                'Recommended Actions'
            ],
            'filter_params': [(field_name, field_desc[1], field_desc[2]) for field_name, field_desc in
                              self.FILTER_FIELDS.items()],

            # TODO: convert this into a list of dicts for multiple filters
            'filter': self.filter_dict,
        })
        return context


class GlobalPoliciesListView(LoginRequiredMixin, LoginTrackMixin, ListView):
    model = GlobalPolicy
    template_name = 'policies.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)


class ConvertPortsInfoMixin:
    def dicts_to_lists(self, ports):
        if ports:
            return [[d[k] for k in ('address', 'protocol', 'port', 'ip_version')] for d in ports]
        else:
            return []

    def lists_to_dicts(self, ports):
        return [{'address': d[0], 'protocol': d[1], 'port': d[2], 'ip_version': d[3]} for d in ports]


class GlobalPolicyCreateView(LoginRequiredMixin, LoginTrackMixin, CreateView, ConvertPortsInfoMixin):
    model = GlobalPolicy
    form_class = GlobalPolicyForm
    template_name = 'create_policy.html'
    success_url = reverse_lazy('global_policies')

    def form_valid(self, form):
        """
        Standard method overwritten in order to:
         - assign a proper owner
         - modify ports info to make it conform to the PortScan.block_ports field format
        """
        # Check name uniqueness.
        if GlobalPolicy.objects.filter(owner=self.request.user, name=form.cleaned_data['name']).exists():
            form.add_error('name', 'Global policy with this name already exists.')
            return super().form_invalid(form)

        self.object = form.save(commit=False)
        self.object.owner = self.request.user
        self.object.ports = self.dicts_to_lists(form.cleaned_data['ports'])
        self.object.save()
        return HttpResponseRedirect(self.get_success_url())

    def get(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            device = get_object_or_404(Device, owner=self.request.user, pk=kwargs['pk'])
            portscan_object, _ = PortScan.objects.get_or_create(device=device)
            firewallstate_object, _ = FirewallState.objects.get_or_create(device=device)
            if firewallstate_object.global_policy:
                return HttpResponseForbidden()
            # TODO: pass networks when we enable this field support.
            self.initial = {'policy': firewallstate_object.policy,
                            'ports': self.lists_to_dicts(portscan_object.block_ports)}
        return super().get(request, *args, **kwargs)


class GlobalPolicyEditView(LoginRequiredMixin, LoginTrackMixin, UpdateView, ConvertPortsInfoMixin):
    model = GlobalPolicy
    form_class = GlobalPolicyForm
    template_name = 'edit_policy.html'
    success_url = reverse_lazy('global_policies')

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def form_valid(self, form):
        """
        Standard method overwritten in order to:
         - modify ports info to make it conform to the PortScan.block_ports field format
        """
        # Check name uniqueness.
        if GlobalPolicy.objects.filter(owner=self.request.user, name=form.cleaned_data['name']).exclude(
                pk=form.instance.pk).exists():
            form.add_error('name', 'Global policy with this name already exists.')
            return super().form_invalid(form)

        self.object = form.save(commit=False)
        self.object.ports = self.dicts_to_lists(form.cleaned_data['ports'])
        self.object.save()
        return HttpResponseRedirect(self.get_success_url())

    def get(self, request, *args, **kwargs):
        """
        Standard method overwritten in order to:
         - modify ports info to format to the format expected by the frontend
        """
        self.object = self.get_object()
        self.object.ports = self.lists_to_dicts(self.object.ports)
        return self.render_to_response(self.get_context_data())


class GlobalPolicyDeleteView(LoginRequiredMixin, LoginTrackMixin, DeleteView):
    """
    Global policy delete view.

    The `get_queryset` method rewritten in order to limit access to other users' policies.
    """
    model = GlobalPolicy
    success_url = reverse_lazy('global_policies')

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)


@login_required
def claim_device_view(request):
    # if this is a POST request we need to process the form data
    text = style = None
    if request.method == 'POST':
        form = ClaimDeviceForm(request.POST)

        if form.is_valid():
            try:
                device = Device.objects.get(
                    device_id=form.cleaned_data['device_id']
                )
            except Device.DoesNotExist:
                text, style = 'Invalid claim/node id pair.', 'warning'
            else:
                if device.claimed:
                    text, style = 'Device has already been claimed.', 'warning'
                elif not device.claim_token == form.cleaned_data['claim_token']:
                    text, style = 'Invalid claim/node id pair.', 'warning'
                else:
                    device.owner = request.user
                    device.claim_token = ""
                    device.save(update_fields=['owner', 'claim_token'])
                    text, style = \
                        f'''You've successfully claimed {device.get_name()}.
                          Learn more about the security state of the device by clicking&nbsp;
                          <a class="claim-link" href="{reverse("device-detail-security", kwargs={"pk": device.pk})}">
                          here</a>.''', 'success'
                    device.owner.profile.track_first_device()

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
            text, style = 'Invalid claim/node id pair.', 'warning'
            form = ClaimDeviceForm()
    else:
        form = ClaimDeviceForm()

    return render(request, 'claim_device.html', {
        'form': form,
        'alert_style': style,
        'alert_text': text
    })


class DeviceDetailView(LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailSoftwareView(LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailSecurityView(LoginRequiredMixin, LoginTrackMixin, DetailView):
    model = Device
    template_name = 'device_info_security.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        has_global_policy = False
        try:
            context['firewall'] = self.object.firewallstate
        except FirewallState.DoesNotExist:
            context['firewall'] = None
        else:
            context['global_policy_form'] = FirewallStateGlobalPolicyForm(instance=self.object.firewallstate)
            has_global_policy = bool(self.object.firewallstate.global_policy)
            context['has_global_policy'] = has_global_policy
        try:
            context['portscan'] = self.object.portscan
        except PortScan.DoesNotExist:
            context['portscan'] = None
        else:
            if not has_global_policy:
                ports_form_data = self.object.portscan.ports_form_data()
                context['ports_choices'] = bool(ports_form_data[0])
                context['choices_extra_data'] = ports_form_data[3]
                context['ports_form'] = PortsForm(ports_choices=ports_form_data[0],
                                                  initial={'open_ports': ports_form_data[1],
                                                           'policy': self.object.firewallstate.policy})
                connections_form_data = self.object.portscan.connections_form_data()
                context['connections_choices'] = bool(connections_form_data[0])
                context['connections_form'] = ConnectionsForm(open_connections_choices=connections_form_data[0],
                                                              initial={'open_connections': connections_form_data[1]})
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        portscan = self.object.portscan
        firewallstate = self.object.firewallstate

        if 'global_policy' in request.POST:
            form = FirewallStateGlobalPolicyForm(request.POST, instance=firewallstate)
            if form.is_valid():
                firewallstate.global_policy = form.cleaned_data["global_policy"]
                firewallstate.save(update_fields=['global_policy'])

        elif 'is_ports_form' in request.POST:
            if firewallstate and firewallstate.global_policy:
                return HttpResponseForbidden()
            ports_form_data = self.object.portscan.ports_form_data()
            form = PortsForm(request.POST, ports_choices=ports_form_data[0])
            if form.is_valid():
                out_data = []
                for element in form.cleaned_data['open_ports']:
                    port_record_index = int(element)
                    out_data.append(ports_form_data[2][port_record_index])
                portscan.block_ports = out_data
                firewallstate.policy = form.cleaned_data['policy']
                self.object.generate_recommended_actions(classes=[FirewallDisabledAction])
                with transaction.atomic():
                    portscan.save(update_fields=['block_ports'])
                    firewallstate.save(update_fields=['policy'])
                    self.object.update_trust_score = True
                    self.object.save(update_fields=['update_trust_score'])

        elif 'is_connections_form' in request.POST:
            if firewallstate and firewallstate.global_policy:
                return HttpResponseForbidden()
            connections_form_data = self.object.portscan.connections_form_data()
            form = ConnectionsForm(request.POST, open_connections_choices=connections_form_data[0])
            if form.is_valid():
                out_data = []
                for element in form.cleaned_data['open_connections']:
                    connection_record_index = int(element)
                    out_data.append(connections_form_data[2][connection_record_index])
                portscan.block_networks = out_data
                portscan.save(update_fields=['block_networks'])

        self.object.generate_recommended_actions(classes=[FirewallDisabledAction])
        return HttpResponseRedirect(reverse('device-detail-security', kwargs={'pk': kwargs['pk']}))


class DeviceDetailNetworkView(LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailHardwareView(LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailMetadataView(LoginRequiredMixin, LoginTrackMixin, DetailView):
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
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = DeviceMetadataForm(request.POST, instance=self.object.deviceinfo)
        if form.is_valid() and "device_metadata" in form.cleaned_data:
            self.object.deviceinfo.device_metadata = form.cleaned_data["device_metadata"]
            self.object.deviceinfo.save(update_fields=['device_metadata'])
            return HttpResponseRedirect(reverse('device-detail-metadata', kwargs={'pk': kwargs['pk']}))
        return self.render_to_response(self.get_context_data(form=form))


class CredentialsView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'credentials.html'

    def get_context_data(self, **kwargs):
        context = super(CredentialsView, self).get_context_data(**kwargs)
        context['pi_credentials_path'] = '/opt/wott/credentials'
        return context


class PairingKeysView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'pairing_keys.html'


class PairingKeySaveFileView(LoginRequiredMixin, LoginTrackMixin, View):

    def get(self, request, *args, **kwargs):
        if 'pk' in request.GET:
            try:
                key = PairingKey.objects.get(key=request.GET['pk'], owner=request.user)
                return self._save_file_response(key)
            except PairingKey.DoesNotExist:
                return HttpResponseBadRequest('Pairing-key not found')
        else:
            return HttpResponseRedirect(reverse('pairing-keys'))

    def _save_file_response(self, key_object):
        data = "[DEFAULT]\n\nenroll_token = {}".format(key_object.key.hex)
        response = HttpResponse(data, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename = "config.ini"'
        return response


class RecommendedActionsView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    """
    Display all available to the user (or to the device) recommended actions.
    Handle 2 different url patterns: one for all user's devices, another of particular device.
    """
    template_name = 'actions.html'

    def get_context_data(self, **kwargs):
        actions = []

        if self.request.user.devices.exists():
            device_pk = kwargs.get('device_pk')
            if device_pk is not None:
                dev = get_object_or_404(Device, pk=device_pk, owner=self.request.user)
                device_name = dev.get_name()
                actions_qs = dev.recommendedaction_set.all()
            else:
                device_name = None
                actions_qs = RecommendedAction.objects.filter(device__owner=self.request.user).order_by('device__pk')

            # Select all RAs for all user's devices which are not snoozed
            active_actions = actions_qs.filter(RecommendedAction.get_affected_query())

            # Gather a dict of action_id: [device_pk] where an action with action_id affects the list of device_pk's.
            actions_by_id = defaultdict(list)
            affected_devices = set()
            for ra in active_actions:
                affected_devices.add(ra.device.pk)
                actions_by_id[ra.action_id].append(ra.device.pk)
            affected_devices = {d.pk: d for d in Device.objects.filter(pk__in=affected_devices)}

            # Generate Action objects to be rendered on page for every affected RA.
            for ra_id, device_pks in actions_by_id.items():
                devices = [affected_devices[d] for d in device_pks]
                a = ActionMeta.get_class(ra_id).action(self.request.user, devices, device_pk)
                actions.append(a)
        else:  # User has no devices - display the special action.
            device_name = None
            actions = [Action(
                'Enroll your node(s) to unlock this feature',
                'In order to receive recommended actions, click "Add Node" under "Dashboard" to receive instructions '
                'on how to enroll your nodes.',
                action_id=0,
                devices=[],
                severity=Severity.LO
            )]

        # Add this unsnoozable action (same as "enroll your nodes" action above) if the user has not authorized wott-bot
        # and has not set up integration with any Github repo. Only shown on common actions page.
        if not (self.request.user.profile.github_oauth_token and
                self.request.user.profile.github_repo_id) and \
                not kwargs.get('device_pk'):
            actions.append(Action(
                'Enable our GitHub integration for improved workflow',
                'Did you know that WoTT integrates directly with GitHub? By enabling this integration, GitHub Issues '
                'are automatically created and updated for Recommended Actions. You can then easily assign these Issues'
                ' to team members and integrate them into your sprint planning.\n\n'
                'Please note that we recommend that you use a private GitHub repository for issues.\n\n'
                'You can find the GitHub integration settings in under your profile in the upper right-hand corner.',
                action_id=0,
                devices=[],
                severity=Severity.LO
            ))

        context = super().get_context_data(**kwargs)

        # Sort actions by severity and then by action id, effectively grouping subclasses together.
        actions.sort(key=lambda a: (a.severity.value, a.action_id))

        context['actions'] = actions
        context['device_name'] = device_name
        return context
