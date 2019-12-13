import json
import uuid
from collections import defaultdict
from typing import NamedTuple, List

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.db import transaction
from django.db.models import Case, When, Count, Window, Value, F, Q, IntegerField, Max
from django.db.models.functions import Round, Coalesce
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views.generic import DetailView, ListView, TemplateView, View, UpdateView, CreateView, DeleteView

from profile_page.mixins import LoginTrackMixin
from .forms import ClaimDeviceForm, DeviceAttrsForm, PortsForm, ConnectionsForm, DeviceMetadataForm
from .forms import FirewallStateGlobalPolicyForm, GlobalPolicyForm
from .models import Device, PortScan, FirewallState, get_bootstrap_color, PairingKey, GlobalPolicy, Vulnerability
from .models import RecommendedAction
from .recommended_actions import ActionMeta, FirewallDisabledAction, EnrollAction, GithubAction
from .mixins import DeviceListFilterMixin, ConvertPortsInfoMixin, BlockUnpaidNodeMixin


class RootView(LoginRequiredMixin, LoginTrackMixin, DeviceListFilterMixin, ListView):
    model = Device
    template_name = 'root.html'
    context_object_name = 'mirai_devices'  # device list moved to ajax, so only mirai detected devices still here
    filter_dict = None

    def get_queryset(self):
        queryset = super().get_queryset()
        common_query = Q(owner=self.request.user, deviceinfo__detected_mirai=True)
        query = self.get_filter_q(set_filter_dict=True)
        if self.request.GET.get('filter_by') == 'trust-score':
            return queryset.annotate(trust_score_prcnt=Round(Coalesce(F('trust_score'), 0.0) * 100)).filter(
                common_query & query).distinct()
        else:
            return queryset.filter(common_query & query).distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        avg_trust_score = self.request.user.profile.average_trust_score
        context.update(
            avg_trust_score=avg_trust_score,
            avg_trust_score_percent=round(avg_trust_score * 100) if avg_trust_score is not None else None,
            avg_trust_score_color=get_bootstrap_color(
                round(avg_trust_score * 100)) if avg_trust_score is not None else None,
            active_inactive=Device.get_active_inactive(self.request.user),
            column_names=[
                'Node Name',
                'Hostname',
                'Last Ping',
                'Trust Score',
                'Recommended Actions'
            ],
            filter_params=[(field_name, field_desc[1], field_desc[2]) for field_name, field_desc in
                           self.FILTER_FIELDS.items()],

            # TODO: convert this into a list of dicts for multiple filters
            filter=self.filter_dict
        )
        return context


class DashboardView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'dashboard.html'

    def _actions(self):
        ra_unresolved, ra_resolved_this_week = self.request.user.profile.actions_weekly

        severities = {ra.action_id: ra.severity for ra in ActionMeta.all_classes()}
        actions = []
        resolved_count = ra_resolved_this_week.count()
        if resolved_count < settings.MAX_WEEKLY_RA:
            ra_unresolved = sorted(ra_unresolved.values_list('action_id', flat=True),
                                   key=lambda v: severities[v].value[2], reverse=True)
            for action_id in ra_unresolved[:settings.MAX_WEEKLY_RA - resolved_count]:
                affected_devices = Device.objects.filter(owner=self.request.user,
                                                         recommendedaction__in=RecommendedAction.objects.filter(
                                                             RecommendedAction.get_affected_query(),
                                                             action_id=action_id)).distinct()
                a = ActionMeta.get_class(action_id).action(self.request.user, affected_devices, None)
                actions.append(a._replace(resolved=False))

        for action_id in ra_resolved_this_week.values_list('action_id', flat=True)[:settings.MAX_WEEKLY_RA]:
            a = ActionMeta.get_class(action_id).action(self.request.user, [], None)
            actions.append(a._replace(resolved=True))

        return actions, min(ra_resolved_this_week.count(), settings.MAX_WEEKLY_RA)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context.update(
            welcome=not self.request.user.devices.exists()
        )
        score = self.request.user.profile.average_trust_score
        actions, resolved_count = self._actions()
        if score is not None:
            last_week_score = self.request.user.profile.average_trust_score_last_week
            context.update(
                ball_offset=-score * 74 - 38,
                trust_score={
                    'current': round(score * 100),
                    'delta': round(abs(score - last_week_score) * 100),
                    'arrow': 'up' if score - last_week_score >= 0 else 'down',
                },
            )
        context.update(
            actions=actions,
            weekly_progress=round(resolved_count * 100 / settings.MAX_WEEKLY_RA)
        )
        return context


class GlobalPoliciesListView(LoginRequiredMixin, LoginTrackMixin, ListView):
    model = GlobalPolicy
    template_name = 'policies.html'

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)


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


class DeviceDetailView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
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
        if self.object.payment_status == 'unpaid':
            return HttpResponseForbidden()
        form = DeviceAttrsForm(request.POST, instance=self.object)
        if form.is_valid():
            if 'revoke_button' in form.data:
                self.object.owner = None
                self.object.claim_token = uuid.uuid4()
                self.object.save(update_fields=['owner', 'claim_token'])
                messages.add_message(request, messages.INFO, 'You have successfully revoked your device.')
                return HttpResponseRedirect(reverse('root'))
            else:
                form.save()
                return HttpResponseRedirect(reverse('device-detail', kwargs={'pk': kwargs['pk']}))
        return self.render_to_response(self.get_context_data(form=form))


class DeviceDetailSoftwareView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailSecurityView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
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
        # TODO: handle missing portscan and firewallstate instances.
        self.object = self.get_object()
        if self.object.payment_status == 'unpaid':
            return HttpResponseForbidden()
        portscan = self.object.portscan
        firewallstate = self.object.firewallstate

        # Submitted the `FirewallStateGlobalPolicyForm` form.
        if 'global_policy' in request.POST:
            form = FirewallStateGlobalPolicyForm(request.POST, instance=firewallstate)
            if form.is_valid():
                # TODO: check isn't it enough to do `form.save()` here.
                firewallstate.global_policy = form.cleaned_data["global_policy"]
                firewallstate.save(update_fields=['global_policy'])
        # Submitted the `PortsForm` form.
        elif 'is_ports_form' in request.POST:
            if firewallstate.global_policy:
                # If some global policy applied to the device - you can't manage its ports.
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
                with transaction.atomic():
                    portscan.save(update_fields=['block_ports'])
                    firewallstate.save(update_fields=['policy'])
                    self.object.update_trust_score = True
                    self.object.save(update_fields=['update_trust_score'])
        # Submitted the `ConnectionsForm` form.
        elif 'is_connections_form' in request.POST:
            if firewallstate.global_policy:
                # If some global policy applied to the device - you can't manage its connections.
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

        self.object.refresh_from_db()
        self.object.generate_recommended_actions(classes=[FirewallDisabledAction])
        return HttpResponseRedirect(reverse('device-detail-security', kwargs={'pk': kwargs['pk']}))


class DeviceDetailNetworkView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
    model = Device
    template_name = 'device_info_network.html'

    def get_queryset(self):  # TODO: put this kind of `get_queryset` method to mixin.
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_context_data(self, **kwargs):  # TODO: put duplicated `get_context_data` to mixin.
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


class DeviceDetailHardwareView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
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


class DeviceDetailMetadataView(BlockUnpaidNodeMixin, LoginRequiredMixin, LoginTrackMixin, DetailView):
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
        if self.object.payment_status == 'unpaid':
            return HttpResponseForbidden()
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

    def _actions(self, device_pk=None):
        actions = []

        if self.request.user.devices.exists():
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
                if ra.device.payment_status == 'unpaid':
                    continue  # Filter out actions for unpaid devices.
                affected_devices.add(ra.device.pk)
                actions_by_id[ra.action_id].append(ra.device.pk)
            affected_devices = {d.pk: d for d in Device.objects.filter(pk__in=affected_devices)}

            # Generate Action objects to be rendered on page for every affected RA.
            for ra_id, device_pks in actions_by_id.items():
                devices = [affected_devices[d] for d in device_pks]
                if ActionMeta.is_action_id(ra_id):
                    # Make sure we have an Action class with this id.
                    # If we don't (this id is invalid or was removed) - ignore it.
                    a = ActionMeta.get_class(ra_id).action(self.request.user, devices, device_pk)
                    actions.append(a)
        else:  # User has no devices - display the special action.
            device_name = None
            actions = [EnrollAction.get_user_context(self.request.user)]

        # Add this unsnoozable action (same as "enroll your nodes" action above) if the user has not authorized wott-bot
        # and has not set up integration with any Github repo. Only shown on common actions page.
        if not (self.request.user.profile.github_oauth_token and
                self.request.user.profile.github_repo_id) and \
                device_pk is None:
            actions.append(GithubAction.action(self.request.user, []))

        # Sort actions by severity and then by action id, effectively grouping subclasses together.
        actions.sort(key=lambda a: (a.severity.value[2], a.action_id), reverse=True)

        return device_name, actions

    def get(self, request, *args, **kwargs):
        device_pk = kwargs.get('pk')
        if device_pk is not None:
            device = get_object_or_404(Device, pk=device_pk, owner=request.user)
            if device.payment_status == 'unpaid':
                return HttpResponseForbidden()
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        device_name, actions = self._actions(kwargs.get('pk'))
        context.update(
            actions=actions,
            device_name=device_name
        )
        return context


class CVEView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'cve.html'

    class Hyperlink(NamedTuple):
        text: str
        href: str

    class AffectedPackage(NamedTuple):
        name: str
        devices_count: int
        devices: List[NamedTuple]

        @property
        def upgrade_command(self):
            return f'$ apt-get update && apt-get install -y {self.name} && apt-get autoremove'

    class TableRow(NamedTuple):
        cve_name: str
        urgency: Vulnerability.Urgency
        packages: List[NamedTuple]  # Actually it's List[AffectedPackage]
        cve_url: str
        cve_date: timezone.datetime = None

        urgencies = {
            Vulnerability.Urgency.HIGH: 'High',
            Vulnerability.Urgency.MEDIUM: 'Medium',
            Vulnerability.Urgency.LOW: 'Low',
            Vulnerability.Urgency.NONE: 'N/A'
        }

        @property
        def key(self):
            return self.urgency, sum([p.devices_count for p in self.packages])

        @property
        def severity(self):
            return self.urgencies[self.urgency]

        @property
        def cve_link(self):
            return CVEView.Hyperlink(self.cve_name, 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=' + self.cve_name)

    @staticmethod
    def delta(current, last):
        if current is None or last is None:
            return
        return {
            'count': current,
            'delta': f'{current - last:+d}'
        }

    @staticmethod
    def percent(a, b):
        return a / b * 100

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        device_pk = kwargs.get('device_pk')
        if device_pk is not None:
            device = get_object_or_404(Device, pk=device_pk, owner=user)
            vuln_query = Q(debpackage__device__pk=device_pk)
        else:
            device = None
            vuln_query = Q(debpackage__device__owner=user)

        # We gather Vulnerabilities from different sources: Debian Security Tracker (DST) and Ubuntu Security Tracker
        # (UST). DST and UST often don't agree on severity for the same CVE. Also UST has CVE publication date
        # (pub_date) while DST has not. But we need to compile the resulting CVE list regardless of those differences.
        # This is why the code below is so complicated.

        # Select all CVEs which affect all user's devices and for every CVE find its publication date by looking through
        # all CVEs with this name and finding maximal pub_date. By using Max() we avoid NULLs, as they compare as less
        # than any other non-NULL value.
        vuln_names = Vulnerability.objects.filter(vuln_query) \
            .values('name').distinct()
        vuln_pub_dates_qs = Vulnerability.objects.filter(name__in=vuln_names) \
            .values('name').annotate(pubdate=Max('pub_date')).distinct()
        # Build a lookup dictionary for CVE publication dates.
        vuln_pub_dates = {v['name']: v['pubdate'] for v in vuln_pub_dates_qs}

        # Group CVEs selected above by their maximal urgency. We could put this into the huge request below,
        # but it would work slower.
        vuln_urgencies = Vulnerability.objects.filter(name__in=vuln_names) \
            .values('name').distinct() \
            .annotate(max_urgency=Max('urgency'))
        vulns_by_urgency = defaultdict(list)
        for vuln_urgency in vuln_urgencies:
            vulns_by_urgency[vuln_urgency['max_urgency']].append(vuln_urgency['name'])

        # For every Vulnerability (cve) on every user's DebPackage (pkg) installed on every user's device (dev) select
        # the following data:
        # cve_1 - pkg_1 - dev_1
        #                   ...
        # cve_1 - pkg_1 - dev_n1
        # cve_1 - pkg_2 - dev_1
        #         ...
        # cve_1 - pkg_n - dev_nn
        # ...
        # cve_n - pkg_n - dev_nn
        #
        # This data is then sorted by:
        # 1) CVE severity
        # 2) total count of devices affected by a CVE (annotated as cvecnt)
        # 3) total count of devices where the package is installed (annotated as devcnt)
        # We have to do this with one request  because the number of CVEs, the number of packages and the number of
        # devices - any of them may be well over a hundred, and we can't afford to run 100 requests while handling the
        # web request.
        devices_packages_cves = Vulnerability.objects.filter(vuln_query, fix_available=True) \
            .values('name') \
            .annotate(max_urgency=Case(
            *[When(name__in=vulns_by_urgency[u], then=Value(u)) for u in Vulnerability.Urgency],
            output_field=IntegerField()
        )) \
            .values('name', 'max_urgency', 'debpackage__pk', 'debpackage__device__pk', 'debpackage__name',
                    'debpackage__device__name', 'debpackage__device__deviceinfo__fqdn') \
            .annotate(devcnt=Window(expression=Count('debpackage__name'),
                                    partition_by=['name', 'debpackage__name']),
                      cvecnt=Window(expression=Count('debpackage__name'),
                                    partition_by=['name'])) \
            .order_by('-max_urgency', '-cvecnt', 'name', '-devcnt', 'debpackage__name', 'debpackage__device__pk')

        table_rows = []
        current_row = None
        current_package = None
        for device_package_cve in devices_packages_cves:
            cve_name, package_name, urgency, devices_count, \
            device_pk, device_name, device_fqdn = (device_package_cve[k] for k in [
                'name', 'debpackage__name', 'max_urgency', 'devcnt',
                'debpackage__device__pk', 'debpackage__device__name',
                'debpackage__device__deviceinfo__fqdn'])
            # In devices_packages_cves the rows are ordered by cve_name and package_name. This means that they will be
            # grouped together by cve_name and the rows with the same cve_name will be grouped together by package_name.
            # Hence we have current_row.cve_name and current_package.name to detect when the cve_name or package_name
            # changes which means we need a new TableRow or a new AffectedPackage.
            if not current_row or current_row.cve_name != cve_name:
                current_row = self.TableRow(cve_name, urgency, [], '', vuln_pub_dates[cve_name])
                table_rows.append(current_row)
                current_package = None
            if not current_package or current_package.name != package_name:
                current_package = self.AffectedPackage(package_name, devices_count, [])
                current_row.packages.append(current_package)
            if device_name or device_fqdn:
                device_pretty_name = device_name or device_fqdn[:36]
            else:
                device_pretty_name = f"device_{device_pk}"
            current_package.devices.append(self.Hyperlink(href=reverse('device_cve', kwargs={'device_pk': device_pk}),
                                                          text=device_pretty_name))

        context['table_rows'] = table_rows
        if device:
            context['device_name'] = device.get_name()

        cve_hi, cve_med, cve_lo = (len(vulns_by_urgency[Vulnerability.Urgency.HIGH]),
                                   len(vulns_by_urgency[Vulnerability.Urgency.MEDIUM]),
                                   len(vulns_by_urgency[Vulnerability.Urgency.LOW]))
        cve_hi_last, cve_med_last, cve_lo_last = self.request.user.profile.cve_count_last_week

        context.update({
            'radius': "15.91549430918954",
            'high_color': "#EF2F20",
            'med_color': "#EF8F20",
            'low_color': "#23BED6",
            'cve': {
                'high': self.delta(cve_hi, cve_hi_last),
                'medium': self.delta(cve_med, cve_med_last),
                'low': self.delta(cve_lo, cve_lo_last),
            }
        })

        cve_sum = sum((cve_hi, cve_med, cve_lo))
        if cve_sum:
            percent_hi = self.percent(cve_hi, cve_sum)
            percent_med = self.percent(cve_med, cve_sum)
            percent_lo = self.percent(cve_lo, cve_sum)
            initial_hi = 35
            initial_med = 100 - percent_hi + initial_hi
            initial_lo = 100 - percent_med + initial_med
            context['cve']['circle'] = {
                'high': (percent_hi, 100 - percent_hi, initial_hi),
                'medium': (percent_med, 100 - percent_med, initial_med),
                'low': (percent_lo, 100 - percent_lo, initial_lo),
            }

        return context
