from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView as DjangoLogoutView, LoginView as DjangoLoginView
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic import View, TemplateView, UpdateView, RedirectView

from registration.signals import user_registered
from registration.views import RegistrationView as BaseRegistrationView
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
import stripe
import djstripe.models
import djstripe.settings

from .forms import AuthenticationForm, GithubForm, ProfileForm, RegistrationForm, ProfilePaymentPlanForm
from .mixins import LoginTrackMixin, StripeContextMixin, SyncUserSubscriptionsMixin
from .models import Profile


class ProfileAccountView(LoginRequiredMixin, SyncUserSubscriptionsMixin, LoginTrackMixin, View):

    def custom_logic(self, request):
        self.user = request.user
        self.profile = Profile.objects.get_or_create(user=self.user)[0]
        self.initial_form_data = {'username': self.user.username, 'email': self.user.email,
                                  'first_name': self.user.first_name, 'last_name': self.user.last_name,
                                  'company': self.profile.company_name,
                                  'phone': self.profile.phone}

    def get(self, request, *args, **kwargs):
        self.sync_user_subscriptions(request.user)
        self.custom_logic(request)
        form = ProfileForm(initial=self.initial_form_data)
        return render(request, 'profile_account.html', {'form': form, 'tab_account': 'active'})

    def post(self, request, *args, **kwargs):
        self.custom_logic(request)
        form = ProfileForm(request.POST, initial=self.initial_form_data)
        if form.is_valid():
            self.user.first_name = form.cleaned_data['first_name']
            self.user.last_name = form.cleaned_data['last_name']
            self.profile.company_name = form.cleaned_data['company']
            self.profile.phone = form.cleaned_data['phone']
            self.user.save(update_fields=['email', 'first_name', 'last_name'])
            self.profile.save(update_fields=['company_name', 'phone'])
            messages.add_message(self.request, messages.INFO, 'Profile info successfully updated.')
            return HttpResponseRedirect(reverse('profile'))
        return render(request, 'profile_account.html', {'form': form, 'tab_account': 'active'})


class ProfileAPITokenView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'profile_token.html'
    extra_context = {'tab_api_token': 'active'}


class LoginView(DjangoLoginView):
    form_class = AuthenticationForm

    def form_valid(self, form):
        self.request.session['signed_in'] = True
        return super().form_valid(form)


class LogoutView(DjangoLogoutView):
    """
    Overwritten default Django's `LogoutView` in order to make it send a message
     with `django.contrib.messages` app.
    """

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        logout(request)
        next_page = self.get_next_page()
        if next_page:
            messages.add_message(request, messages.INFO, 'You have successfully logged out. Now you can log in again.')
            # Redirect to this page until the session has been cleared.
            return HttpResponseRedirect(next_page)
        # Skip `LogoutView.dispatch` (as its logic was duplicated here) and call its parent's `dispatch`.
        return View.dispatch(self, request, *args, **kwargs)


class GenerateAPITokenView(LoginRequiredMixin, LoginTrackMixin, View):
    def get(self, request, *args, **kwargs):
        if not hasattr(request.user, 'auth_token'):
            Token.objects.create(user=request.user)
        return HttpResponseRedirect(reverse('profile_token'))


class RevokeAPITokenView(LoginRequiredMixin, LoginTrackMixin, View):
    def get(self, request, *args, **kwargs):
        if hasattr(request.user, 'auth_token'):
            Token.objects.filter(user=request.user).delete()
        return HttpResponseRedirect(reverse('profile_token'))


class RegistrationView(StripeContextMixin, BaseRegistrationView):
    """Overwritten standard registration view from the 'django-registration-redux' 3rd party app."""
    success_url = '/'
    form_class = RegistrationForm
    template_name = 'registration/registration_form.html'

    def form_valid(self, form):
        new_user = form.save(commit=False)
        username_field = getattr(new_user, 'USERNAME_FIELD', 'username')
        # Save lowercased email as username.
        setattr(new_user, username_field, form.cleaned_data['email'].lower())
        new_user.first_name = form.cleaned_data.get('first_name', '')
        new_user.last_name = form.cleaned_data.get('last_name', '')
        new_user.save()
        new_user = authenticate(username=getattr(new_user, username_field), password=form.cleaned_data['password1'])
        login(self.request, new_user)
        self.request.session['signed_up'] = True
        user_registered.send(sender=self.__class__, user=new_user, request=self.request)
        profile, _ = Profile.objects.get_or_create(user=new_user)
        profile.payment_plan = int(form.cleaned_data['payment_plan'])
        profile.company_name = form.cleaned_data.get('company', '')
        profile.phone = form.cleaned_data.get('phone', '')
        profile.save(update_fields=['payment_plan', 'company_name', 'phone'])
        if profile.payment_plan != Profile.PAYMENT_PLAN_FREE:
            messages.add_message(self.request, messages.INFO,
                                 'You\'ll be charged in 30 days. You can cancel your subscription until then.')

        # Create the stripe Customer.
        if profile.payment_plan == Profile.PAYMENT_PLAN_STANDARD:
            nodes_number = form.cleaned_data['nodes_number']
            payment_method_id = form.cleaned_data['payment_method_id']

            # Collect customer's info for Stripe.
            name = ('%s %s' % (form.cleaned_data.get('first_name', ''),
                               form.cleaned_data.get('last_name', ''))).strip()
            company = form.cleaned_data.get('company', '').strip()
            if company:
                name += ' (%s)' % company
            # Create a Stripe customer.
            action = 'create:{}'.format(new_user.pk)
            idempotency_key = djstripe.settings.get_idempotency_key(
                'customer', action, djstripe.settings.STRIPE_LIVE_MODE)
            metadata = {}
            subscriber_key = djstripe.settings.SUBSCRIBER_CUSTOMER_KEY
            if subscriber_key not in ('', None):
                metadata[subscriber_key] = new_user.pk
            stripe_customer = djstripe.models.Customer._api_create(
                idempotency_key=idempotency_key,
                metadata=metadata,
                email=new_user.email,
                phone=form.cleaned_data.get('phone'),
                name=name if name else None,
                payment_method=payment_method_id,
                invoice_settings={'default_payment_method': payment_method_id}
            )
            # Create djstripe model's instance for the customer.
            customer, created = djstripe.models.Customer.objects.get_or_create(
                id=stripe_customer['id'],
                defaults={
                    'subscriber': new_user,
                    'livemode': stripe_customer['livemode'],
                    'balance': stripe_customer.get('balance', 0),
                    'delinquent': stripe_customer.get('delinquent', False)
                }
            )
            djstripe.models.Customer.sync_from_stripe_data(stripe_customer)

            # Using the Stripe API, create a subscription for this customer,
            # using the customer's default payment source
            stripe_subscription = stripe.Subscription.create(customer=customer.id,
                                                             billing='charge_automatically',
                                                             plan=settings.WOTT_STANDARD_PLAN_ID,
                                                             quantity=nodes_number,
                                                             trial_from_plan=True,
                                                             # TODO: billing_cycle_anchor=n,
                                                             expand=['latest_invoice.payment_intent'],
                                                             api_key=djstripe.settings.STRIPE_SECRET_KEY)
            # Sync the Stripe API return data to the database,
            # this way we don't need to wait for a webhook-triggered sync
            subscription = djstripe.models.Subscription.sync_from_stripe_data(stripe_subscription)
            # Load automatically created (with the subscription) invoice info from Stripe.
            customer._sync_invoices(subscription=subscription.id)

            if subscription.status == 'active' or \
                    (subscription.status == 'trialing' and subscription.pending_setup_intent is None):
                pass  # No card security check required.
            elif subscription.status in ('trialing', 'incomplete'):
                if subscription.status == 'trialing':
                    intent = subscription.pending_setup_intent
                    setup = True
                else:
                    intent = subscription.invoices.order_by('-pk')[0].payment_intent
                    setup = False
                if intent.status == 'requires_action' and intent.next_action['type'] == 'use_stripe_sdk':
                    # Tell the client to handle the action.
                    return render(self.request, 'card_action.html',
                                  {'STRIPE_PUBLIC_KEY': djstripe.settings.STRIPE_PUBLIC_KEY, 'setup': setup,
                                   'payment_intent_client_secret': intent.client_secret,
                                   'subscription_pk': subscription.pk})
                else:
                    raise NotImplementedError(f'Subscription status `{subscription.status}` with the intent status '
                                              f'`{intent.status}` with the next action type '
                                              f'`{intent.next_action["type"]}` are not supported yet.')
            else:
                raise NotImplementedError(f'Subscription status `{subscription.status}` is not supported yet.')

        # Standard redirect logic.
        success_url = self.get_success_url(new_user)
        try:
            to, args, kwargs = success_url
        except ValueError:
            return redirect(success_url)
        else:
            return redirect(to, *args, **kwargs)

    def get_initial(self):
        """
        Take a payment plan GET parameter value and pass it to the form
         as an initial value of its `payment_plan` field.
         All irrelevant values will be simply ignored by the form.
        Needed for setting appropriate plan value as default in the form field
         while redirected from the project site.
        """
        return {'payment_plan': self.request.GET.get('plan')}


class WizardCompleteView(LoginRequiredMixin, LoginTrackMixin, APIView):
    def post(self, request, *args, **kwargs):
        request.user.profile.wizard_shown = True
        request.user.profile.save(update_fields=['wizard_shown'])
        return Response(status=status.HTTP_200_OK)


class GithubIntegrationView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        profile = request.user.profile
        if None in [settings.GITHUB_APP_ID, settings.GITHUB_APP_PEM, settings.GITHUB_APP_CLIENT_ID,
                    settings.GITHUB_APP_CLIENT_SECRET, settings.GITHUB_APP_REDIRECT_URL, settings.GITHUB_APP_NAME]:
            context = {'github_authorized': None}
        else:
            repos = profile.github_repos
            if repos is None:
                profile.github_random_state = uuid4().hex
                profile.save(update_fields=['github_random_state'])
                context = {
                    'github_authorized': False,
                    'github_auth_url': f'https://github.com/login/oauth/authorize?'
                                       f'client_id={settings.GITHUB_APP_CLIENT_ID}&'
                                       f'redirect_uri={settings.GITHUB_APP_REDIRECT_URL}&'
                                       f'state={profile.github_random_state}'
                }
            else:
                if profile.github_repo_id not in repos:
                    profile.github_repo_id = None  # Not saving because this is a GET
                form = GithubForm({'repo': profile.github_repo_id},
                                  repo_choices=[(repo_id, repo['full_name']) for repo_id, repo in repos.items()])
                context = {
                    'form': form,
                    'github_authorized': True,
                    'github_inst_url': f'https://github.com/apps/{settings.GITHUB_APP_NAME}/installations/new'
                }
        context['tab_github_integration'] = 'active'
        return render(request, 'profile_github.html', context)

    def post(self, request, *args, **kwargs):
        profile = request.user.profile
        repos = profile.github_repos
        form = GithubForm(request.POST,
                          repo_choices=[(repo_id, repo['full_name']) for repo_id, repo in repos.items()])
        if form.is_valid():
            repo = form.cleaned_data['repo']
            repo = int(repo) if repo else None
            if profile.github_repo_id != repo:
                profile.github_repo_id = repo
                profile.github_repo_url = repos[repo]['url'] if repo else ''
                profile.github_issues = {}
                profile.save(update_fields=['github_repo_id', 'github_repo_url', 'github_issues'])
            return HttpResponseRedirect(reverse('github_integration'))
        return render(request, 'profile_github.html', {'form': form, 'tab_github_integration': 'active'})


class SlackIntegrationView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'coming_soon.html'
    extra_context = {'tab_slack_integration': 'active', 'header': 'Slack Integration'}


class PaymentPlanView(StripeContextMixin, LoginRequiredMixin, SyncUserSubscriptionsMixin, LoginTrackMixin, UpdateView):
    form_class = ProfilePaymentPlanForm
    template_name = 'profile_billing.html'
    extra_context = {'tab_payment_plan': 'active'}
    success_url = reverse_lazy('payment_plan')

    def get(self, request, *args, **kwargs):
        self.sync_user_subscriptions(request.user)
        return super().get(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return self.request.user.profile

    def form_valid(self, form):
        # TODO: wrap all in one transaction.
        self.object = form.save()  # Save the profile instance.
        payment_plan = form.cleaned_data['payment_plan']
        nodes_number = form.cleaned_data['nodes_number_hidden']
        # Cancel an existing subscription (if it's not cancelled yet).
        if payment_plan == Profile.PAYMENT_PLAN_FREE:
            if self.object.has_active_subscription:
                subscription = self.object.djstripe_customer.subscription
                if not subscription.is_status_temporarily_current():  # Not cancelled yet.
                    # Cancel subscription automatic renewal.
                    stripe_subscription = subscription.api_retrieve()
                    stripe_subscription.cancel_at_period_end = True
                    stripe_subscription.save()
                    djstripe.models.Subscription.sync_from_stripe_data(stripe_subscription)
                    messages.add_message(self.request, messages.INFO,
                                         'Subscription cancelled successfully. Note: you can use your previous plan '
                                         'features until the end of current paid billing period.')
        # Create a new or update an existing subscription.
        elif payment_plan == Profile.PAYMENT_PLAN_STANDARD:
            if self.object.has_active_subscription:
                subscription = self.object.djstripe_customer.subscription
                # Not cancelled and has nodes number changed.
                if not subscription.is_status_temporarily_current() and subscription.quantity != nodes_number:
                    # Update an existing subscription.
                    subscription.update(quantity=nodes_number, prorate=True)
                    # Automatically immediately charge a customer's card for increased number of items
                    # in his subscription, or put (for paying future invoices from it as a 1st source) the extra
                    # money to his Stripe balance (in case of reduced number of items).
                    subscription.customer.send_invoice()
                    messages.add_message(self.request, messages.INFO, 'Paid nodes number successfully changed.')
                # Immediately cancel the subscription before creating the new one.
                # Also put all unused money for this subscription to the customer's Stripe balance.
                elif subscription.is_status_temporarily_current():
                    djstripe.models.Subscription.sync_from_stripe_data(subscription._api_delete(prorate=True))
                    subscription.customer.send_invoice()

            if not self.object.has_active_subscription:
                payment_method_id = form.cleaned_data['payment_method_id']

                # Create a Stripe customer (if needed).
                if not djstripe.models.Customer.objects.filter(subscriber=self.object.user).exists():
                    # Collect customer's info for Stripe.
                    name = ('%s %s' % (self.object.user.first_name, self.object.user.last_name)).strip()
                    company = self.object.company_name.strip()
                    if company:
                        name += ' (%s)' % company

                    action = 'create:{}'.format(self.object.user.pk)
                    idempotency_key = djstripe.settings.get_idempotency_key(
                        'customer', action, djstripe.settings.STRIPE_LIVE_MODE)
                    metadata = {}
                    subscriber_key = djstripe.settings.SUBSCRIBER_CUSTOMER_KEY
                    if subscriber_key not in ('', None):
                        metadata[subscriber_key] = self.object.user.pk
                    stripe_customer = djstripe.models.Customer._api_create(
                        idempotency_key=idempotency_key,
                        metadata=metadata,
                        email=self.object.user.email,
                        phone=form.cleaned_data.get('phone'),
                        name=name if name else None,
                        payment_method=payment_method_id,
                        invoice_settings={'default_payment_method': payment_method_id}
                    )
                    # Create djstripe model's instance for the customer.
                    customer, created = djstripe.models.Customer.objects.get_or_create(
                        id=stripe_customer['id'],
                        defaults={
                            'subscriber': self.object.user,
                            'livemode': stripe_customer['livemode'],
                            'balance': stripe_customer.get('balance', 0),
                            'delinquent': stripe_customer.get('delinquent', False)
                        }
                    )
                    djstripe.models.Customer.sync_from_stripe_data(stripe_customer)
                else:
                    customer = self.object.djstripe_customer
                    customer.add_payment_method(payment_method_id)
                # Using the Stripe API, create a subscription for this customer,
                # using the customer's default payment source
                stripe_subscription = stripe.Subscription.create(customer=customer.id,
                                                                 billing='charge_automatically',
                                                                 plan=settings.WOTT_STANDARD_PLAN_ID,
                                                                 quantity=nodes_number,
                                                                 trial_from_plan=True,
                                                                 expand=['latest_invoice.payment_intent'],
                                                                 api_key=djstripe.settings.STRIPE_SECRET_KEY)
                # Sync the Stripe API return data to the database,
                # this way we don't need to wait for a webhook-triggered sync
                subscription = djstripe.models.Subscription.sync_from_stripe_data(stripe_subscription)
                # Load automatically created (with the subscription) invoice info from Stripe.
                customer._sync_invoices(subscription=subscription.id)

                # No card security check required.
                if subscription.status == 'active' or \
                        (subscription.status == 'trialing' and subscription.pending_setup_intent is None):
                    messages.add_message(self.request, messages.INFO, 'Subscription created successfully.')
                # Stripe payments intent API involved.
                elif subscription.status in ('trialing', 'incomplete'):
                    if subscription.status == 'trialing':
                        intent = subscription.pending_setup_intent
                        setup = True
                    else:
                        intent = subscription.invoices.order_by('-pk')[0].payment_intent
                        setup = False
                    if intent.status == 'requires_action' and intent.next_action['type'] == 'use_stripe_sdk':
                        # Tell the client to handle the action.
                        return render(self.request, 'card_action.html',
                                      {'STRIPE_PUBLIC_KEY': djstripe.settings.STRIPE_PUBLIC_KEY, 'setup': setup,
                                       'payment_intent_client_secret': intent.client_secret,
                                       'subscription_pk': subscription.pk})
                    else:
                        raise NotImplementedError(
                            f'Subscription status `{subscription.status}` with the intent status '
                            f'`{intent.status}` with the next action type '
                            f'`{intent.next_action["type"]}` are not supported yet.')
                else:
                    raise NotImplementedError(f'Subscription status `{subscription.status}` is not supported yet.')
        else:
            raise NotImplementedError
        return HttpResponseRedirect(self.get_success_url())

    def get_initial(self):
        initial = super().get_initial()
        nodes_number = self.request.user.profile.paid_nodes_number
        if nodes_number:
            initial['nodes_number'] = nodes_number
            initial['total_sum'] = nodes_number * settings.WOTT_PRICE_PER_NODE
        initial['subscription_status'] = self.request.user.profile.subscription_status_text
        if self.request.user.profile.current_period_end:
            initial['current_period_ends'] = self.request.user.profile.current_period_end.strftime(
                '%Y-%m-%d %H:%M:%S %Z')
        return initial


class GithubCallbackView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        profile = request.user.profile
        if profile.github_random_state != request.GET.get('state'):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        request.user.profile.fetch_oauth_token(request.GET.get('code'), profile.github_random_state)
        return render(request, 'github_callback.html')


class SyncSubscriptionView(LoginRequiredMixin, RedirectView):
    """
    The only purpose of this view is to (silently) sync a newly created subscription's
     local status with Stripe after its 3D Secure protected payment check.
    """
    url = reverse_lazy('root')

    def get(self, request, *args, **kwargs):
        subscription = get_object_or_404(djstripe.models.Subscription, pk=kwargs['pk'],
                                         customer__subscriber=self.request.user)
        djstripe.models.Subscription.sync_from_stripe_data(subscription.api_retrieve())
        messages.add_message(request, messages.INFO, 'Subscription created successfully.')
        return super().get(request, *args, **kwargs)
