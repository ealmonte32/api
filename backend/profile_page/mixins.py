from django.conf import settings

import djstripe.models
import djstripe.settings

from .models import Profile


class LoginTrackMixin:
    """
    Set either signed_in or signed_up in context if the user has just signed in or registered.
    One of those will be set only once which allows on-page JS code to take proper actions like send tracking events.
    """

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        for attr in ('signed_in', 'signed_up'):
            if attr in self.request.session:
                context[attr] = self.request.session[attr]
                del self.request.session[attr]
        return context


class StripeContextMixin:
    def get_context_data(self, **kwargs):
        # if not djstripe.models.Plan.objects.exists():
        #     raise Exception(
        #         "No Product Plans in the dj-stripe database - create some in your "
        #         "stripe account and then "
        #         "run `./manage.py djstripe_sync_plans_from_stripe` "
        #         "(or use the dj-stripe webhooks)")
        context = super().get_context_data(**kwargs)
        context["STRIPE_PUBLIC_KEY"] = djstripe.settings.STRIPE_PUBLIC_KEY
        context["PRICE_PER_NODE"] = settings.WOTT_PRICE_PER_NODE
        return context


class SyncUserSubscriptionsMixin:
    def sync_user_subscriptions(self, user):
        # Sync all locally existing subscriptions' statuses with Stripe.
        # TODO: Delete all locally existing subscriptions that not exist in Stripe.
        # TODO: Pull from Stripe missing (locally) subscriptions' info.
        subscriptions = djstripe.models.Subscription.objects.filter(customer__subscriber=user)
        for subscription in subscriptions:
            djstripe.models.Subscription.sync_from_stripe_data(subscription.api_retrieve())

        # Switch to the free payment plan if a user has no active subscriptions.
        if not user.profile.has_active_subscription and user.profile.payment_plan != Profile.PAYMENT_PLAN_FREE:
            user.profile.payment_plan = Profile.PAYMENT_PLAN_FREE
            user.profile.save(update_fields=['payment_plan'])
        # # Switch to the standard payment plan if a user has active subscriptions.
        # elif user.profile.has_active_subscription and user.profile.payment_plan == Profile.PAYMENT_PLAN_FREE:
        #     user.profile.payment_plan = Profile.PAYMENT_PLAN_STANDARD
        #     user.profile.save(update_fields=['payment_plan'])
