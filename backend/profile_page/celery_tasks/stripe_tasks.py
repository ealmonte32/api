import djstripe.models


def sync_subscriptions():
    """Sync all existing subscriptions' statuses with Stripe."""
    for subscription in djstripe.models.Subscription.objects.all():
        # TODO: reduce the amount of work by excluding from sync subscriptions with statuses that can't be changed.
        djstripe.models.Subscription.sync_from_stripe_data(subscription.api_retrieve())
