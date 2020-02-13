import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.db.models import Q, Avg, Max, Window, Count
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils import timezone

from dateutil.relativedelta import relativedelta, MO, SU
from mixpanel import Mixpanel, MixpanelException
from phonenumber_field.modelfields import PhoneNumberField

from device_registry.models import RecommendedAction, Device, HistoryRecord, Vulnerability, PairingKey
from device_registry.celery_tasks import github
from device_registry.recommended_actions import ActionMeta

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=User, dispatch_uid="user_save_lower")
def user_save_lower(sender, instance, *args, **kwargs):
    instance.username = instance.username.lower()


class Profile(models.Model):
    PAYMENT_PLAN_FREE = 1
    PAYMENT_PLAN_STANDARD = 2
    PAYMENT_PLAN_PROFESSIONAL = 3
    PAYMENT_PLAN_ENTERPRISE = 4
    PAYMENT_PLAN_CHOICES = (
        (PAYMENT_PLAN_FREE, 'Free'),
        (PAYMENT_PLAN_STANDARD, 'Standard'),
        (PAYMENT_PLAN_PROFESSIONAL, 'Professional'),
        (PAYMENT_PLAN_ENTERPRISE, 'Enterprise')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_active = models.DateField(null=True, blank=True)
    company_name = models.CharField(blank=True, max_length=128)
    payment_plan = models.PositiveSmallIntegerField(choices=PAYMENT_PLAN_CHOICES, default=PAYMENT_PLAN_FREE)
    wizard_shown = models.BooleanField(default=False)
    phone = PhoneNumberField(blank=True)
    github_auth_code = models.CharField(blank=True, max_length=32)
    github_repo_id = models.PositiveIntegerField(blank=True, null=True)
    github_repo_url = models.URLField(blank=True)
    github_random_state = models.CharField(blank=True, max_length=32)
    github_oauth_token = models.CharField(blank=True, max_length=64)
    github_issues = JSONField(blank=True, default=dict)

    @property
    def actions_count(self):
        return RecommendedAction.objects.filter(
            Q(device__owner=self.user) & RecommendedAction.get_affected_query()) \
            .values('action_id').distinct().count()

    @property
    def actions_weekly(self):
        """
        Gather RAs resolved this week and unresolved RAs.
        Resolved are those which were truly resolved (not snoozed).
        Unresolved are those which affect user's device(s) and are not snoozed.
        :return: a tuple of QuerySets: unresolved, resolved
        """
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1))).date()  # Last week's sunday (just before this monday)
        this_monday = sunday + relativedelta(days=1)  # This week's monday
        all_ids = [ra.action_id for ra in ActionMeta.all_classes()]

        ra_maybe_resolved_this_week = RecommendedAction.objects.filter(device__owner=self.user,
                                                                       action_id__in=all_ids,
                                                                       status=RecommendedAction.Status.NOT_AFFECTED,
                                                                       resolved_at__gte=this_monday) \
            .values('action_id')  # resolved this week (not completely)
        ra_unresolved = RecommendedAction.objects.filter(~Q(status=RecommendedAction.Status.NOT_AFFECTED),
                                                         device__owner=self.user,
                                                         action_id__in=all_ids) \
            .values('action_id').distinct()  # unresolved (incl. snoozed)
        ra_resolved_this_week = ra_maybe_resolved_this_week.exclude(action_id__in=ra_unresolved).distinct()
        return ra_unresolved.filter(RecommendedAction.get_affected_query()), ra_resolved_this_week

    @property
    def actions_resolved_since_monday(self):
        resolved = self.actions_weekly[1]
        return min(resolved.count(), settings.MAX_WEEKLY_RA)

    @property
    def github_repos(self):
        try:
            return github.list_repos(self.github_oauth_token)
        except github.GithubError:
            self.github_oauth_token = ''
            self.save(update_fields=['github_oauth_token'])

    def fetch_oauth_token(self, code, state):
        self.github_oauth_token = github.get_token_from_code(code, state)
        self.save(update_fields=['github_oauth_token'])

    def track_first_device(self):
        if self.user.devices.count() == 1 and settings.MIXPANEL_TOKEN:
            try:
                mp = Mixpanel(settings.MIXPANEL_TOKEN)
                mp.track(self.user.email, 'First Node')
            except MixpanelException:
                logger.exception('Failed to send First Device event')

    @property
    def average_trust_score(self):
        devices = Device.objects.filter(owner=self.user, trust_score__isnull=False)
        if not devices.exists():
            return None
        return devices.aggregate(Avg('trust_score'))['trust_score__avg']

    @property
    def average_trust_score_last_week(self):
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1))).date()  # Last week's sunday (just before this monday)
        last_monday = sunday + relativedelta(weekday=MO(-1))  # Last week's monday
        this_monday = sunday + relativedelta(days=1)  # This week's monday
        score_history = HistoryRecord.objects.filter(owner=self.user, sampled_at__date__gte=last_monday,
                                                     sampled_at__date__lt=this_monday) \
                                             .values('average_trust_score') \
                                             .aggregate(Max('average_trust_score'))
        return score_history['average_trust_score__max'] or 0

    def sample_history(self):
        """
        Count the number of newly resolved user's RAs in the last 24h, save it together with the user's average trust
        score into a new HistoryRecord.
        """
        now = timezone.now()
        day_ago = now - timezone.timedelta(hours=24)
        ra_resolved = RecommendedAction.objects.filter(
            status=RecommendedAction.Status.NOT_AFFECTED,
            resolved_at__gt=day_ago, resolved_at__lte=now,
            device__owner=self.user
        ).values('action_id').distinct().count()

        cve_hi, cve_med, cve_lo = self.cve_count
        HistoryRecord.objects.create(owner=self.user,
                                     recommended_actions_resolved=ra_resolved,
                                     average_trust_score=self.average_trust_score,
                                     cve_high_count=cve_hi, cve_medium_count=cve_med, cve_low_count=cve_lo)

        for d in self.user.devices.all():
            d.sample_history()

    @property
    def cve_count(self):
        # For every CVE name detected on all user's devices, find its maximal urgency among the whole CVE database.
        # This will include CVEs with the same name from different sources (Denian and Ubuntu trackers currently).
        # Then count the number of distinct CVE names grouped by urgency.
        vuln_names = Vulnerability.objects.filter(debpackage__device__owner=self.user, fix_available=True) \
            .values('name').distinct()
        urgency_counts = Vulnerability.objects.filter(name__in=vuln_names) \
            .values('name').distinct() \
            .annotate(max_urgency=Max('urgency')) \
            .annotate(urg_cnt=Window(expression=Count('name'), partition_by='max_urgency')).order_by() \
            .values('max_urgency', 'urg_cnt')
        counts_by_urgency = {s['max_urgency']: s['urg_cnt'] for s in urgency_counts}
        return (counts_by_urgency.get(urgency, 0) for urgency in [Vulnerability.Urgency.HIGH,
                                                                  Vulnerability.Urgency.MEDIUM,
                                                                  Vulnerability.Urgency.LOW])

    @property
    def cve_count_last_week(self):
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1))).date()  # Last week's sunday (just before this monday)
        last_monday = sunday + relativedelta(weekday=MO(-1))  # Last week's monday
        this_monday = sunday + relativedelta(days=1)  # This week's monday
        cve_history = HistoryRecord.objects.filter(owner=self.user, sampled_at__date__gte=last_monday,
                                                   sampled_at__date__lt=this_monday)\
            .values('cve_high_count', 'cve_medium_count', 'cve_low_count')\
            .annotate(cve_high=Max('cve_high_count'), cve_med=Max('cve_medium_count'), cve_lo=Max('cve_low_count'))\
            .values('cve_high', 'cve_med', 'cve_lo')
        if cve_history.exists():
            cve_history = cve_history.first()
            return cve_history['cve_high'], cve_history['cve_med'], cve_history['cve_lo']
        else:
            return 0, 0, 0

    @property
    def pairing_key(self):
        default_comment = "Key used for the 'Add node' functionality"
        pairing_keys = PairingKey.objects.filter(owner=self.user, comment=default_comment)
        if not pairing_keys.exists():
            pairing_key = PairingKey.objects.create(owner=self.user, comment=default_comment)
        else:
            pairing_key = pairing_keys[0]
        return pairing_key
