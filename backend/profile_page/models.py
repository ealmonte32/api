import datetime
import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Q, Avg, Max, Window, Count, Sum
from django.db.models.functions import Coalesce
from django.db.models.signals import pre_save
from django.core.exceptions import ObjectDoesNotExist
from django.dispatch import receiver
from django.utils import timezone

from dateutil.relativedelta import relativedelta, MO, SU
from mixpanel import Mixpanel, MixpanelException
from phonenumber_field.modelfields import PhoneNumberField

from device_registry.models import RecommendedAction, RecommendedActionStatus, \
    Device, HistoryRecord, Vulnerability, PairingKey, DeviceHistoryRecord
from device_registry.celery_tasks import github

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

    @property
    def actions_count(self):
        return RecommendedActionStatus.objects.filter(
            Q(device__owner=self.user) & RecommendedActionStatus.get_affected_query()) \
            .values('ra__pk').distinct().count()

    @property
    def actions_weekly(self):
        """
        Gather RAs resolved this week and unresolved RAs.
        Resolved are those which were truly resolved (not snoozed).
        Unresolved are those which affect user's device(s) and are not snoozed.
        :return: a tuple of QuerySets: unresolved, resolved
        """
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1)))  # Last week's sunday (just before this monday)
        sunday = sunday.combine(sunday, datetime.time(0), sunday.tzinfo)  # Reset time to midnight
        this_monday = sunday + relativedelta(days=1)  # This week's monday

        ra_maybe_resolved_this_week = RecommendedActionStatus.objects.exclude(ra__action_class='CVEAction').filter(
            device__owner=self.user, status=RecommendedAction.Status.NOT_AFFECTED, resolved_at__gte=this_monday) \
            .values('ra__action_class', 'ra__action_param', 'ra__action_context', 'ra__action_severity')  # resolved this week (not completely)
        ra_unresolved = RecommendedActionStatus.objects.filter(~Q(status=RecommendedAction.Status.NOT_AFFECTED),
                                                               ~Q(ra__action_class='CVEAction'),
                                                               device__owner=self.user) \
            .values('ra__pk').distinct()  # unresolved (incl. snoozed)

        ra_resolved_this_week = ra_maybe_resolved_this_week \
            .exclude(ra__in=ra_unresolved)\
            .distinct()
        return (ra_unresolved.filter(RecommendedActionStatus.get_affected_query())
                             .values('ra__action_class', 'ra__action_param', 'ra__action_context', 'ra__action_severity'),
                ra_resolved_this_week)

    @property
    def actions_resolved_since_monday(self):
        resolved = self.actions_weekly[1]
        return min(resolved.count(), settings.MAX_WEEKLY_RA)

    @property
    def actions_resolved_today(self):
        """
        A method for finding the number of RAs resolved today that are not reflected in a history record.
        If no history record for today - return the number of RAs resolved today.
        Otherwise - return 0.
        """
        now = timezone.now()
        day_ago = now - timezone.timedelta(hours=24)
        if self.user.history_records.filter(sampled_at__date=now.date()).exists():
            return 0
        else:
            try:
                yesterday_history_record = self.user.history_records.get(sampled_at__date=day_ago.date())
            except ObjectDoesNotExist:
                day_ago = day_ago.replace(hour=settings.SAMPLE_HISTORY_AT, minute=0, second=0, microsecond=0)
            else:
                day_ago = yesterday_history_record.sampled_at
            return RecommendedActionStatus.objects.filter(
                status=RecommendedAction.Status.NOT_AFFECTED, resolved_at__gt=day_ago, resolved_at__lte=now,
                device__owner=self.user).exclude(ra__action_class='CVEAction').values('ra__pk').distinct().count()

    @property
    def actions_resolved_this_quarter(self):
        """
        Return number of RAs resolved during current quarter.
        """
        now = timezone.now()
        # Timestamp for the very beginning of the current quarter.
        quarter_start_ts = timezone.datetime(now.year, (now.month - 1) // 3 * 3 + 1, 1, tzinfo=now.tzinfo)
        actions_number_from_history = self.user.history_records.filter(
            sampled_at__gt=quarter_start_ts).aggregate(Sum('recommended_actions_resolved')
                                                       )['recommended_actions_resolved__sum'] or 0
        return actions_number_from_history + self.actions_resolved_today

    @property
    def current_weekly_streak(self):
        """
        Return the number of weeks in a row (starting from the current one) when
        the number of resolved RAs was equal or greater than MAX_WEEKLY_RA (5).
        """
        streak = 0
        current_week = True
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1)))  # Last week's sunday (just before this monday)
        sunday = sunday.combine(sunday, datetime.time(0), sunday.tzinfo)  # Reset time to midnight
        monday = sunday + timezone.timedelta(days=1)  # This week's monday
        end_ts = now
        while True:
            actions_resolved = self.user.history_records.filter(
                sampled_at__gt=monday, sampled_at__lt=end_ts).aggregate(Sum('recommended_actions_resolved')
                                                                        )['recommended_actions_resolved__sum'] or 0
            if current_week:
                actions_resolved += self.actions_resolved_today
            if actions_resolved >= settings.MAX_WEEKLY_RA:
                streak += 1
            else:
                if not current_week:
                    break
            current_week = False
            end_ts = monday
            monday = monday - timezone.timedelta(days=7)
        return streak

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
        sunday = (now + relativedelta(days=-1, weekday=SU(-1)))  # Last week's sunday (just before this monday)
        sunday = sunday.combine(sunday, datetime.time(0), sunday.tzinfo)  # Reset time to midnight
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
        ra_resolved = RecommendedActionStatus.objects.exclude(ra__action_class='CVEAction').filter(
            status=RecommendedAction.Status.NOT_AFFECTED,
            resolved_at__gt=day_ago, resolved_at__lte=now,
            device__owner=self.user
        ).values('ra__pk').distinct().count()

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

    def cve_count_last_week(self, device=None):
        now = timezone.now()
        sunday = (now + relativedelta(days=-1, weekday=SU(-1)))  # Last week's sunday (just before this monday)
        sunday = sunday.combine(sunday, datetime.time(0), sunday.tzinfo)  # Reset time to midnight
        last_monday = sunday + relativedelta(weekday=MO(-1))  # Last week's monday
        this_monday = sunday + relativedelta(days=1)  # This week's monday
        if device:
            history = DeviceHistoryRecord.objects.filter(device=device)
        else:
            history = HistoryRecord.objects.filter(owner=self.user)
        cve_history = history.filter(sampled_at__date__gte=last_monday,
                                     sampled_at__date__lt=this_monday)\
            .values('cve_high_count', 'cve_medium_count', 'cve_low_count')\
            .annotate(cve_high=Coalesce(Max('cve_high_count'), 0),
                      cve_med=Coalesce(Max('cve_medium_count'), 0),
                      cve_lo=Coalesce(Max('cve_low_count'), 0))\
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
