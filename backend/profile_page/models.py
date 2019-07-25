from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver


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
