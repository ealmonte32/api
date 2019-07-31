from django.contrib.auth.models import User
from django.db.models import Count

print(list(User.objects.exclude(
    devices__isnull=True).annotate(num_devices=Count('devices')).values_list('username', 'email', 'num_devices')))
