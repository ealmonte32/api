from django.contrib.auth.models import User
from django.db.models import Count

print('user,email,device_count')
for user in User.objects.exclude(
        devices__isnull=True).annotate(
                num_devices=Count('devices')):
    print('{},{},{}'.format(user.username, user.email, user.num_devices))
