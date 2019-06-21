# Generated by Django 2.1.9 on 2019-06-20 17:07

import device_registry.validators
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('device_registry', '0044_auto_20190620_0915'),
    ]

    operations = [
        migrations.AddField(
            model_name='credential',
            name='linux_user',
            field=models.CharField(blank=True, max_length=32, validators=[device_registry.validators.LinuxUserNameValidator()]),
        ),
        migrations.AlterUniqueTogether(
            name='credential',
            unique_together={('owner', 'key', 'name', 'linux_user')},
        ),
    ]
