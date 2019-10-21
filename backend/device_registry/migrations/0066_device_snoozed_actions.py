# Generated by Django 2.2.6 on 2019-10-18 09:12

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0065_device_auto_upgrades'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='snoozed_actions',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list),
        ),
    ]
