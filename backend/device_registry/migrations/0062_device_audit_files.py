# Generated by Django 2.2.6 on 2019-10-03 06:44

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0061_deviceinfo_processes'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='audit_files',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list),
        ),
    ]
