# Generated by Django 2.2.5 on 2019-09-18 04:43

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0058_auto_20190917_1245'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='audit_files',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list),
        ),
    ]
