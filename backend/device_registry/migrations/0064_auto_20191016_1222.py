# Generated by Django 2.2.6 on 2019-10-16 12:22

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0063_auto_20191014_0742'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='deviceinfo',
            name='distr_id',
        ),
        migrations.RemoveField(
            model_name='deviceinfo',
            name='distr_release',
        ),
        migrations.AddField(
            model_name='device',
            name='os_release',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=dict),
        ),
    ]