# Generated by Django 2.1.7 on 2019-06-02 17:31

import django.core.validators
from django.db import migrations, models
import re


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0036_merge_20190529_1023'),
    ]

    operations = [
        migrations.AlterField(
            model_name='credential',
            name='name',
            field=models.CharField(max_length=64, validators=[django.core.validators.RegexValidator(code='invalid_name', message='Use only alphanumeric charecters, and _.-:', regex=re.compile(r'^[\w0-9_.\-:]+$'))]),
        ),
    ]