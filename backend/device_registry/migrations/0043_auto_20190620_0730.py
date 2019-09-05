# Generated by Django 2.1.9 on 2019-06-20 07:30

import device_registry.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0042_merge_20190613_1313'),
    ]

    operations = [
        migrations.AlterField(
            model_name='credential',
            name='name',
            field=models.CharField(max_length=64, validators=[device_registry.validators.UnicodeNameValidator()]),
        ),
    ]