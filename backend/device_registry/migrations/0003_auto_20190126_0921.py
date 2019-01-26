# Generated by Django 2.1.5 on 2019-01-26 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0002_device_certificate_csr'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='device_manufacturer',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='device',
            name='device_model',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
    ]