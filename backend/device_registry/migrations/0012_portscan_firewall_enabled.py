# Generated by Django 2.1.7 on 2019-03-20 06:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0011_portscan'),
    ]

    operations = [
        migrations.AddField(
            model_name='portscan',
            name='firewall_enabled',
            field=models.BooleanField(blank=True, null=True),
        ),
    ]
