# Generated by Django 2.1.7 on 2019-03-13 11:49

from django.db import migrations, models
import django.db.models.deletion
from django.contrib.postgres.fields import JSONField


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0010_deviceinfo_fqdn'),
    ]

    operations = [
        migrations.CreateModel(
            name='PortScan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_date', models.DateTimeField(auto_now_add=True)),
                ('scan_info', JSONField(default=dict)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='device_registry.Device')),
            ],
        ),
    ]
