# Generated by Django 2.1.7 on 2019-05-11 07:23

from django.db import migrations
import jsonfield_compat.fields


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0027_auto_20190509_0516'),
    ]

    operations = [
        migrations.AlterField(
            model_name='portscan',
            name='block_ports',
            field=jsonfield_compat.fields.JSONField(default=list),
        ),
    ]