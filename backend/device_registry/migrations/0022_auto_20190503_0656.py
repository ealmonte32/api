# Generated by Django 2.1.7 on 2019-05-03 06:56

from django.db import migrations
import jsonfield_compat.fields


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0021_auto_20190502_0942'),
    ]

    operations = [
        migrations.AlterField(
            model_name='portscan',
            name='scan_info',
            field=jsonfield_compat.fields.JSONField(default=list),
        ),
    ]