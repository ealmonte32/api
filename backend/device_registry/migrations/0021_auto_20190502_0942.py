# Generated by Django 2.1.7 on 2019-05-02 09:42

from jsonfield_compat.fields import JSONField
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0020_auto_20190502_0436'),
    ]

    operations = [

        migrations.AlterField(
            model_name='portscan',
            name='scan_info',
            field=JSONField(default=list),
        ),
    ]
