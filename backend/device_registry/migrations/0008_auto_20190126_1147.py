# Generated by Django 2.1.5 on 2019-01-26 11:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0007_auto_20190126_1009'),
    ]

    operations = [
        migrations.RenameField(
            model_name='deviceinfo',
            old_name='device_id',
            new_name='device',
        ),
    ]