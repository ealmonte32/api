# Generated by Django 2.1.10 on 2019-08-06 05:10

from django.db import migrations, models


def save_trust_score(apps, schema_editor):
    Device = apps.get_model('device_registry', 'Device')
    for d in Device.objects.all():
        d.save(update_fields=['trust_score'])


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0053_auto_20190716_1247'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='trust_score',
            field=models.FloatField(null=True),
        ),
        migrations.RunPython(save_trust_score),
    ]
