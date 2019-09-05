# Generated by Django 2.1.10 on 2019-09-04 07:50

import device_registry.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0056_device_deb_packages'),
    ]

    operations = [
        migrations.CreateModel(
            name='DebPackage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
                ('version', models.CharField(max_length=128)),
                ('distro', models.CharField(choices=[(device_registry.models.DebPackage.Distro('debian'), 'debian'),
                                                     (device_registry.models.DebPackage.Distro('raspbian'), 'raspbian'),
                                                     (device_registry.models.DebPackage.Distro('ubuntu'), 'ubuntu')],
                                            max_length=128)),
            ],
        ),
        migrations.AddField(
            model_name='device',
            name='deb_packages_hash',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.RemoveField(
            model_name='device',
            name='deb_packages',
        ),
        migrations.AddField(
            model_name='device',
            name='deb_packages',
            field=models.ManyToManyField(to='device_registry.DebPackage'),
        ),
    ]
