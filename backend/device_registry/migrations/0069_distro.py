# Generated by Django 2.2.6 on 2019-11-05 14:53

from django.db import migrations, models
from django.core.management import call_command


def load_fixture(apps, schema_editor):
    call_command('loaddata', 'distros.yaml', app_label='device_registry')


class Migration(migrations.Migration):
    dependencies = [
        ('device_registry', '0068_auto_20191101_1017'),
    ]

    operations = [
        migrations.CreateModel(
            name='Distro',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('os_release_codename', models.CharField(max_length=64, unique=True)),
                ('end_of_life', models.DateField(blank=True, null=True)),
            ],
        ),
        migrations.RunPython(load_fixture),
        migrations.AlterField(
            model_name='distro',
            name='end_of_life',
            field=models.DateField(),
        )
    ]
