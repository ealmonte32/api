# Generated by Django 2.2.7 on 2019-11-14 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('device_registry', '0070_auto_20191112_1510'),
    ]

    operations = [
        migrations.AlterField(
            model_name='debpackage',
            name='source_name',
            field=models.CharField(db_index=True, max_length=128),
        ),
    ]
