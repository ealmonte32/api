# Generated by Django 2.1.10 on 2019-07-04 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profile_page', '0002_auto_20190605_1012'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='last_active',
            field=models.DateField(blank=True, null=True),
        ),
    ]
