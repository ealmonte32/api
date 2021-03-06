# Generated by Django 2.2.5 on 2019-09-17 12:45

from django.conf import settings
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('device_registry', '0057_device_update_trust_score'),
    ]

    operations = [
        migrations.CreateModel(
            name='GlobalPolicy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=32)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('policy', models.PositiveSmallIntegerField(choices=[(1, 'Allow by default'), (2, 'Block by default')], verbose_name='firewall ports policy')),
                ('ports', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list)),
                ('networks', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=list)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='global_policies', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'global policy',
                'verbose_name_plural': 'global policies',
                'ordering': ['-pk'],
            },
        ),
        migrations.AddField(
            model_name='firewallstate',
            name='global_policy',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='device_registry.GlobalPolicy'),
        ),
        migrations.AddConstraint(
            model_name='globalpolicy',
            constraint=models.UniqueConstraint(fields=('name', 'owner'), name='unique_name'),
        ),
    ]
