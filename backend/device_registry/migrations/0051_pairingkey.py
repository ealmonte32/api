# Generated by Django 2.1.10 on 2019-07-19 07:35

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('device_registry', '0050_deviceinfo_device_metadata'),
    ]

    operations = [
        migrations.CreateModel(
            name='PairingKey',
            fields=[
                ('key', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('comment', models.CharField(blank=True, max_length=512)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pairing_keys', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('created',),
            },
        ),
    ]