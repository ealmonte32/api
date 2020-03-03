import device_registry.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.db.models import Case, CharField, Value, When


def update_default_credentials(apps, schema_editor):
    from device_registry.models import RecommendedActionStatus
    from device_registry.recommended_actions import DefaultCredentialsAction
    RecommendedActionStatus.update_all_devices(classes=[DefaultCredentialsAction])


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('device_registry', '0083_auto_20200226_0527'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='recommendedaction',
            unique_together={('action_class', 'action_param')},
        ),

        migrations.RemoveField(
            model_name='recommendedaction',
            name='action_id',
        ),
        migrations.RemoveField(
            model_name='recommendedaction',
            name='device',
        ),
        migrations.RemoveField(
            model_name='recommendedaction',
            name='resolved_at',
        ),
        migrations.RemoveField(
            model_name='recommendedaction',
            name='snoozed_until',
        ),
        migrations.RemoveField(
            model_name='recommendedaction',
            name='status',
        ),
        migrations.RunPython(update_default_credentials)
    ]