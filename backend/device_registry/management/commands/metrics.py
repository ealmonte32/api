import os
from statistics import mean

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone

from google.cloud import bigquery
from google.api_core.exceptions import NotFound

from device_registry import google_cloud_helper
from device_registry.models import Device

DATASET = os.getenv('WOTT_METRICS_DATASET', 'wott_api')
TABLE = os.getenv('WOTT_METRICS_TABLE', 'metrics')


class Command(BaseCommand):
    """
    Write metrics info into the Google BigQuery table.

    Known issues:
    - Just after the table creation or its schema update the platform silently
     ignores the `insert_rows` command and writes nothing. It usually lasts up to 1m.
     Then everything works fine.
    """

    def handle(self, *args, **options):
        def average_trust_score(devices):
            scores = [d.trust_score for d in devices if d.trust_score is not None]
            return mean(scores) if scores else 0

        now = timezone.now()
        today = now.date()
        month_ago_date = today - timezone.timedelta(days=30)
        week_ago_date = today - timezone.timedelta(days=7)
        day_ago_date = today - timezone.timedelta(days=1)
        week_ago = now - timezone.timedelta(days=7)

        all_users = User.objects.count()
        all_devices = Device.objects.count()
        claimed_devices = Device.objects.exclude(owner__isnull=True).count()
        active_users_monthly = User.objects.filter(profile__last_active__gte=month_ago_date).count()
        active_users_weekly = User.objects.filter(profile__last_active__gte=week_ago_date).count()
        active_users_daily = User.objects.filter(profile__last_active__gte=day_ago_date).count()
        active_devices = Device.objects.filter(last_ping__gte=week_ago)
        inactive_devices = Device.objects.filter(last_ping__lt=week_ago)
        metrics = {
            'time': now,
            'all_devices': all_devices,
            'claimed_devices': claimed_devices,
            'all_users': all_users,
            'active_users_monthly': active_users_monthly,
            'active_users_weekly': active_users_weekly,
            'active_users_daily': active_users_daily,
            'active_devices': active_devices.count(),
            'avg_score_active': average_trust_score(active_devices),
            'avg_score_inactive': average_trust_score(inactive_devices)
        }
        print(metrics)

        client = bigquery.Client(project=google_cloud_helper.project,
                                 credentials=google_cloud_helper.credentials)
        client.create_dataset(bigquery.Dataset(f'{google_cloud_helper.project}.{DATASET}'), exists_ok=True)

        # !!! Currently only adding (at the end of the list!) new fields allowed.
        # Modification and deletion are not supported by the automated schema migration handler.
        # Newly added fields should not have `mode` parameter set!
        schema = [
            bigquery.SchemaField("time", "DATETIME", mode="REQUIRED", description='Time of this sample'),
            bigquery.SchemaField("all_devices", "INTEGER", mode="REQUIRED", description='Registered devices'),
            bigquery.SchemaField("all_users", "INTEGER", mode="REQUIRED", description='All Users'),
            bigquery.SchemaField("active_users_monthly", "INTEGER", mode="REQUIRED",
                                 description='Users who have been signed in in the last 30 days'),
            bigquery.SchemaField("active_users_daily", "INTEGER", mode="REQUIRED",
                                 description='Users who have been signed in in the last 24 hours'),
            bigquery.SchemaField("active_devices", "INTEGER", mode="REQUIRED",
                                 description='Devices who have pinged in the last 7 days'),
            bigquery.SchemaField("avg_score_active", "FLOAT", mode="REQUIRED",
                                 description='Average Trust Score of active devices'),
            bigquery.SchemaField("avg_score_inactive", "FLOAT", mode="REQUIRED",
                                 description='Average Trust Score of inactive devices'),
            bigquery.SchemaField("claimed_devices", "INTEGER", description='Claimed devices'),
            bigquery.SchemaField("active_users_weekly", "INTEGER",
                                 description='Users who have been signed in in the last 7 days')
        ]
        print(f'{google_cloud_helper.project}.{DATASET}.{TABLE}')

        # Try to get existing table.
        table_ref = client.dataset(DATASET).table(TABLE)
        try:
            table = client.get_table(table_ref)
        except NotFound:
            # Create a new table.
            table = bigquery.Table(f'{google_cloud_helper.project}.{DATASET}.{TABLE}', schema=schema)
            table = client.create_table(table)
            print('Created a new table')
        else:
            if table.schema != schema:
                # Update existing table schema.
                table.schema = schema
                table = client.update_table(table, ["schema"])
                print('Updated table schema')
        print(f'{table}')
        result = client.insert_rows(table, [metrics])
        print(f'DONE: {result}')
