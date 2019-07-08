import os
from statistics import mean

from google.cloud import bigquery
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone

from device_registry import google_cloud_helper
from device_registry.models import Device

DATASET = os.getenv('WOTT_METRICS_DATASET', 'wott_api')
TABLE = os.getenv('WOTT_METRICS_TABLE', 'metrics')


class Command(BaseCommand):

    def handle(self, *args, **options):
        def average_trust_score(devices):
            scores = [d.trust_score for d in devices]
            scores = [s for s in scores if s is not None]
            return mean(scores) if scores else 0

        now = timezone.now()
        today = now.date()
        month_ago_date = today - timezone.timedelta(days=30)
        day_ago_date = today - timezone.timedelta(days=1)
        week_ago = now - timezone.timedelta(days=7)

        all_users = User.objects.count()
        all_devices = Device.objects.count()
        active_users_monthly = User.objects.filter(profile__last_active__gte=month_ago_date).count()
        active_users_daily = User.objects.filter(profile__last_active__gte=day_ago_date).count()
        active_devices = Device.objects.filter(last_ping__gte=week_ago)
        inactive_devices = Device.objects.filter(last_ping__lt=week_ago)
        metrics = {
            'time': now,
            'all_devices': all_devices,
            'all_users': all_users,
            'active_users_monthly': active_users_monthly,
            'active_users_daily': active_users_daily,
            'active_devices': active_devices.count(),
            'avg_score_active': average_trust_score(active_devices),
            'avg_score_inactive': average_trust_score(inactive_devices)
        }
        print(metrics)

        client = bigquery.Client(project=google_cloud_helper.project,
                                 credentials=google_cloud_helper.credentials)
        client.create_dataset(bigquery.Dataset(f'{google_cloud_helper.project}.{DATASET}'), exists_ok=True)

        schema = [
            bigquery.SchemaField("time", "DATETIME", mode="REQUIRED", description='Time of this sample'),
            bigquery.SchemaField("all_devices", "INTEGER", mode="REQUIRED", description='Registered devices	'),
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
        ]
        print(f'{google_cloud_helper.project}.{DATASET}.{TABLE}')
        table = bigquery.Table(f'{google_cloud_helper.project}.{DATASET}.{TABLE}', schema=schema)
        table = client.create_table(table, exists_ok=True)
        print(f'{table}')

        result = client.insert_rows(table, [metrics])
        print(f'DONE: {result}')
