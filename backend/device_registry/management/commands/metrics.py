import datetime
import json
import os
from statistics import mean

from google.cloud import bigquery

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone

from device_registry import google_cloud_helper
from device_registry.models import Device


PROJECT = os.getenv('WOTT_METRICS_PROJECT', 'wott-244904')
DATASET = os.getenv('WOTT_METRICS_DATASET','wott_api')
TABLE = os.getenv('WOTT_METRICS_TABLE', 'metrics')


class Command(BaseCommand):

    def handle(self, *args, **options):
        def average_trust_score(devices):
            scores = [d.trust_score for d in devices]
            scores = [s for s in scores if s is not None]
            return mean(scores) if scores else 0

        day_ago = timezone.now() - datetime.timedelta(hours=24)
        week_ago = timezone.now() - datetime.timedelta(days=7)
        month_ago = timezone.now() - datetime.timedelta(days=30)
        all_users = User.objects.count()
        all_devices = Device.objects.count()
        active_users_monthly = User.objects.filter(last_login__gte=month_ago).count()
        active_users_daily = User.objects.filter(last_login__gte=day_ago).count()
        active_devices = Device.objects.filter(last_ping__gte=week_ago)
        inactive_devices = Device.objects.filter(last_ping__lt=week_ago)
        metrics = {
            'time': datetime.datetime.utcnow(),
            'all_devices': all_devices,
            'all_users': all_users,
            'active_users_monthly': active_users_monthly,
            'active_users_daily': active_users_daily,
            'active_devices': len(active_devices),
            'avg_score_active': average_trust_score(active_devices),
            'avg_score_inactive': average_trust_score(inactive_devices)
        }
        print(metrics)

        client = bigquery.Client(project=google_cloud_helper.project,
                                 credentials=google_cloud_helper.credentials)
        dataset = bigquery.Dataset(f'{PROJECT}.{DATASET}')
        dataset = client.create_dataset(dataset, exists_ok=True)

        schema = [
            bigquery.SchemaField("time", "DATETIME", mode="REQUIRED", description='Time of this sample'),
            bigquery.SchemaField("all_devices", "INTEGER", mode="REQUIRED", description='Registered devices	'),
            bigquery.SchemaField("all_users", "INTEGER", mode="REQUIRED", description='All Users'),
            bigquery.SchemaField("active_users_monthly", "INTEGER", mode="REQUIRED", description='Users who have been signed in in the last 30 days'),
            bigquery.SchemaField("active_users_daily", "INTEGER", mode="REQUIRED", description='Users who have been signed in in the last 24 hours'),
            bigquery.SchemaField("active_devices", "INTEGER", mode="REQUIRED", description='Devices who have pinged in the last 7 days'),
            bigquery.SchemaField("avg_score_active", "INTEGER", mode="REQUIRED", description='Average Trust Score of active devices'),
            bigquery.SchemaField("avg_score_inactive", "INTEGER", mode="REQUIRED", description='Average Trust Score of inactive devices'),
        ]
        print(f'{PROJECT}.{DATASET}.{TABLE}')
        table = bigquery.Table(f'{PROJECT}.{DATASET}.{TABLE}', schema=schema)
        table = client.create_table(table, exists_ok=True)
        print(f'{table}')

        client.insert_rows(table, [{
            'time': datetime.datetime.utcnow(),
            'all_devices': all_devices,
            'all_users': all_users,
            'active_users_monthly': active_users_monthly,
            'active_users_daily': active_users_daily,
            'active_devices': len(active_devices),
            'avg_score_active': average_trust_score(active_devices),
            'avg_score_inactive': average_trust_score(inactive_devices)
        }])

    def add_arguments(self, parser):
        parser.add_argument(
            '-s',
            '--short',
            action='store_true',
            default=False,
            help='Test option'
        )
