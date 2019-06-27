import datetime

from google.cloud import bigquery
from django.core.management.base import BaseCommand

from device_registry.models import Device
from profile_page.models import Profile


PROJECT_ID = 'wott-244904'
DATASET_ID = 'wott_api'
TABLE_ID = 'metrics'


class Command(BaseCommand):

    def handle(self, *args, **options):
        nprofiles = Profile.objects.count()
        ndevices = Device.objects.count()
        print(f'profiles: {nprofiles} devices: {ndevices}')

        client = bigquery.Client()
        dataset = bigquery.Dataset(f'{PROJECT_ID}.{DATASET_ID}')
        dataset = client.create_dataset(dataset, exists_ok=True)

        schema = [
            bigquery.SchemaField("time", "DATETIME", mode="REQUIRED"),
            bigquery.SchemaField("all_devices", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("all_users", "INTEGER", mode="REQUIRED")
        ]
        table = bigquery.Table(f'{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}', schema=schema)
        table = client.create_table(table, exists_ok=True)

        client.insert_rows(table, [{
            'time': datetime.datetime.utcnow(),
            'all_devices': ndevices,
            'all_users': nprofiles
        }])

    def add_arguments(self, parser):
        parser.add_argument(
            '-s',
            '--short',
            action='store_true',
            default=False,
            help='Test option'
        )
