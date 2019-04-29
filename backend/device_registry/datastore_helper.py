import json
import logging
import os
from google.cloud import datastore
from google.oauth2 import service_account


logger = logging.getLogger(__name__)


if 'DATASTORE_KEY_JSON' in os.environ:
    key_json = json.loads(os.environ['DATASTORE_KEY_JSON'])
    creds = service_account.Credentials.from_service_account_info(key_json)
    datastore_client = datastore.Client(credentials=creds, project=key_json.get('project_id'))
else:
    datastore = None
    datastore_client = None
