"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application
from django.db.backends.base import base as django_db_base

from .utils import ensure_connection_with_retries

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings.base')

# Patch the standard django database connection class' method in order to try to
# connect to DB multiple times using exponential backoff algorithm until success
# or the end of time allowed to spend on reconnection attempts
# (settings.DB_RETRY_TO_CONNECT_SEC).
django_db_base.BaseDatabaseWrapper.ensure_connection = ensure_connection_with_retries

application = get_wsgi_application()
