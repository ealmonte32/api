"""
Django settings for backend project.

Generated by 'django-admin startproject' using Django 2.1.5.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""

import os
import socket
import re

from netaddr import IPNetwork, AddrFormatError
from celery.schedules import crontab


def check_ip_range(ipr):
    try:
        _ = IPNetwork(ipr)
    except AddrFormatError:
        return False
    return True


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_DIR = os.path.dirname(os.path.dirname(BASE_DIR))

# Load spam networks list from the local file.
# TODO: Load this list from its original site.
spam_networks_list_path = os.path.join(REPO_DIR, 'misc', 'spam_networks.txt')
with open(spam_networks_list_path) as f:
    read_data = f.read()
spam_networks_list = re.findall(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.0/\d{1,2}).*', read_data, re.MULTILINE)
SPAM_NETWORKS = [[addr, False] for addr in filter(check_ip_range, spam_networks_list)]

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv(
    'SECRET_KEY',
    '3y(yuq&dt*2nhl_)iv9^a_&-d97zw3)*btf(ano43p=krwcfe4'
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = bool(int(os.getenv('DEBUG', "0")))

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'registration',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_json_widget',
    'rest_framework',
    'rest_framework.authtoken',
    'tagulous',
    'device_registry.apps.DeviceRegistryConfig',
    'profile_page.apps.ProfilePageConfig',
    'monitoring.apps.MonitoringConfig',
    'bootstrap4',
    'phonenumber_field'
]

MIDDLEWARE = [
    'device_registry.middleware.HealthCheckMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'profile_page.middleware.UserActivityMiddleware'
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'device_registry.context_processors.webpack_bundle'
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases

# Configured in overrides

# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LOGIN_REDIRECT_URL = 'root'
LOGOUT_REDIRECT_URL = 'auth_login'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework.authentication.SessionAuthentication'],
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
    'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer'],
    'DEFAULT_PARSER_CLASSES': ['rest_framework.parsers.JSONParser'],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
}

# App configurations
CFSSL_SERVER = os.getenv('CFSSL_SERVER', '127.0.0.1')
CFSSL_PORT = int(os.getenv('CFSSL_PORT', 8888))

# SMTP
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.sendgrid.net'
EMAIL_HOST_USER = 'apikey'
EMAIL_HOST_PASSWORD = os.getenv('SMTP_PASSWORD')
EMAIL_PORT = 2525

# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': '{asctime} {module} {funcName} {process:d} {thread:d} {message}',
            'style': '{',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'ERROR'),
        },
    },
}

# Role definition based on hostnames
IS_API = socket.gethostname().startswith('api-')
IS_MTLS_API = socket.gethostname().startswith('mtls-api-')
IS_DASH = socket.gethostname().startswith('dash-')
IS_CELERY = socket.gethostname().startswith('celery')

IS_DEV = False

USE_NATIVE_JSONFIELD = True

# Sentry
SENTRY_DSN = os.getenv('SENTRY_DSN')
if SENTRY_DSN:
    import sentry_sdk

    with open(os.path.join(REPO_DIR, 'release.txt'), 'r') as release_file:
        release = release_file.read().strip()

    from sentry_sdk.integrations.django import DjangoIntegration

    sentry_sdk.init(SENTRY_DSN, integrations=[DjangoIntegration()], release=release)

# 'tagulous'
SERIALIZATION_MODULES = {
    'xml': 'tagulous.serializers.xml_serializer',
    'json': 'tagulous.serializers.json',
    'python': 'tagulous.serializers.python',
    'yaml': 'tagulous.serializers.pyyaml',
}

# `django-registration-redux` 3rd party app settings.
INCLUDE_REGISTER_URL = False

# Retry to connect to DB (after receiving a connection error) within 60 seconds.
DB_RETRY_TO_CONNECT_SEC = 60

# Celery settings.
CELERY_BROKER_URL = 'redis://%s%s:%i/0' % (
    ':{}@'.format(os.getenv('REDIS_PASSWORD')) if os.getenv('REDIS_PASSWORD', False) else '',
    os.getenv('REDIS_HOST', 'redis'),
    int(os.getenv('REDIS_PORT', '6379'))
)

CELERY_BEAT_SCHEDULE = {
    'update_celery_pulse_timestamp': {
        'task': 'monitoring.tasks.update_celery_pulse_timestamp',
        'schedule': crontab()  # Execute once a minute.
    },
    'send_devices_to_trust_score_update': {
        'task': 'device_registry.tasks.send_devices_to_trust_score_update',
        'schedule': crontab(minute='*/3')  # Execute every 3 minutes.
    },
    'fetch_vulnerabilities_debian': {
        'task': 'device_registry.tasks.fetch_vulnerabilities_debian',
        'schedule': crontab(hour=15, minute=0)  # Execute once a day at 3PM.
    },
    'fetch_vulnerabilities_ubuntu': {
        'task': 'device_registry.tasks.fetch_vulnerabilities_ubuntu',
        'schedule': crontab(hour=16, minute=0)  # Execute once a day at 4PM.
    },
    'send_packages_to_vulns_update': {
        'task': 'device_registry.tasks.send_packages_to_vulns_update',
        'schedule': crontab(minute='*/3')  # Execute every 3 minutes.
    },
    'file_github_issues': {
        'task': 'device_registry.tasks.file_github_issues',
        'schedule': crontab(hour='*/6', minute=0)  # Execute every 6 hours.
    },
    'sample_history': {
        'task': 'device_registry.tasks.sample_history',
        'schedule': crontab(hour=17, minute=0)  # Execute once a day at 5PM.
    }
}

# Mixpanel token
MIXPANEL_TOKEN = os.getenv('MIXPANEL_TOKEN', '')

# Redis connection settings
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

# The following data can be obtained at https://github.com/settings/apps/wott-bot
GITHUB_APP_PEM = os.getenvb(b'GITHUB_APP_PEM')  # Github app private key, either raw or escape-encoded
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')    # Github App ID
GITHUB_APP_NAME = os.getenv('GITHUB_APP_NAME')  # Github app name (wott-bot)
GITHUB_APP_CLIENT_ID = os.getenv('GITHUB_APP_CLIENT_ID')  # Github app Client ID
GITHUB_APP_CLIENT_SECRET = os.getenv('GITHUB_APP_CLIENT_SECRET')    # Github App Client Secret
GITHUB_APP_REDIRECT_URL = os.getenv('GITHUB_APP_REDIRECT_URL')    # Github App Redirect URL

MAX_WEEKLY_RA = 5
