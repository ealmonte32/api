from backend.settings.base import *

if DEBUG:
    ALLOWED_HOSTS += [
        'localhost'
    ]

if IS_DASH or DEBUG:
    ALLOWED_HOSTS += [
        'dash.wott.io'
    ]

if IS_API or DEBUG:
    ALLOWED_HOSTS += [
        'api.wott.io'
    ]

if IS_MTLS_API or DEBUG:
    ALLOWED_HOSTS += [
        'mtls.wott.io'
    ]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'wott-backend'),
        'USER': os.getenv('DB_USER', 'wott-backend'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST', 'psql'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'OPTIONS': {
            'connect_timeout': 3,
        },
    }
}

COMMON_NAME_PREFIX = 'd.wott.local'
STATIC_URL = 'https://static.wott.io/'

# Sentry
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    sentry_sdk.init(SENTRY_DSN,integrations=[DjangoIntegration()])
