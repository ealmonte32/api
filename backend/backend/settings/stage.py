from backend.settings.base import *

ALLOWED_HOSTS += [
    'localhost',
    'dash-stage.wott.io',
    'api-stage.wott.io',
    'mtls-stage.stage.wott.io'
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'wott-backend'),
        'USER': os.getenv('DB_USER', 'wott-backend'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST', 'psql'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

COMMON_NAME_PREFIX = 'd.wott-stage.local'

# Sentry
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    sentry_sdk.init(SENTRY_DSN,integrations=[DjangoIntegration()])
