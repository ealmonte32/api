from backend.settings.base import *

DEBUG = True

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
        }
    }
}
COMMON_NAME_PREFIX = 'd.wott-dev.local'
STATIC_URL = 'http://localhost:8003/'

INSTALLED_APPS += [
    'django_extensions'
]

IS_DEV = True
# IS_API = IS_DEV = IS_DASH = IS_MTLS_API = True

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

DASH_URL = 'http://localhost:8000'
ALLOWED_HOSTS = ['*']
