from backend.settings.base import *

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'wott-backend',
        'USER': 'postgres',
        'PASSWORD': 'SuperSecurePassword',
        'HOST': 'psql',
        'OPTIONS': {
            'connect_timeout': 3,
        }
    }
}

COMMON_NAME_PREFIX = 'd.wott-dev.local'

# 3 parameters below are needed for views tests (they activate all url patterns).
IS_DASH = True
IS_API = True
IS_MTLS_API = True
DASH_URL = 'https://example.com'
