from backend.settings.base import *

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/tmp/db.sqlite3',
    }
}

COMMON_NAME_PREFIX = 'd.wott-dev.local'

# 3 parameters below are needed for views tests (they activate all url patterns).
IS_DASH = True
IS_API = True
IS_MTLS_API = True
