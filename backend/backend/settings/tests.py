from backend.settings.base import *

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/tmp/db.sqlite3',
    }
}

COMMON_NAME_PREFIX = 'd.wott-dev.local'
