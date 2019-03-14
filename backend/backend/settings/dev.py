from backend.settings.base import *

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

COMMON_NAME_PREFIX = 'd.wott-dev.local'
STATIC_URL = 'http://localhost:8003/'
INSTALLED_APPS += ['django_extensions']