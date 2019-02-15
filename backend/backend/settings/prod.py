from backend.settings.base import *

ALLOWED_HOSTS += [
    'localhost',
    'dash.wott.io',
    'api.wott.io',
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

DEBUG = bool(int(os.getenv('DEBUG', "0")))
