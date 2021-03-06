from backend.settings.base import *

if DEBUG:
    ALLOWED_HOSTS += [
        'localhost'
    ]

DASH_URL = 'https://dash.wott.io'

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

INSTALLED_APPS += [
    'django_prometheus',
]

MIDDLEWARE += [
    'allow_cidr.middleware.AllowCIDRMiddleware'
]

ALLOWED_CIDR_NETS = ['10.36.0.0/14']

# This must go first
MIDDLEWARE.insert(0, 'django_prometheus.middleware.PrometheusBeforeMiddleware')

# This should go last
MIDDLEWARE.append('django_prometheus.middleware.PrometheusAfterMiddleware')

DATABASES = {
    'default': {
        'ENGINE': 'django_prometheus.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'wott-backend'),
        'USER': os.getenv('DB_USER', 'wott-backend'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST', 'psql'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'OPTIONS': {
            'connect_timeout': 65,
        },
    }
}

COMMON_NAME_PREFIX = 'd.wott.local'
STATIC_URL = 'https://static.wott.io/'

GITHUB_IMMEDIATE_SYNC = True
