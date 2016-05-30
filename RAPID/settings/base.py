import json
from django.core.exceptions import ImproperlyConfigured
from unipath import Path


BASE_DIR = Path(__file__).ancestor(3)
MEDIA_ROOT = BASE_DIR.child("media")
STATIC_ROOT = BASE_DIR.child("static")
TEMPLATE_ROOT = BASE_DIR.child("templates")

STATICFILES_DIRS = (
    STATIC_ROOT.child("css"),
    STATIC_ROOT.child("js"),
    STATIC_ROOT.child("bootstrap-3.3.2"),
    STATIC_ROOT.child("bootstrap-select-1.7.3"),
    STATIC_ROOT.child("DataTables-1.10.5"),
)

TEMPLATE_DIRS = (
    TEMPLATE_ROOT,
)

ROOT_URLCONF = "RAPID.urls"
WSGI_APPLICATION = 'RAPID.wsgi.application'

MEDIA_URL = "/media/"
STATIC_URL = "/static/"

# Open JSON-based secrets module
with open("secrets.json", "r") as f:
    secrets = json.loads(f.read())


def retrieve_secret_configuration(setting, config=secrets):
    """
    :param setting: JSON key for desired / requested configuration
    :param config: JSON element / file containing all sensitive configurations
    :return: configuration
    """

    try:
        return config[setting]
    except KeyError:
        error_msg = "Set the {0} environment variable".format(setting)
        raise ImproperlyConfigured(error_msg)


SECRET_KEY = retrieve_secret_configuration("SECRET_KEY")
AUTH_USER_MODEL = 'profiles.Profile'

# Third-party service settings
IID_USER = retrieve_secret_configuration("IID_USER")
IID_PASS = retrieve_secret_configuration("IID_PASS")
PASSIVE_TOTAL_API = retrieve_secret_configuration("PASSIVE_TOTAL_API")
CENSYS_API_ID = retrieve_secret_configuration("CENSYS_API_ID")
CENSYS_API_SECRET = retrieve_secret_configuration("CENSYS_API_SECRET")
TOTAL_HASH_API_ID = retrieve_secret_configuration("TOTAL_HASH_API_ID")
TOTAL_HASH_SECRET = retrieve_secret_configuration("TOTAL_HASH_SECRET")
MALWR_LOGIN_ID = retrieve_secret_configuration("MALWR_LOGIN_ID")
MALWR_LOGIN_SECRET = retrieve_secret_configuration("MALWR_LOGIN_SECRET")
GOOGLE_SAFEBROWSING_API_KEY = retrieve_secret_configuration("GOOGLE_SAFEBROWSING_API_KEY")
GOOGLE_SAFEBROWSING_API_CLIENT = retrieve_secret_configuration("GOOGLE_SAFEBROWSING_API_CLIENT")
GOOGLE_SAFEBROWSING_URL = "https://www.google.com/transparencyreport/safebrowsing/diagnostic/?hl=en#url="

# Database setting variables
SQL_NAME = retrieve_secret_configuration("SQL_NAME")
SQL_USER = retrieve_secret_configuration("SQL_USER")
SQL_PASS = retrieve_secret_configuration("SQL_PASS")
SQL_HOST = retrieve_secret_configuration("SQL_HOST")
SQL_PORT = 5432

# Database Settings
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': SQL_NAME,
        'USER': SQL_USER,
        'PASSWORD': SQL_PASS,
        'HOST': SQL_HOST,
        'PORT': SQL_PORT,
    }
}


INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'widget_tweaks',
    'core',
    'profiles',
    'pivoteer',
    'monitors',
    'unit_tests',
    'integration_tests',
)


MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)


TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.request',
    'django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
)