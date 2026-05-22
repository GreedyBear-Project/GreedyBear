# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
import os
import tomllib
from datetime import timedelta
from pathlib import Path

from django.core.management.utils import get_random_secret_key
from elasticsearch import Elasticsearch

BASE_DIR = Path(__file__).resolve().parent.parent
BASE_STATIC_PATH = BASE_DIR / "static"

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("DJANGO_SECRET", None) or get_random_secret_key()

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", "False") == "True"

DJANGO_LOG_DIRECTORY = "/var/log/greedybear/django"
ML_MODEL_DIRECTORY = BASE_DIR / "mlmodels"  # "/opt/deploy/greedybear/mlmodels"
ML_CONFIG_FILE = BASE_DIR / "configuration" / "ml_config.json"
MOCK_CONNECTIONS = os.environ.get("MOCK_CONNECTIONS", "False") == "True"
STAGE = os.environ.get("ENVIRONMENT", "production")
STAGE_PRODUCTION = STAGE == "production"
STAGE_LOCAL = STAGE == "local"
STAGE_CI = STAGE == "ci"

PUBLIC_DEPLOYMENT = os.environ.get("PUBLIC_DEPLOYMENT", "True") == "True"

AWS_REGION = os.environ.get("AWS_REGION")

ELASTIC_ENDPOINT = os.getenv("ELASTIC_ENDPOINT", "")
if ELASTIC_ENDPOINT:
    ELASTIC_ENDPOINT = ELASTIC_ENDPOINT.split(",")
else:
    print("WARNING!!! You need an ElasticSearch TPOT instance to have the Greedybear to work correctly.")
    if not DEBUG:
        print("you are in production mode: closing the application")
        exit(9)

if ELASTIC_ENDPOINT and not STAGE_CI:
    ELASTIC_CLIENT = Elasticsearch(
        ELASTIC_ENDPOINT,
        connections_per_node=20,
        retry_on_timeout=True,
        request_timeout=30,
    )
else:
    ELASTIC_CLIENT = None

SLACK_TOKEN = os.environ.get("SLACK_TOKEN", "")
DEFAULT_SLACK_CHANNEL = os.environ.get("DEFAULT_SLACK_CHANNEL", "")
NTFY_URL = os.environ.get("NTFY_URL", "")

with (BASE_DIR / "pyproject.toml").open("rb") as f:
    VERSION = tomllib.load(f)["project"]["version"]

CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True

# Prevent browsers from MIME-sniffing the content type, reducing
# the risk of drive-by downloads.
SECURE_CONTENT_TYPE_NOSNIFF = True

# Block framing of the site entirely to prevent clickjacking.
# XFrameOptionsMiddleware is already in the middleware stack but
# defaults to SAMEORIGIN; DENY is stricter and appropriate here
# because GreedyBear has no legitimate need to be framed.
X_FRAME_OPTIONS = "DENY"

HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "False") == "True"
if HTTPS_ENABLED:
    # Mark session and CSRF cookies as Secure so they are only
    # sent over HTTPS connections if HTTPS is enabled.
    # Allows local/CI environments to run plain HTTP.
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    # NOTE: SECURE_SSL_REDIRECT is intentionally omitted. TLS is
    # terminated at nginx, which already redirects HTTP -> HTTPS.
    # Enabling it here would cause an infinite redirect loop because
    # Django only sees plain HTTP from the gunicorn unix socket.

# Read DJANGO_ALLOWED_HOSTS from env (comma-separated).
# Falls back to ["*"] for backward compatibility.
# For security checks, see greedybear/checks.py.
_allowed_hosts_env = os.environ.get("DJANGO_ALLOWED_HOSTS", "")
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_env.split(",") if h.strip()] if _allowed_hosts_env else ["*"]

# certego_saas
HOST_URI = os.environ.get("HOST_URI", "http://localhost")
HOST_NAME = "GreedyBear"

# Application definition
INSTALLED_APPS = [
    # default
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    # rest framework libs
    "rest_framework",
    "api.apps.ApiConfig",
    # certego libs
    "durin",
    "certego_saas",
    "certego_saas.apps.auth",
    "certego_saas.apps.user",
    "certego_saas.apps.organization",
    # greedybear apps
    "greedybear.apps.GreedyBearConfig",
    "django_q",
    "authentication",
    # auth
    "rest_email_auth",
]

if os.environ.get("DJANGO_TEST_SERVER", "False") == "True":
    INSTALLED_APPS.append("django_watchfiles")

# required by the certego-saas, but GreedyBear doesn't use the recaptcha, for this reason is filled with a placeholder
DRF_RECAPTCHA_SECRET_KEY = "not-active"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    # Exception Handling
    "EXCEPTION_HANDLER": "certego_saas.ext.exceptions.custom_exception_handler",
    # Auth
    "DEFAULT_AUTHENTICATION_CLASSES": ["certego_saas.apps.auth.backend.CookieTokenAuthentication"],
    # Pagination
    "DEFAULT_PAGINATION_CLASS": "certego_saas.ext.pagination.CustomPageNumberPagination",
    "PAGE_SIZE": 10,
    # Throttling
    "DEFAULT_THROTTLE_RATES": {
        "feeds": os.environ.get("FEEDS_THROTTLE_RATE", "30/minute"),
        "feeds_advanced": os.environ.get("FEEDS_ADVANCED_THROTTLE_RATE", "100/minute"),
        "feeds_shared": os.environ.get("FEEDS_SHARED_THROTTLE_RATE", "10/minute"),
    },
    # Disable DRF's format suffix negotiation via ?format= query param,
    # since feeds endpoints handle the format parameter internally.
    "URL_FORMAT_OVERRIDE": None,
}

# Django-Rest-Durin
REST_DURIN = {
    "DEFAULT_TOKEN_TTL": timedelta(days=14),
    "TOKEN_CHARACTER_LENGTH": 32,
    "USER_SERIALIZER": "certego_saas.apps.user.serializers.UserSerializer",
    "AUTH_HEADER_PREFIX": "Token",
    "TOKEN_CACHE_TIMEOUT": 300,  # 5 minutes
    "REFRESH_TOKEN_ON_LOGIN": True,
    "API_ACCESS_CLIENT_NAME": "pygreedybear",
    "API_ACCESS_EXCLUDE_FROM_SESSIONS": True,
    "API_ACCESS_RESPONSE_INCLUDE_TOKEN": True,
    # not part of durin but used in data migration
    "API_ACCESS_CLIENT_TOKEN_TTL": timedelta(days=3650),
}

# django-rest-email-auth
REST_EMAIL_AUTH = {
    "EMAIL_VERIFICATION_URL": HOST_URI + "/verify-email?key={key}",
    "PASSWORD_RESET_URL": HOST_URI + "/reset-password?key={key}",
    "REGISTRATION_SERIALIZER": "authentication.serializers.RegistrationSerializer",
    "EMAIL_VERIFICATION_PASSWORD_REQUIRED": False,
    "EMAIL_SUBJECT_VERIFICATION": "GreedyBear - Please Verify Your Email Address",
    "EMAIL_SUBJECT_DUPLICATE": "GreedyBear - Registration Attempt",
    "PATH_TO_VERIFY_EMAIL_TEMPLATE": "authentication/emails/verify-email",
    "PATH_TO_DUPLICATE_EMAIL_TEMPLATE": "authentication/emails/duplicate-email",
    "PATH_TO_RESET_EMAIL_TEMPLATE": "authentication/emails/reset-password",
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "greedybear.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_STATIC_PATH / "reactapp"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "certego_saas.templates.context_processors.host",  # custom
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "greedybear.wsgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_NAME = os.environ.get("DB_NAME", "greedybear_db")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
        "TIMEOUT": 180,
        "CONN_MAX_AGE": 3600,
        "CONN_HEALTH_CHECKS": True,
    },
}

Q_CLUSTER = {
    "name": "greedybear_q",
    "workers": 1,
    "recycle": 500,
    "retry": 1860,  # Must be larger than timeout
    "timeout": 1800,  # 30 minutes
    "compress": True,
    "save_limit": 250,
    "queue_limit": 500,
    "cpu_affinity": 1,
    "label": "Django Q",
    "orm": "default",
    "cache": "django-q",
}

# Cache configuration
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greedybear-default",
    },
    "django-q": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "greedybear_cache",
    },
}

AUTH_USER_MODEL = "certego_saas_user.User"  # custom user model
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "certego_saas.apps.auth.backend.CookieTokenAuthentication",
]

# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
STATIC_ROOT = BASE_STATIC_PATH
STATICFILES_DIRS = [
    ("reactapp", "/var/www/reactapp"),
]


INFO_OR_DEBUG_LEVEL = "DEBUG" if DEBUG else "INFO"
LOGGING = (
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "stdfmt": {
                "format": "%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s",
            },
        },
        "handlers": {
            "django_q": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/django_q.log",
                "formatter": "stdfmt",
            },
            "django_q_error": {
                "level": "ERROR",
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/django_q_errors.log",
                "formatter": "stdfmt",
            },
            "elasticsearch": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/elasticsearch.log",
                "formatter": "stdfmt",
            },
            "api": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/api.log",
                "formatter": "stdfmt",
            },
            "api_error": {
                "level": "ERROR",
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/api_errors.log",
                "formatter": "stdfmt",
            },
            "greedybear": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/greedybear.log",
                "formatter": "stdfmt",
            },
            "greedybear_error": {
                "level": "ERROR",
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/greedybear_errors.log",
                "formatter": "stdfmt",
            },
            "django_unhandled_errors": {
                "level": "ERROR",
                "class": "logging.handlers.WatchedFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/django_errors.log",
                "formatter": "stdfmt",
            },
            "authentication": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.RotatingFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/authentication.log",
                "formatter": "stdfmt",
                "maxBytes": 20 * 1024 * 1024,
                "backupCount": 6,
            },
            "authentication_errors": {
                "level": "ERROR",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/authentication_errors.log",
                "formatter": "stdfmt",
                "maxBytes": 20 * 1024 * 1024,
                "backupCount": 6,
            },
            "rest_email_auth": {
                "level": INFO_OR_DEBUG_LEVEL,
                "class": "logging.handlers.RotatingFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/authentication.log",
                "formatter": "stdfmt",
                "maxBytes": 20 * 1024 * 1024,
                "backupCount": 6,
            },
            "rest_email_auth_errors": {
                "level": "ERROR",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": f"{DJANGO_LOG_DIRECTORY}/authentication_errors.log",
                "formatter": "stdfmt",
                "maxBytes": 20 * 1024 * 1024,
                "backupCount": 6,
            },
        },
        "loggers": {
            "django_q": {
                "handlers": ["django_q", "django_q_error"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
            "elasticsearch": {
                "handlers": ["elasticsearch"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
            "api": {
                "handlers": ["api", "api_error"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
            "authentication": {
                "handlers": ["authentication", "authentication_errors"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
            "greedybear": {
                "handlers": ["greedybear", "greedybear_error"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
            "django": {
                "handlers": ["django_unhandled_errors"],
                "level": "ERROR",
                "propagate": True,
            },
            "rest_email_auth": {
                "handlers": ["rest_email_auth", "rest_email_auth_errors"],
                "level": INFO_OR_DEBUG_LEVEL,
                "propagate": True,
            },
        },
    }
    if not STAGE_CI
    else {}
)

# disable some really noisy logs
es_logger = logging.getLogger("elasticsearch")
if DEBUG:
    es_logger.setLevel(logging.INFO)
else:
    es_logger.setLevel(logging.WARNING)

# email
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL")
DEFAULT_EMAIL = os.environ.get("DEFAULT_EMAIL")
AWS_SES = os.environ.get("AWS_SES", "False") == "True"

if STAGE_LOCAL:
    # The console backend writes the emails that would be sent to the standard output
    # https://docs.djangoproject.com/en/4.1/topics/email/#console-backend
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
elif STAGE_CI:
    # force in-memory backend for tests/internal deployments
    # https://docs.djangoproject.com/en/2.1/topics/email/#in-memory-backend
    # https://docs.djangoproject.com/en/2.1/topics/testing/tools/#topics-testing-email
    EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
else:
    if AWS_SES:
        # Use amazon SES via django-ses
        # see: https://github.com/django-ses/django-ses
        EMAIL_BACKEND = "django_ses.SESBackend"
        AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
        AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
        AWS_SES_REGION_NAME = AWS_REGION
        AWS_SES_REGION_ENDPOINT = f"email.{AWS_SES_REGION_NAME}.amazonaws.com"
    else:
        EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
        EMAIL_HOST = os.environ.get("EMAIL_HOST")
        EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
        EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
        EMAIL_PORT = os.environ.get("EMAIL_PORT")
        EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "False") == "True"
        EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "False") == "True"


EXTRACTION_INTERVAL = int(os.environ.get("EXTRACTION_INTERVAL", 10))
if EXTRACTION_INTERVAL < 1 or EXTRACTION_INTERVAL > 60:
    raise ValueError(f"EXTRACTION_INTERVAL must be between 1 and 60 minutes, got {EXTRACTION_INTERVAL}")
if 60 % EXTRACTION_INTERVAL:
    raise ValueError(f"EXTRACTION_INTERVAL must be a divisor of 60, got {EXTRACTION_INTERVAL}")
INITIAL_EXTRACTION_TIMESPAN = int(os.environ.get("INITIAL_EXTRACTION_TIMESPAN", 60 * 24 * 3))  # 3 days
CLUSTER_COWRIE_COMMAND_SEQUENCES = os.environ.get("CLUSTER_COWRIE_COMMAND_SEQUENCES", "False") == "True"

IOC_RETENTION = int(os.environ.get("IOC_RETENTION", "3650"))
COWRIE_SESSION_RETENTION = int(os.environ.get("COWRIE_SESSION_RETENTION", "365"))
COMMAND_SEQUENCE_RETENTION = int(os.environ.get("COMMAND_SEQUENCE_RETENTION", "365"))
STATISTICS_RETENTION = 730

TRENDING_MAX_WINDOW_MINUTES = int(os.environ.get("TRENDING_MAX_WINDOW_MINUTES", str((24 * 31 * 60) // 2)))
TRENDING_BUCKET_RETENTION_HOURS = int(os.environ.get("TRENDING_BUCKET_RETENTION_HOURS", str(24 * 31)))

THREATFOX_API_KEY = os.environ.get("THREATFOX_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Optional feed license URL to include in API responses
# If not set, no license information will be included in feeds
FEEDS_LICENSE = os.environ.get("FEEDS_LICENSE", "")

# Project test runner
TEST_RUNNER = "tests.test_runner.CustomTestRunner"
