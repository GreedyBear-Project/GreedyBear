#!/bin/bash

# checking if DJANGO_SECRET is set and not empty
if [ -z "$DJANGO_SECRET" ]; then
    echo "ERROR: DJANGO_SECRET environment variable is not set!" >&2
    echo "Aborting startup." >&2
    exit 1
fi

until cd /opt/deploy/greedybear
do
    echo "Waiting for server volume..."
done

# Create DB cache tables for all DatabaseCache backends in settings.CACHES (idempotent)
python manage.py createcachetable

# Make durin migrations and migrate
python manage.py makemigrations durin
python manage.py migrate

# Collect static files, overwriting existing ones
python manage.py collectstatic --noinput --clear --verbosity 0

# Ensure log directories exist (volumes may persist from older builds)
mkdir -p /var/log/greedybear/gunicorn
mkdir -p /run/gunicorn
mkdir -p /var/lib/greedybear/quarantine

# Fix log file ownership (manage.py commands above run as root 
# and may create new log files owned by root instead of www-data)
chown -R www-data:www-data /var/log/greedybear /run/gunicorn /var/lib/greedybear/quarantine

# Obtain the current GreedyBear version number
GREEDYBEAR_VERSION=$(uv version --short)

echo "------------------------------"
echo "GreedyBear $GREEDYBEAR_VERSION"
echo "DEBUG: $DEBUG"
echo "DJANGO_TEST_SERVER: $DJANGO_TEST_SERVER"
echo "------------------------------"

if [ "$DJANGO_TEST_SERVER" = "True" ]; then
    # Dev mode: run as root (needed for hot-reload on volume-mounted source)
    exec "$@"
else
    # Production mode: drop privileges to www-data before starting Gunicorn
    exec gosu www-data "$@"
fi
