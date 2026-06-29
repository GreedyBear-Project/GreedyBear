#!/bin/bash

# Fix mlmodels and honeypot payloads ownership (volumes may retain files owned by a previous UID)
chown -R www-data:www-data /opt/deploy/greedybear/mlmodels /var/lib/greedybear/quarantine

if [ "$DJANGO_TEST_SERVER" = "True" ]; then
    # Dev mode: run as root (needed for hot-reload on volume-mounted source)
    exec "$@"
else
    # Production mode: drop privileges to www-data before starting qcluster
    exec gosu www-data "$@"
fi
