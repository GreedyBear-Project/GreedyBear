# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.conf import settings
from django.core.checks import Tags, register
from django.core.checks import Warning as CheckWarning


@register(Tags.security, deploy=True)
def check_allowed_hosts_wildcard(app_configs, **kwargs):
    """Warn when ALLOWED_HOSTS contains a wildcard entry."""
    errors = []
    if "*" in settings.ALLOWED_HOSTS:
        errors.append(
            CheckWarning(
                "ALLOWED_HOSTS contains a wildcard ('*').",
                hint="Set the DJANGO_ALLOWED_HOSTS environment variable to a comma-separated list of valid hostnames for production.",
                id="greedybear.W001",
            )
        )
    return errors
