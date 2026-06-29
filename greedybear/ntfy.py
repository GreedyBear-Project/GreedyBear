import logging

from django.conf import settings

from greedybear.cronjobs.http_client import HttpClient

logger = logging.getLogger(__name__)


def send_ntfy_message(message):
    if not settings.NTFY_URL:
        logger.warning("ntfy is not configured, message not sent")
        return

    headers = {
        "Title": "GreedyBear Error",
        "Priority": "4",
        "Tags": "warning",
        "Markdown": "yes",
    }

    try:
        with HttpClient() as client:
            client.post(
                settings.NTFY_URL,
                data=message.encode("utf-8"),
                headers=headers,
                timeout=(1, 2),
            )

    except Exception:
        logger.exception("Failed to send ntfy message")
