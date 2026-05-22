# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.conf import settings
from slack_sdk import WebClient

logger = logging.getLogger(__name__)


def send_slack_message(text):
    if not settings.SLACK_TOKEN:
        logger.warning("Slack is not configured, message not sent")
        return

    try:
        slack_token = settings.SLACK_TOKEN
        channel = settings.DEFAULT_SLACK_CHANNEL
        sc = WebClient(token=slack_token)

        sc.chat_postMessage(channel=channel, text=text, mrkdwn=True)

    except Exception:
        logger.exception("Failed to send Slack message")
