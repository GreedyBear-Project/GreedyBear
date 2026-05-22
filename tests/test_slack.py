from unittest.mock import MagicMock, patch

from django.test import override_settings

from greedybear.slack import send_slack_message
from tests import CustomTestCase

TEST_LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
}


@override_settings(LOGGING=TEST_LOGGING)
class SendSlackMessageTests(CustomTestCase):
    @override_settings(SLACK_TOKEN="")
    @patch("greedybear.slack.WebClient")
    @patch("greedybear.slack.logger")
    def test_no_token_configured_logs_warning_and_skips(self, mock_logger, mock_webclient):
        send_slack_message("hello")

        mock_webclient.assert_not_called()
        mock_logger.warning.assert_called_once()

    @override_settings(SLACK_TOKEN="xoxb-test-token", DEFAULT_SLACK_CHANNEL="#alerts")
    @patch("greedybear.slack.WebClient")
    @patch("greedybear.slack.logger")
    def test_message_sent_successfully(self, mock_logger, mock_webclient):
        mock_client = MagicMock()
        mock_webclient.return_value = mock_client

        send_slack_message("test alert")

        mock_webclient.assert_called_once_with(token="xoxb-test-token")
        mock_client.chat_postMessage.assert_called_once_with(channel="#alerts", text="test alert", mrkdwn=True)
        mock_logger.exception.assert_not_called()

    @override_settings(SLACK_TOKEN="xoxb-test-token", DEFAULT_SLACK_CHANNEL="#alerts")
    @patch("greedybear.slack.WebClient")
    @patch("greedybear.slack.logger")
    def test_exception_is_logged_but_not_raised(self, mock_logger, mock_webclient):
        error = Exception("Slack API error")
        mock_client = MagicMock()
        mock_client.chat_postMessage.side_effect = error
        mock_webclient.return_value = mock_client

        send_slack_message("test alert")

        mock_logger.exception.assert_called_once()
