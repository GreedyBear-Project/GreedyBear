from unittest.mock import MagicMock, patch

from django.test import override_settings

from greedybear.ntfy import send_ntfy_message
from tests import CustomTestCase

TEST_LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
}


@override_settings(LOGGING=TEST_LOGGING)
class SendNtfyMessageTests(CustomTestCase):
    @override_settings(NTFY_URL="https://ntfy.sh/greedybear")
    @patch("greedybear.ntfy.requests.post")
    @patch("greedybear.ntfy.logger")
    def test_happy_path_successful_post(self, mock_logger, mock_post):
        message = "Something went wrong"

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        send_ntfy_message(message)

        mock_post.assert_called_once_with(
            "https://ntfy.sh/greedybear",
            data=message.encode("utf-8"),
            headers={
                "Title": "GreedyBear Error",
                "Priority": "4",
                "Tags": "warning",
                "Markdown": "yes",
            },
            timeout=(1, 2),
        )
        mock_logger.exception.assert_not_called()

    @override_settings(NTFY_URL="https://ntfy.sh/greedybear")
    @patch("greedybear.ntfy.requests.post")
    def test_happy_path_non_ascii_message(self, mock_post):
        message = "⚠️ Über-alert"

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        send_ntfy_message(message)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"], message.encode("utf-8"))

    @override_settings(NTFY_URL="")
    @patch("greedybear.ntfy.requests.post")
    @patch("greedybear.ntfy.logger")
    def test_no_url_configured_logs_warning_and_skips_post(self, mock_logger, mock_post):
        send_ntfy_message("anything")

        mock_post.assert_not_called()
        mock_logger.warning.assert_called_once()

    @override_settings(NTFY_URL="https://ntfy.sh/greedybear")
    @patch("greedybear.ntfy.requests.post")
    @patch("greedybear.ntfy.logger")
    def test_http_error_logged_but_not_raised(self, mock_logger, mock_post):
        error = Exception("HTTP 500")

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = error
        mock_post.return_value = mock_response

        send_ntfy_message("msg")

        mock_logger.exception.assert_called_once()

    @override_settings(NTFY_URL="https://ntfy.sh/greedybear")
    @patch("greedybear.ntfy.requests.post")
    @patch("greedybear.ntfy.logger")
    def test_network_error_logged_but_not_raised(self, mock_logger, mock_post):
        error = TimeoutError("timeout")
        mock_post.side_effect = error

        send_ntfy_message("msg")

        mock_logger.exception.assert_called_once()
