from unittest.mock import Mock, patch

import requests
from django.test import TestCase

from greedybear.cronjobs.client import HttpClient


class TestHttpClient(TestCase):
    def setUp(self):
        self.client = HttpClient(default_timeout=5.0)

    @patch("requests.Session.request")
    def test_default_timeout_applied(self, mock_request):
        """Test that the default timeout is applied when no timeout is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        self.client.get("https://example.com")

        mock_request.assert_called_once_with("GET", "https://example.com", timeout=5.0)

    @patch("requests.Session.request")
    def test_custom_timeout_override(self, mock_request):
        """Test that a custom timeout overrides the default."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        self.client.get("https://example.com", timeout=15.0)

        mock_request.assert_called_once_with("GET", "https://example.com", timeout=15.0)

    @patch("requests.Session.request")
    def test_raise_for_status_called(self, mock_request):
        """Test that raise_for_status is automatically called."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_request.return_value = mock_response

        with self.assertRaises(requests.HTTPError):
            self.client.get("https://example.com")

        mock_response.raise_for_status.assert_called_once()

    @patch("requests.Session.request")
    def test_post_request(self, mock_request):
        """Test that post requests work and apply defaults."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        payload = {"key": "value"}
        self.client.post("https://example.com", json=payload)

        mock_request.assert_called_once_with("POST", "https://example.com", data=None, json=payload, timeout=5.0)

    def test_context_manager(self):
        """Test that the client can be used as a context manager."""
        with patch("requests.Session.close") as mock_close:
            with HttpClient() as client:
                self.assertIsInstance(client, HttpClient)
            mock_close.assert_called_once()
