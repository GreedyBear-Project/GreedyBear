import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock, patch

import requests
from django.test import TestCase

from greedybear.cronjobs.http_client import FingerprintAdapter, HttpClient


class RetryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.request_count += 1
        self.send_response(500)
        self.end_headers()

    def do_POST(self):
        self.server.request_count += 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass


class TestHttpClient(TestCase):
    def setUp(self):
        self.http_client = HttpClient(default_timeout=5.0)

    @patch("requests.Session.request")
    def test_default_timeout_applied(self, mock_request):
        """Test that the default timeout is applied when no timeout is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        self.http_client.get("https://example.com")

        mock_request.assert_called_once_with("GET", "https://example.com", timeout=5.0)

    @patch("requests.Session.request")
    def test_custom_timeout_override(self, mock_request):
        """Test that a custom timeout overrides the default."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        self.http_client.get("https://example.com", timeout=15.0)

        mock_request.assert_called_once_with("GET", "https://example.com", timeout=15.0)

    @patch("greedybear.cronjobs.http_client.logger")
    @patch("requests.Session.request")
    def test_raise_for_status_called_and_logged(self, mock_request, mock_logger):
        """Test that raise_for_status is automatically called and errors are logged."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_request.return_value = mock_response

        with self.assertRaises(requests.HTTPError):
            self.http_client.get("https://example.com")

        mock_response.raise_for_status.assert_called_once()
        mock_logger.exception.assert_called_once()
        self.assertIn("HTTP Request failed", mock_logger.exception.call_args[0][0])

    @patch("requests.Session.request")
    def test_post_request(self, mock_request):
        """Test that post requests work and apply defaults."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        payload = {"key": "value"}
        self.http_client.post("https://example.com", json=payload)

        mock_request.assert_called_once_with("POST", "https://example.com", data=None, json=payload, timeout=5.0)

    def test_context_manager(self):
        """Test that the client can be used as a context manager."""
        with patch("requests.Session.close") as mock_close:
            with HttpClient() as client:
                self.assertIsInstance(client, HttpClient)
            mock_close.assert_called_once()

    def test_no_fingerprint_keeps_default_verification(self):
        """Without a fingerprint, HTTPS uses the plain adapter and normal CA verification."""
        client = HttpClient()

        adapter = client.session.get_adapter("https://example.com")
        self.assertNotIsInstance(adapter, FingerprintAdapter)
        self.assertIs(client.session.verify, True)

    def test_fingerprint_pins_https_connections(self):
        """With a fingerprint, HTTPS connections pin it instead of validating the CA chain."""
        client = HttpClient(retries=5, cert_fingerprint="AB:CD:EF")

        adapter = client.session.get_adapter("https://example.com")
        self.assertIsInstance(adapter, FingerprintAdapter)
        self.assertEqual(adapter.poolmanager.connection_pool_kw["assert_fingerprint"], "AB:CD:EF")
        self.assertIs(adapter.poolmanager.connection_pool_kw["assert_hostname"], False)
        self.assertIs(client.session.verify, False)
        # Retries still apply to the pinned adapter.
        self.assertEqual(adapter.max_retries.total, 5)
        # Plain HTTP has no certificate to pin.
        self.assertNotIsInstance(client.session.get_adapter("http://example.com"), FingerprintAdapter)

    def test_fingerprint_pins_proxied_connections(self):
        """Connections through a proxy must pin the fingerprint as well."""
        adapter = FingerprintAdapter("AB:CD:EF")

        proxy_manager = adapter.proxy_manager_for("http://proxy:3128")

        self.assertEqual(proxy_manager.connection_pool_kw["assert_fingerprint"], "AB:CD:EF")
        self.assertIs(proxy_manager.connection_pool_kw["assert_hostname"], False)

    def test_get_retry_logic(self):
        """Test that GET requests are correctly retried upon receiving server errors."""
        server = HTTPServer(("localhost", 0), RetryHandler)
        server.request_count = 0

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            port = server.server_port
            url = f"http://localhost:{port}/api"

            # Use a short backoff for fast tests
            client = HttpClient(retries=3, backoff_factor=0)

            with self.assertRaises(requests.exceptions.RetryError):
                client.get(url)

            # Initial call + 3 retries = 4 calls
            self.assertEqual(server.request_count, 4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_post_not_retried(self):
        """Test that POST requests are NOT retried to prevent duplicate side effects."""
        server = HTTPServer(("localhost", 0), RetryHandler)
        server.request_count = 0

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            port = server.server_port
            url = f"http://localhost:{port}/api"

            client = HttpClient(retries=3, backoff_factor=0)

            with self.assertRaises(requests.HTTPError):
                client.post(url, json={"test": "data"})

            # POST should NOT be retried — only 1 call
            self.assertEqual(server.request_count, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
