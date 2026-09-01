# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

import requests

from greedybear.cronjobs import whatsmyip
from greedybear.models import IOC, WhatsMyIPDomain
from tests import CustomTestCase


class WhatsMyIPTestCase(CustomTestCase):
    """Test WhatsMyIPCron cronjob"""

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_add_new_domains(self, mock_get):
        """Test adding new domains from MISP warning list"""
        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": ["test-domain-1.com", "test-domain-2.com"]}
        mock_get.return_value = mock_response

        # Run the cronjob
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify domains were added
        self.assertEqual(WhatsMyIPDomain.objects.count(), 2)
        self.assertTrue(WhatsMyIPDomain.objects.filter(domain="test-domain-1.com").exists())
        self.assertTrue(WhatsMyIPDomain.objects.filter(domain="test-domain-2.com").exists())

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_skip_existing_domains(self, mock_get):
        """Test that existing domains are skipped"""
        # Add an existing domain
        existing_domain = WhatsMyIPDomain.objects.create(domain="existing-domain.com")

        # Mock the HTTP response with existing and new domains
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": ["existing-domain.com", "new-domain.com"]}
        mock_get.return_value = mock_response

        # Run the cronjob
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify only new domain was added
        self.assertEqual(WhatsMyIPDomain.objects.count(), 2)
        self.assertEqual(WhatsMyIPDomain.objects.get(domain="existing-domain.com").id, existing_domain.id)
        self.assertTrue(WhatsMyIPDomain.objects.filter(domain="new-domain.com").exists())

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_remove_old_ioc_records(self, mock_get):
        """Test that old IOC records are cleaned up"""
        # Create an IOC record for a domain
        domain_name = "cleanup-domain.com"
        ioc = IOC.objects.create(name=domain_name)

        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": [domain_name]}
        mock_get.return_value = mock_response

        # Run the cronjob
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify IOC record was deleted
        self.assertFalse(IOC.objects.filter(id=ioc.id).exists())
        self.assertTrue(WhatsMyIPDomain.objects.filter(domain=domain_name).exists())

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_handle_missing_ioc_gracefully(self, mock_get):
        """Test that missing IOC records don't cause errors"""
        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": ["domain-with-no-ioc.com"]}
        mock_get.return_value = mock_response

        # Run the cronjob - should not raise exception
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify domain was added
        self.assertTrue(WhatsMyIPDomain.objects.filter(domain="domain-with-no-ioc.com").exists())

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_empty_domain_list(self, mock_get):
        """Test handling of empty domain list"""
        # Mock the HTTP response with empty list
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": []}
        mock_get.return_value = mock_response

        # Run the cronjob
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify no domains were added
        self.assertEqual(WhatsMyIPDomain.objects.count(), 0)

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_http_request_parameters(self, mock_get):
        """Test that HTTP request is made with correct parameters"""
        # Mock the HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {"list": []}
        mock_get.return_value = mock_response

        # Run the cronjob
        cron = whatsmyip.WhatsMyIPCron()
        cron.run()

        # Verify the request was made correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertIn(
            "https://raw.githubusercontent.com/MISP/misp-warninglists",
            call_args[0][0],
        )

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_raises_on_http_error(self, mock_get):
        """Test that HTTP errors (4xx/5xx) are raised instead of silently ignored."""
        mock_get.side_effect = requests.exceptions.HTTPError("404 Client Error")

        cron = whatsmyip.WhatsMyIPCron()
        with self.assertRaises(requests.exceptions.HTTPError):
            cron.run()

        self.assertEqual(WhatsMyIPDomain.objects.count(), 0)

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_raises_on_network_error(self, mock_get):
        """Test that network errors (DNS failure, timeout) are raised."""
        mock_get.side_effect = requests.exceptions.ConnectionError("DNS resolution failed")

        cron = whatsmyip.WhatsMyIPCron()
        with self.assertRaises(requests.exceptions.ConnectionError):
            cron.run()

        self.assertEqual(WhatsMyIPDomain.objects.count(), 0)

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_raises_on_invalid_json(self, mock_get):
        """Test that non-JSON responses raise an error."""
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("No JSON object could be decoded")
        mock_get.return_value = mock_response

        cron = whatsmyip.WhatsMyIPCron()
        with self.assertRaises(ValueError):
            cron.run()

        self.assertEqual(WhatsMyIPDomain.objects.count(), 0)

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_raises_on_missing_list_key(self, mock_get):
        """Test that a JSON response missing the 'list' key raises KeyError."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected_key": ["domain.com"]}
        mock_get.return_value = mock_response

        cron = whatsmyip.WhatsMyIPCron()
        with self.assertRaises(KeyError):
            cron.run()

        self.assertEqual(WhatsMyIPDomain.objects.count(), 0)

    @patch("greedybear.cronjobs.whatsmyip.HttpClient.get")
    def test_execute_raises_on_http_error(self, mock_get):
        """Test that base class execute() propagates HTTP errors"""
        mock_get.side_effect = requests.exceptions.HTTPError("500 Server Error")

        cron = whatsmyip.WhatsMyIPCron()

        with self.assertRaises(requests.exceptions.HTTPError):
            cron.execute()
