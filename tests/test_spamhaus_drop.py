from unittest.mock import MagicMock, patch

from django.test import TestCase
from requests.exceptions import RequestException

from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.cronjobs.spamhaus_drop import SpamhausDropCron


class TestSpamhausDropCron(TestCase):
    @patch("greedybear.cronjobs.spamhaus_drop.HttpClient.get")
    def test_fetch_drop_feed_adds_entries(self, mock_requests_get):
        """Test that valid CIDRs are processed successfully."""
        mock_response = MagicMock()
        mock_response.text = """
        {"cidr":"1.2.3.0/24","sblid":"SBL123","rir":"arin"}
        {"cidr":"4.5.6.0/24","sblid":"SBL456","rir":"arin"}"""
        mock_requests_get.return_value = mock_response

        cron = SpamhausDropCron()
        cron._fetch_drop_feed()

    @patch("greedybear.cronjobs.spamhaus_drop.HttpClient.get")
    def test_invalid_cidrs_are_skipped(self, mock_requests_get):
        """Test that invalid CIDRs are skipped without error."""
        mock_response = MagicMock()
        mock_response.text = """
        {"cidr":"invalid_cidr"}
        {"cidr":"999.999.999.999/24"}"""
        mock_requests_get.return_value = mock_response

        cron = SpamhausDropCron()
        cron._fetch_drop_feed()

    @patch("greedybear.cronjobs.spamhaus_drop.HttpClient.get")
    def test_request_exception_is_handled(self, mock_requests_get):
        """Test that network errors are logged but do not crash the cronjob."""
        mock_requests_get.side_effect = RequestException("Network error")

        cron = SpamhausDropCron()
        cron._fetch_drop_feed()

    @patch("greedybear.cronjobs.spamhaus_drop.HttpClient.get")
    def test_unexpected_exception_is_raised(self, mock_requests_get):
        """Test that unexpected exceptions are re-raised."""
        mock_requests_get.side_effect = ValueError("Unexpected error")

        cron = SpamhausDropCron()

        with self.assertRaises(ValueError):
            cron._fetch_drop_feed()

    @patch.object(FireHolRepository, "cleanup_old_entries")
    def test_cleanup_old_entries(self, mock_cleanup):
        """Test that cleanup calls the repository with correct days."""
        mock_cleanup.return_value = 5

        cron = SpamhausDropCron()
        cron._cleanup_old_entries()

        mock_cleanup.assert_called_once_with(days=30)
