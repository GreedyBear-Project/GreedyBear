from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import Tag
from tests import CustomTestCase


class TestAbuseIPDBCron(CustomTestCase):
    """Tests for AbuseIPDBCron with the 'fetch and join directly' approach."""

    def setUp(self):
        self.tag_repo = TagRepository()
        self.cron = AbuseIPDBCron(tag_repo=self.tag_repo)

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_skips_when_no_api_key(self, mock_settings):
        """Should skip enrichment when ABUSEIPDB_API_KEY is not set."""
        mock_settings.ABUSEIPDB_API_KEY = ""

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_enriches_matching_iocs(self, mock_settings, mock_get):
        """Should create tags for IOCs that match blocklist IPs."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": self.ioc.name,
                    "abuseConfidenceScore": 84,
                }
            ],
        }
        mock_get.return_value = mock_response

        self.cron.run()

        tags = Tag.objects.filter(source="abuseipdb", ioc=self.ioc)
        self.assertTrue(tags.exists())

        tag_keys = set(tags.values_list("key", flat=True))
        self.assertIn("confidence_of_abuse", tag_keys)

        confidence_tag = tags.get(key="confidence_of_abuse")
        self.assertEqual(confidence_tag.value, "84%")

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_no_tags_for_non_matching_iocs(self, mock_settings, mock_get):
        """Should not create tags for IPs not in our IOC table."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": "203.0.113.99",
                    "abuseConfidenceScore": 90,
                }
            ],
        }
        mock_get.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_replaces_stale_tags(self, mock_settings, mock_get):
        """Tags should be replaced on each run, not accumulated."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        # Create a pre-existing tag with old confidence
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="50%", source="abuseipdb")

        # New run with updated confidence
        mock_response = Mock()
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": self.ioc.name,
                    "abuseConfidenceScore": 95,
                }
            ],
        }
        mock_get.return_value = mock_response

        self.cron.run()

        # Old tag should be gone, new one present
        confidence_tags = Tag.objects.filter(source="abuseipdb", ioc=self.ioc, key="confidence_of_abuse")
        self.assertEqual(confidence_tags.count(), 1)
        self.assertEqual(confidence_tags.first().value, "95%")

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_clears_tags_when_ip_delisted(self, mock_settings, mock_get):
        """Tags should be removed when an IP is no longer in the blocklist."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        # Pre-existing tag
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        # New run with empty blocklist (IP delisted)
        mock_response = Mock()
        mock_response.json.return_value = {"data": []}
        mock_get.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="abuseipdb", ioc=self.ioc).count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_handles_request_exception(self, mock_settings, mock_get):
        """Should raise on network errors."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"
        mock_get.side_effect = requests.RequestException("Connection error")

        with self.assertRaises(requests.RequestException):
            self.cron.run()

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_skips_invalid_ips(self, mock_settings, mock_get):
        """Should skip entries with invalid IP addresses."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": "999.999.999.999",
                    "abuseConfidenceScore": 90,
                },
                {
                    "ipAddress": "",
                    "abuseConfidenceScore": 80,
                },
            ],
        }
        mock_get.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_does_not_affect_threatfox_tags(self, mock_settings, mock_get):
        """AbuseIPDB enrichment should not touch tags from other sources."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        # Create a ThreatFox tag
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")

        mock_response = Mock()
        mock_response.json.return_value = {"data": []}
        mock_get.return_value = mock_response

        self.cron.run()

        # ThreatFox tag should still exist
        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 1)

    @patch("greedybear.cronjobs.abuseipdb_feed.HttpClient.get")
    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_enriches_multiple_iocs(self, mock_settings, mock_get):
        """Should enrich multiple IOCs from a single feed download."""
        mock_settings.ABUSEIPDB_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "data": [
                {
                    "ipAddress": self.ioc.name,
                    "abuseConfidenceScore": 84,
                },
                {
                    "ipAddress": self.ioc_2.name,
                    "abuseConfidenceScore": 92,
                },
            ],
        }
        mock_get.return_value = mock_response

        self.cron.run()

        # Both IOCs should have tags
        self.assertTrue(Tag.objects.filter(source="abuseipdb", ioc=self.ioc).exists())
        self.assertTrue(Tag.objects.filter(source="abuseipdb", ioc=self.ioc_2).exists())

        # Verify correct values
        ioc1_confidence = Tag.objects.get(source="abuseipdb", ioc=self.ioc, key="confidence_of_abuse")
        self.assertEqual(ioc1_confidence.value, "84%")

        ioc2_confidence = Tag.objects.get(source="abuseipdb", ioc=self.ioc_2, key="confidence_of_abuse")
        self.assertEqual(ioc2_confidence.value, "92%")
