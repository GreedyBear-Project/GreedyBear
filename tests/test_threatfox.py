from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.cronjobs.threatfox_feed import ThreatFoxCron
from greedybear.models import Tag
from tests import CustomTestCase


class TestThreatFoxCron(CustomTestCase):
    """Tests for ThreatFoxCron with the 'fetch and join directly' approach."""

    def setUp(self):
        self.tag_repo = TagRepository()
        self.cron = ThreatFoxCron(tag_repo=self.tag_repo)

    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_skips_when_no_api_key(self, mock_settings):
        """Should skip enrichment when THREATFOX_API_KEY is not set."""
        mock_settings.THREATFOX_API_KEY = ""

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_enriches_matching_iocs(self, mock_settings, mock_post):
        """Should create tags for IOCs that match feed IPs."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        # Mock ThreatFox API response with our test IOC IP
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": f"{self.ioc.name}:4444",
                    "ioc_type": "ip:port",
                    "malware": "win.mirai",
                    "malware_printable": "Mirai",
                    "threat_type": "botnet_cc",
                    "confidence_level": 85,
                }
            ],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        tags = Tag.objects.filter(source="threatfox", ioc=self.ioc)
        self.assertTrue(tags.exists())

        tag_keys = set(tags.values_list("key", flat=True))
        self.assertIn("malware", tag_keys)
        self.assertIn("threat_type", tag_keys)
        self.assertIn("confidence_level", tag_keys)

        malware_tag = tags.get(key="malware")
        self.assertEqual(malware_tag.value, "Mirai")

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_no_tags_for_non_matching_iocs(self, mock_settings, mock_post):
        """Should not create tags for IPs not in our IOC table."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "203.0.113.99:4444",
                    "ioc_type": "ip:port",
                    "malware_printable": "Emotet",
                    "threat_type": "payload_delivery",
                    "confidence_level": 90,
                }
            ],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_replaces_stale_tags(self, mock_settings, mock_post):
        """Tags should be replaced on each run, not accumulated."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        # Create a pre-existing tag
        Tag.objects.create(ioc=self.ioc, key="malware", value="OldMalware", source="threatfox")

        # New run with updated data
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": f"{self.ioc.name}:4444",
                    "ioc_type": "ip:port",
                    "malware_printable": "NewMalware",
                    "threat_type": "botnet_cc",
                    "confidence_level": 95,
                }
            ],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        # Old tag should be gone, new one present
        tags = Tag.objects.filter(source="threatfox", ioc=self.ioc)
        malware_tags = tags.filter(key="malware")
        self.assertEqual(malware_tags.count(), 1)
        self.assertEqual(malware_tags.first().value, "NewMalware")

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_clears_tags_when_ip_delisted(self, mock_settings, mock_post):
        """Tags should be removed when an IP is no longer in the feed."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        # Pre-existing tag
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")

        # New run with empty feed (IP was delisted)
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        # Tags should be gone
        self.assertEqual(Tag.objects.filter(source="threatfox", ioc=self.ioc).count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_skips_private_ips(self, mock_settings, mock_post):
        """Should filter out private, loopback, and reserved IPs."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "192.168.1.1:4444",
                    "ioc_type": "ip:port",
                    "malware_printable": "TestMalware",
                    "threat_type": "botnet_cc",
                    "confidence_level": 80,
                },
                {
                    "ioc": "127.0.0.1:4444",
                    "ioc_type": "ip:port",
                    "malware_printable": "TestMalware2",
                    "threat_type": "botnet_cc",
                    "confidence_level": 80,
                },
            ],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_handles_non_ok_status(self, mock_settings, mock_post):
        """Should handle non-OK API response gracefully."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "no_result",
            "data": [],
        }
        mock_post.return_value = mock_response

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="threatfox").count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_handles_request_exception(self, mock_settings, mock_post):
        """Should raise on network errors."""
        mock_settings.THREATFOX_API_KEY = "test_key"
        mock_post.side_effect = requests.RequestException("Connection error")

        with self.assertRaises(requests.RequestException):
            self.cron.run()

    def test_extract_ip_from_ip_port(self):
        """Should extract IP from ip:port format."""
        ip = ThreatFoxCron._extract_ip("1.2.3.4:4444", "ip:port")
        self.assertEqual(ip, "1.2.3.4")

    def test_extract_ip_from_url(self):
        """Should extract IP from URL format."""
        ip = ThreatFoxCron._extract_ip("http://1.2.3.4/malware.exe", "url")
        self.assertEqual(ip, "1.2.3.4")

    def test_extract_ip_returns_none_for_domain(self):
        """Should return None for domain IOC types."""
        ip = ThreatFoxCron._extract_ip("evil.example.com", "domain")
        self.assertIsNone(ip)

    @patch("greedybear.cronjobs.threatfox_feed.HttpClient.post")
    @patch("greedybear.cronjobs.threatfox_feed.settings")
    def test_does_not_affect_abuseipdb_tags(self, mock_settings, mock_post):
        """ThreatFox enrichment should not touch tags from other sources."""
        mock_settings.THREATFOX_API_KEY = "test_key"

        # Create an AbuseIPDB tag
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

        mock_response = Mock()
        mock_response.json.return_value = {"query_status": "ok", "data": []}
        mock_post.return_value = mock_response

        self.cron.run()

        # AbuseIPDB tag should still exist
        self.assertEqual(Tag.objects.filter(source="abuseipdb").count(), 1)
