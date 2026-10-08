from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import requests

from greedybear.cronjobs.firehol import FireHolCron
from greedybear.models import FireHolList, Tag
from tests import CustomTestCase


class FireHolCronTestCase(CustomTestCase):
    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_creates_all_firehol_entries(self, mock_get):
        # Setup mock responses
        mock_response_blocklist_de = MagicMock()
        mock_response_blocklist_de.text = "# blocklist_de\n1.1.1.1\n2.2.2.2"

        mock_response_greensnow = MagicMock()
        mock_response_greensnow.text = "# greensnow\n3.3.3.3"

        mock_response_bruteforceblocker = MagicMock()
        mock_response_bruteforceblocker.text = "# bruteforceblocker\n1.1.1.1"

        mock_response_dshield = MagicMock()
        mock_response_dshield.text = "# dshield\n4.4.4.0/24"

        # Side effect for multiple calls
        mock_get.side_effect = self._firehol_get_side_effect(
            {
                "blocklist_de": mock_response_blocklist_de,
                "greensnow": mock_response_greensnow,
                "bruteforceblocker": mock_response_bruteforceblocker,
                "dshield": mock_response_dshield,
            }
        )

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.execute()

        # Check that all FireHolList entries were created
        self.assertTrue(FireHolList.objects.filter(ip_address="1.1.1.1", source="blocklist_de").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="2.2.2.2", source="blocklist_de").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="3.3.3.3", source="greensnow").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="1.1.1.1", source="bruteforceblocker").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="4.4.4.0/24", source="dshield").exists())
        # Verify FireHolList holds what _write_blocklist_tags will match against
        firehol_entries = FireHolList.objects.filter(ip_address="1.1.1.1")
        self.assertEqual(firehol_entries.count(), 2)
        sources = list(firehol_entries.values_list("source", flat=True))
        self.assertIn("blocklist_de", sources)
        self.assertIn("bruteforceblocker", sources)

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_creates_some_firehol_entries(self, mock_get):
        # Setup mock response
        mock_response_blocklist_de = MagicMock()
        mock_response_blocklist_de.text = "# blocklist_de\n1.1.1.1\n2.2.2.2"

        # Side effect for multiple calls — bruteforceblocker raises HTTPError
        mock_get.side_effect = self._firehol_get_side_effect(
            {
                "blocklist_de": mock_response_blocklist_de,
                "bruteforceblocker": requests.exceptions.HTTPError("404 Client Error"),
            }
        )

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        # Check that some FireHolList entries were created
        self.assertTrue(FireHolList.objects.filter(ip_address="1.1.1.1", source="blocklist_de").exists())
        self.assertTrue(FireHolList.objects.filter(ip_address="2.2.2.2", source="blocklist_de").exists())
        self.assertFalse(FireHolList.objects.filter(source="bruteforceblocker").exists())

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_creates_no_firehol_entries(self, mock_get):
        # Setup mock response
        mock_response_blocklist_de = MagicMock()
        mock_response_blocklist_de.text = "# blocklist_de\n"

        # Side effect for multiple calls — bruteforceblocker raises HTTPError
        mock_get.side_effect = self._firehol_get_side_effect(
            {
                "blocklist_de": mock_response_blocklist_de,
                "bruteforceblocker": requests.exceptions.HTTPError("404 Client Error"),
            }
        )

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        # Check that no FireHolList entries were created
        self.assertFalse(FireHolList.objects.filter(source="blocklist_de").exists())
        self.assertFalse(FireHolList.objects.filter(source="bruteforceblocker").exists())

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_handles_network_errors(self, mock_get):
        # Setup mock to raise a network error
        mock_get.side_effect = requests.exceptions.RequestException("Network error")

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        cronjob.log.exception.assert_called()
        self.assertEqual(FireHolList.objects.count(), 0)

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_handles_raise_for_status_errors(self, mock_get):
        # Setup mock to raise a 404 error (HttpClient raises this automatically)
        mock_get.side_effect = requests.exceptions.HTTPError("404 Client Error")

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        cronjob.log.exception.assert_called()

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_handles_invalid_ip(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.text = "# blocklist_de\n256.1.1.1\n999.999.999.999\n"
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        self.assertFalse(FireHolList.objects.filter(ip_address="256.1.1.1", source="blocklist_de").exists())
        self.assertFalse(FireHolList.objects.filter(ip_address="999.999.999.999", source="blocklist_de").exists())

    @patch("greedybear.cronjobs.firehol.HttpClient.get")
    def test_run_handles_invalid_cidr(self, mock_get):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.text = "# blocklist_de\n192.168.1.256/24\n"
        mock_get.return_value = mock_response

        # Run the cronjob
        cronjob = FireHolCron()
        cronjob.log = MagicMock()
        cronjob.execute()

        self.assertFalse(FireHolList.objects.filter(ip_address="192.168.1.256", source="blocklist_de").exists())

    def test_cleanup_old_entries(self):
        now = datetime.now()

        old_entry = FireHolList.objects.create(
            ip_address="9.9.9.9",
            source="blocklist_de",
            added=now - timedelta(days=31),
        )

        new_entry = FireHolList.objects.create(
            ip_address="8.8.8.8",
            source="blocklist_de",
            added=now - timedelta(days=10),
        )

        # Run the cronjob
        cron = FireHolCron()
        cron.log = MagicMock()
        cron._cleanup_old_entries()

        self.assertFalse(FireHolList.objects.filter(id=old_entry.id).exists())
        self.assertTrue(FireHolList.objects.filter(id=new_entry.id).exists())

    def _firehol_get_side_effect(self, side_effect_map):
        def _side_effect(url, **kwargs):
            for key, response_or_error in side_effect_map.items():
                if key in url:
                    if isinstance(response_or_error, Exception):
                        raise response_or_error
                    return response_or_error
            raise requests.exceptions.HTTPError(f"Unhandled URL: {url}")

        return _side_effect


class FireHolTaggingTestCase(CustomTestCase):
    """Tests for turning stored blocklist entries into tags."""

    def _run_tagging(self):
        cron = FireHolCron()
        cron.log = MagicMock()
        cron._write_blocklist_tags()

    def test_exact_ip_match_creates_tag(self):
        """An IOC whose name is on a blocklist gets a blocklist tag."""
        FireHolList.objects.create(ip_address=self.ioc.name, source="greensnow")

        self._run_tagging()

        tags = Tag.objects.filter(ioc=self.ioc, source="firehol")
        self.assertEqual(tags.count(), 1)
        self.assertEqual(tags[0].key, "blocklist")
        self.assertEqual(tags[0].value, "greensnow")

    def test_cidr_match_creates_tag(self):
        """An IOC inside a stored network range gets a blocklist tag."""
        FireHolList.objects.create(ip_address="140.246.171.0/24", source="dshield")

        self._run_tagging()

        tags = Tag.objects.filter(ioc=self.ioc, source="firehol")
        self.assertEqual(tags.count(), 1)
        self.assertEqual(tags[0].value, "dshield")

    def test_ip_on_two_lists_gets_two_tags(self):
        """Each blocklist an IOC appears on becomes its own tag."""
        FireHolList.objects.create(ip_address=self.ioc.name, source="greensnow")
        FireHolList.objects.create(ip_address=self.ioc.name, source="blocklist_de")

        self._run_tagging()

        values = sorted(Tag.objects.filter(ioc=self.ioc, source="firehol").values_list("value", flat=True))
        self.assertEqual(values, ["blocklist_de", "greensnow"])

    def test_no_match_creates_no_tags(self):
        """An IOC on no blocklist gets no tags."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="greensnow")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(source="firehol").count(), 0)

    def test_stale_tag_is_removed(self):
        """An IOC that drops off a blocklist loses its tag."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="greensnow")
        Tag.objects.create(ioc=self.ioc, key="blocklist", value="greensnow", source="firehol")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(ioc=self.ioc, source="firehol").count(), 0)

    def test_no_entries_keeps_existing_tags(self):
        """A failed download must not wipe the tags we already have."""
        Tag.objects.create(ioc=self.ioc, key="blocklist", value="greensnow", source="firehol")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(ioc=self.ioc, source="firehol").count(), 1)

    def test_other_sources_are_not_touched(self):
        """Tags from other enrichment sources survive a FireHol run."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="greensnow")
        Tag.objects.create(ioc=self.ioc, key="malware", value="mirai", source="threatfox")
        self._run_tagging()

        self.assertTrue(Tag.objects.filter(ioc=self.ioc, source="threatfox").exists())
