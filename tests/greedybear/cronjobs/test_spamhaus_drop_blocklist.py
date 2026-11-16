from unittest.mock import MagicMock

from greedybear.cronjobs.enrichment.spamhaus_drop_blocklist import SpamhausDropBlocklistCron
from greedybear.models import FireHolList, Tag
from tests import CustomTestCase


class SpamhausDropBlocklistCronTestCase(CustomTestCase):
    """Tests for turning stored Spamhaus DROP entries into tags."""

    def _run_tagging(self):
        cron = SpamhausDropBlocklistCron()
        cron.log = MagicMock()
        cron.run()

    def test_exact_ip_match_creates_tag(self):
        """An IOC whose name is on the DROP list gets a Spamhaus tag."""
        FireHolList.objects.create(ip_address=self.ioc.name, source="spamhaus_drop")

        self._run_tagging()

        tags = Tag.objects.filter(ioc=self.ioc, source="spamhaus_drop")
        self.assertEqual(tags.count(), 1)
        self.assertEqual(tags[0].key, "blocklist")
        self.assertEqual(tags[0].value, "spamhaus_drop")

    def test_cidr_match_creates_tag(self):
        """An IOC inside a stored DROP range gets a Spamhaus tag."""
        FireHolList.objects.create(ip_address="140.246.171.0/24", source="spamhaus_drop")

        self._run_tagging()

        tags = Tag.objects.filter(ioc=self.ioc, source="spamhaus_drop")
        self.assertEqual(tags.count(), 1)
        self.assertEqual(tags[0].value, "spamhaus_drop")

    def test_firehol_rows_are_skipped(self):
        """FireHol rows in the same table are not tagged as Spamhaus."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="spamhaus_drop")
        FireHolList.objects.create(ip_address=self.ioc.name, source="greensnow")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(ioc=self.ioc).count(), 0)

    def test_stale_tag_is_removed(self):
        """An IOC that drops off the DROP list loses its tag."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="spamhaus_drop")
        Tag.objects.create(ioc=self.ioc, key="blocklist", value="spamhaus_drop", source="spamhaus_drop")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(ioc=self.ioc, source="spamhaus_drop").count(), 0)

    def test_no_entries_keeps_existing_tags(self):
        """A failed download must not wipe the tags we already have."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="greensnow")
        Tag.objects.create(ioc=self.ioc, key="blocklist", value="spamhaus_drop", source="spamhaus_drop")

        self._run_tagging()

        self.assertEqual(Tag.objects.filter(ioc=self.ioc, source="spamhaus_drop").count(), 1)

    def test_firehol_tags_are_not_touched(self):
        """FireHol tags survive a Spamhaus run."""
        FireHolList.objects.create(ip_address="5.5.5.5", source="spamhaus_drop")
        Tag.objects.create(ioc=self.ioc, key="blocklist", value="greensnow", source="firehol")

        self._run_tagging()

        self.assertTrue(Tag.objects.filter(ioc=self.ioc, source="firehol").exists())
