from unittest.mock import MagicMock

from greedybear.cronjobs.enrichment.firehol_blocklist import FireHolBlocklistCron
from greedybear.models import FireHolList, Tag
from tests import CustomTestCase


class FireHolBlocklistCronTestCase(CustomTestCase):
    """Tests for turning stored blocklist entries into tags."""

    def _run_tagging(self):
        cron = FireHolBlocklistCron()
        cron.log = MagicMock()
        cron.run()

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

    def test_malformed_cidr_entry_is_skipped(self):
        """A junk entry does not abort the containment query."""
        FireHolList.objects.create(ip_address="not-an-ip/24", source="greensnow")
        FireHolList.objects.create(ip_address="140.246.171.0/24", source="dshield")

        self._run_tagging()

        values = sorted(Tag.objects.filter(ioc=self.ioc, source="firehol").values_list("value", flat=True))
        self.assertEqual(values, ["dshield"])

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
