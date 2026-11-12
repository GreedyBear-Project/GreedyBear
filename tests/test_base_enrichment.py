from unittest.mock import Mock

from greedybear.cronjobs.enrichment.firehol_blocklist import FireHolBlocklistCron
from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.models import IOC

from . import CustomTestCase


class TestMatchIocs(CustomTestCase):
    def setUp(self):
        self.repo = FireHolRepository()
        self.job = FireHolBlocklistCron(firehol_repo=self.repo, tag_repo=Mock())

    def _tag_entries(self):
        entries_by_ip = self.repo.get_entries_by_ip(self.job.BLOCKLIST_SOURCES)
        matching_iocs = self.job._match_iocs(entries_by_ip)
        return self.job._build_tag_entries(matching_iocs, entries_by_ip)

    def test_build_tag_entries_handles_uncompressed_ipv6_keys(self):
        """An uncompressed IPv6 blocklist entry must still produce tags."""
        ioc = IOC.objects.create(name="2001:db8::1", type="ip")
        self.repo.get_or_create("2001:DB8:0:0:0:0:0:1", "blocklist_de")

        self.assertEqual(self._tag_entries(), [{"ioc_id": ioc.id, "key": "blocklist", "value": "blocklist_de"}])

    def test_build_tag_entries_handles_ipv4_mapped_entries(self):
        """An IPv4-mapped blocklist entry must match the plain IPv4 IOC."""
        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        self.repo.get_or_create("::ffff:1.2.3.4", "blocklist_de")

        self.assertEqual(self._tag_entries(), [{"ioc_id": ioc.id, "key": "blocklist", "value": "blocklist_de"}])
