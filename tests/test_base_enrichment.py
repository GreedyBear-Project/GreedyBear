from unittest.mock import Mock

from greedybear.cronjobs.enrichment.firehol_blocklist import FireHolBlocklistCron
from greedybear.models import IOC

from . import CustomTestCase


class TestMatchIocs(CustomTestCase):
    def setUp(self):
        self.job = FireHolBlocklistCron(firehol_repo=Mock(), tag_repo=Mock())

    def test_match_iocs_normalizes_uncompressed_ipv6(self):
        """An uncompressed IPv6 key must still match a compressed IOC.name."""
        IOC.objects.create(name="2001:db8::1", type="ip")
        ip_dict = {"2001:DB8:0:0:0:0:0:1": {}}

        result = list(self.job._match_iocs(ip_dict))

        names = [name for _, name in result]
        self.assertIn("2001:db8::1", names)

    def test_build_tag_entries_handles_uncompressed_ipv6_keys(self):
        """An uncompressed IPv6 key must still produce tags."""
        ioc = IOC.objects.create(name="2001:db8::1", type="ip")
        uncompressed = "2001:DB8:0:0:0:0:0:1"

        job = FireHolBlocklistCron(firehol_repo=Mock(), tag_repo=Mock())
        feed_by_ip = {uncompressed: ["blocklist_de"]}
        expected_entry = {"ioc_id": ioc.id, "key": "blocklist", "value": "blocklist_de"}

        matching_iocs = job._match_iocs(feed_by_ip)
        tag_entries = job._build_tag_entries(matching_iocs, feed_by_ip)
        self.assertEqual(tag_entries, [expected_entry])
