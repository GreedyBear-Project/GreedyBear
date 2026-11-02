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