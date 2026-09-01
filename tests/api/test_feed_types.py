"""
Tests for API feed type handling after migration from boolean fields.
"""

from django.test import override_settings
from rest_framework.test import APIClient

from api.serializers import get_valid_feed_types
from greedybear.models import IOC, Honeypot, IocType
from tests import CustomTestCase


class FeedTypeAPITestCase(CustomTestCase):
    """Test API feed handling with Honeypot M2M instead of boolean fields."""

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

        # Ensure Cowrie and Log4pot honeypots exist
        self.cowrie_hp = Honeypot.objects.get_or_create(name="Cowrie", defaults={"active": True})[0]
        self.log4pot_hp = Honeypot.objects.get_or_create(name="Log4pot", defaults={"active": True})[0]

    def test_feed_type_derived_from_m2m(self):
        """Verify feed_type is derived from honeypot M2M."""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        # Feed types should be derived from M2M
        feed_types = set(target_ioc["feed_type"])
        self.assertIn("log4pot", feed_types)
        self.assertIn("cowrie", feed_types)
        self.assertIn("heralding", feed_types)
        self.assertIn("ciscoasa", feed_types)

    def test_feed_filter_by_cowrie(self):
        """Verify filtering by cowrie feed type works via M2M."""
        # Include mass scanners and tor exit nodes since test IOCs have those reputations
        response = self.client.get("/api/feeds/cowrie/all/recent.json?include_mass_scanners=true&include_tor_exit_nodes=true")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        ioc_names = [ioc["value"] for ioc in iocs]

        # Should include IOCs associated with Cowrie honeypot
        self.assertIn(self.ioc.name, ioc_names)
        self.assertIn(self.ioc_2.name, ioc_names)
        self.assertIn(self.ioc_3.name, ioc_names)

    def test_feed_filter_by_log4pot(self):
        """Verify filtering by log4pot feed type works via M2M."""
        # Include mass scanners since ioc_2 has that reputation
        response = self.client.get("/api/feeds/log4pot/all/recent.json?include_mass_scanners=true")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        ioc_names = [ioc["value"] for ioc in iocs]

        # Should include IOCs associated with Log4pot honeypot
        self.assertIn(self.ioc.name, ioc_names)
        self.assertIn(self.ioc_2.name, ioc_names)

    def test_feed_valid_types_includes_all_active_honeypots(self):
        """Verify valid feed types include all active honeypots."""
        valid_types = get_valid_feed_types()

        # Should include all active honeypots (case-insensitive)
        self.assertIn("all", valid_types)
        self.assertIn("cowrie", valid_types)
        self.assertIn("log4pot", valid_types)
        self.assertIn("heralding", valid_types)
        self.assertIn("ciscoasa", valid_types)

    def test_inactive_honeypot_not_in_valid_types(self):
        """Verify inactive honeypots are not included in valid feed types."""
        valid_types_before = get_valid_feed_types()

        # Deactivate a honeypot
        self.ddospot.active = False
        self.ddospot.save()

        valid_types_after = get_valid_feed_types()

        # Ddospot was already inactive, should not be in either
        self.assertNotIn("ddospot", valid_types_before)
        self.assertNotIn("ddospot", valid_types_after)

    def test_feed_type_no_normalization_log4pot(self):
        """Verify Log4pot is NOT normalized to log4j in feed output."""
        # Create an IOC with only Log4pot
        ioc = IOC.objects.create(
            name="100.200.100.200",
            type=IocType.IP.value,
            scanner=True,
        )
        ioc.honeypots.add(self.log4pot_hp)

        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == ioc.name), None)
        self.assertIsNotNone(target_ioc)

        # Should contain "log4pot" and NOT "log4j"
        self.assertIn("log4pot", target_ioc["feed_type"])
        self.assertNotIn("log4j", target_ioc["feed_type"])

    def test_feed_output_without_boolean_fields(self):
        """Verify feed output doesn't contain legacy boolean fields."""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        if iocs:
            first_ioc = iocs[0]
            # These boolean fields should not exist in the output
            self.assertNotIn("log4j", first_ioc)
            self.assertNotIn("cowrie", first_ioc)

    def test_enrichment_output_includes_honeypot_list(self):
        """Verify enrichment endpoint includes honeypot list."""
        response = self.client.get(f"/api/enrichment?query={self.ioc.name}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["found"])

        # Should have general_honeypot list (serialized as list of strings)
        honeypots = response.json()["ioc"]["general_honeypot"]
        self.assertIsInstance(honeypots, list)
        self.assertGreater(len(honeypots), 0)

        # Check that honeypot names are in the list
        self.assertIn("Cowrie", honeypots)
        self.assertIn("Log4pot", honeypots)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_feed_with_multiple_honeypots(self):
        """Verify IOC with multiple honeypots shows all in feed_type."""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        # Should have multiple feed types from all associated honeypots
        feed_types = target_ioc["feed_type"]
        self.assertGreater(len(feed_types), 1)
        self.assertIsInstance(feed_types, list)
