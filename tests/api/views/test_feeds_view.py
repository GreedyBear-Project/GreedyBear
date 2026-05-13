from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import override_settings

from api.throttles import FeedsThrottle
from tests import CustomTestCase


class FeedsViewTestCase(CustomTestCase):
    def test_200_log4pot_feeds(self):
        response = self.client.get("/api/feeds/log4pot/all/recent.json")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        # feed_type now derived from honeypot M2M
        self.assertIn("log4pot", target_ioc["feed_type"])
        self.assertIn("cowrie", target_ioc["feed_type"])
        self.assertIn("heralding", target_ioc["feed_type"])
        self.assertIn("ciscoasa", target_ioc["feed_type"])
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_200_all_feeds_with_license(self):
        """Test feeds endpoint when FEEDS_LICENSE is populated"""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.json())
        self.assertEqual(response.json()["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_200_all_feeds_without_license(self):
        """Test feeds endpoint when FEEDS_LICENSE is empty"""
        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.json())

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        self.assertEqual(set(target_ioc["feed_type"]), {"log4pot", "cowrie", "heralding", "ciscoasa"})
        self.assertEqual(target_ioc["attack_count"], 1)
        self.assertEqual(target_ioc["scanner"], True)
        self.assertEqual(target_ioc["payload_request"], True)
        self.assertEqual(target_ioc["recurrence_probability"], self.ioc.recurrence_probability)
        self.assertEqual(target_ioc["expected_interactions"], self.ioc.expected_interactions)

    def test_200_feeds_scanner_inclusion(self):
        response = self.client.get("/api/feeds/heralding/all/recent.json?include_mass_scanners")
        self.assertEqual(response.status_code, 200)
        if settings.FEEDS_LICENSE:
            self.assertEqual(response.json()["license"], settings.FEEDS_LICENSE)
        else:
            self.assertNotIn("license", response.json())
        # Expecting 3 because setupTestData creates 3 IOCs (ioc, ioc_2, ioc_domain) associated with Heralding
        self.assertEqual(len(response.json()["iocs"]), 3)

    def test_200_feeds_ignores_undocumented_params(self):
        # Setup data has multiple IOCs. We pass feed_size=1.
        # If the undocumented param is correctly ignored/filtered,
        # the response should fallback to the default feed_size and return >1 items.
        response = self.client.get("/api/feeds/all/all/recent.json?feed_size=1")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json()["iocs"]), 1)

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/test/all/recent.json")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_inclusion_mass(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_mass_scanners")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_inclusion_tor(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_tor_exit_nodes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_inclusion_mass_and_tor(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&include_mass_scanners&include_tor_exit_nodes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 4)

    def test_200_feeds_filter_ip_only(self):
        response = self.client.get("/api/feeds/all/all/recent.json?ioc_type=ip")
        self.assertEqual(response.status_code, 200)
        # Should only return IP addresses, not domains
        for ioc in response.json()["iocs"]:
            # Verify all returned values are IPs (contain dots and numbers pattern)
            self.assertRegex(ioc["value"], r"^\d+\.\d+\.\d+\.\d+$")

    def test_200_feeds_filter_domain_only(self):
        response = self.client.get("/api/feeds/all/all/recent.json?ioc_type=domain")
        self.assertEqual(response.status_code, 200)
        # Should only return domains, not IPs
        self.assertGreater(len(response.json()["iocs"]), 0)
        for ioc in response.json()["iocs"]:
            # Verify all returned values are domains (contain alphabetic characters)
            self.assertRegex(ioc["value"], r"[a-zA-Z]")

    def test_200_feeds_pagination_filter_ip(self):
        response = self.client.get(
            "/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&ioc_type=ip&include_mass_scanners&include_tor_exit_nodes"
        )
        self.assertEqual(response.status_code, 200)
        # Should return only IPs (3 in test data)
        self.assertEqual(response.json()["count"], 3)

    def test_200_feeds_pagination_filter_domain(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&ioc_type=domain")
        self.assertEqual(response.status_code, 200)
        # Should return only domains (1 in test data)
        self.assertEqual(response.json()["count"], 1)

    def test_200_feeds_multi_type_union(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=cowrie,heralding&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        returned_values = {ioc["value"] for ioc in response.json()["results"]["iocs"]}
        self.assertIn(self.ioc.name, returned_values)
        self.assertIn(self.ioc_domain.name, returned_values)

    def test_200_feeds_pagination_ignores_undocumented_params(self):
        # Setup data has multiple IOCs. We pass feed_size=1.
        # If the undocumented param is correctly ignored/filtered,
        # the pagination response should fallback to the default feed_size and return count > 1.
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent&feed_size=1")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json()["count"], 1)

    def test_400_feeds_multi_type_with_invalid(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=cowrie,invalid_type&attack_type=all&age=recent")
        self.assertEqual(response.status_code, 400)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=test&age=recent")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination_ordering_value_desc(self):
        response = self.client.get(
            "/api/feeds/?page_size=50&page=1&feed_type=all&attack_type=all&prioritize=recent&ordering=-value&include_mass_scanners&include_tor_exit_nodes"
        )
        self.assertEqual(response.status_code, 200)

        values = [ioc["value"] for ioc in response.json()["results"]["iocs"]]
        self.assertEqual(values, sorted(values, reverse=True))

    def test_200_feeds_pagination_ordering_value_asc(self):
        response = self.client.get(
            "/api/feeds/?page_size=50&page=1&feed_type=all&attack_type=all&prioritize=recent&ordering=value&include_mass_scanners&include_tor_exit_nodes"
        )
        self.assertEqual(response.status_code, 200)

        values = [ioc["value"] for ioc in response.json()["results"]["iocs"]]
        self.assertEqual(values, sorted(values))

    def test_feeds_endpoint_uses_feeds_throttle(self):
        cache.clear()
        try:
            with patch.object(FeedsThrottle, "THROTTLE_RATES", {"feeds": "1/minute"}):
                first = self.client.get("/api/feeds/all/all/recent.json")
                second = self.client.get("/api/feeds/all/all/recent.json")
        finally:
            cache.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_feeds_pagination_endpoint_uses_feeds_throttle(self):
        url = "/api/feeds/?page_size=10&page=1&feed_type=all&attack_type=all&age=recent"
        cache.clear()
        try:
            with patch.object(FeedsThrottle, "THROTTLE_RATES", {"feeds": "1/minute"}):
                first = self.client.get(url)
                second = self.client.get(url)
        finally:
            cache.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
