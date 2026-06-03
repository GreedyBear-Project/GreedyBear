from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from greedybear.cache import Cache
from greedybear.consts import API_CACHE_ALIAS, IOC_DATA_VERSION_KEY
from greedybear.models import IOC, AutonomousSystem, Honeypot
from tests import CustomTestCase


class FeedsASNViewTestCase(CustomTestCase):
    """Tests for ASN aggregated feeds API"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        IOC.objects.all().delete()
        cls.testpot1, _ = Honeypot.objects.get_or_create(name="testpot1", active=True)
        cls.testpot2, _ = Honeypot.objects.get_or_create(name="testpot2", active=True)

        cls.high_asn = "13335"
        cls.low_asn = "16276"

        cls.as_high = AutonomousSystem.objects.create(asn=int(cls.high_asn), name="CLOUDFLARE")

        cls.as_low = AutonomousSystem.objects.create(asn=int(cls.low_asn), name="OVH")

        cls.ioc_high1 = IOC.objects.create(
            name="high1.example.com",
            type="ip",
            autonomous_system=cls.as_high,
            attack_count=15,
            interaction_count=30,
            login_attempts=5,
            first_seen=timezone.now() - timezone.timedelta(days=10),
            recurrence_probability=0.8,
            expected_interactions=20.0,
        )
        cls.ioc_high1.honeypots.add(cls.testpot1, cls.testpot2)

        cls.ioc_high2 = IOC.objects.create(
            name="high2.example.com",
            type="ip",
            autonomous_system=cls.as_high,
            attack_count=5,
            interaction_count=10,
            login_attempts=2,
            first_seen=timezone.now() - timezone.timedelta(days=5),
            recurrence_probability=0.3,
            expected_interactions=8.0,
        )
        cls.ioc_high2.honeypots.add(cls.testpot1, cls.testpot2)

        cls.ioc_low = IOC.objects.create(
            name="low.example.com",
            type="ip",
            autonomous_system=cls.as_low,
            attack_count=2,
            interaction_count=5,
            login_attempts=1,
            first_seen=timezone.now(),
            recurrence_probability=0.1,
            expected_interactions=3.0,
        )
        cls.ioc_low.honeypots.add(cls.testpot1, cls.testpot2)

    def setUp(self):
        super().setUp()
        cache.clear()
        self.cache = Cache(API_CACHE_ALIAS)
        self.cache.clear()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        self.url = "/api/feeds/asn/"

    def _get_results(self, response):
        payload = response.json()
        self.assertIsInstance(payload, list)
        return payload

    def test_200_asn_feed_aggregated_fields(self):
        """Ensure aggregated fields are computed correctly per ASN using dynamic sums"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        # filtering high ASN
        high_item = next((item for item in results if str(item["asn"]) == self.high_asn), None)
        self.assertIsNotNone(high_item)

        # getting all IOCs for high ASN from the DB
        high_iocs = IOC.objects.filter(autonomous_system__asn=self.high_asn)

        self.assertEqual(high_item["ioc_count"], high_iocs.count())
        self.assertEqual(high_item["total_attack_count"], sum(i.attack_count for i in high_iocs))
        self.assertEqual(high_item["total_interaction_count"], sum(i.interaction_count for i in high_iocs))
        self.assertEqual(high_item["total_login_attempts"], sum(i.login_attempts for i in high_iocs))
        self.assertAlmostEqual(high_item["expected_ioc_count"], sum(i.recurrence_probability for i in high_iocs))
        self.assertAlmostEqual(high_item["expected_interactions"], sum(i.expected_interactions for i in high_iocs))

        # validating first_seen / last_seen dynamically
        self.assertEqual(high_item["first_seen"], min(i.first_seen for i in high_iocs).isoformat())
        self.assertEqual(high_item["last_seen"], max(i.last_seen for i in high_iocs).isoformat())

        # validating honeypots dynamically
        expected_honeypots = sorted({hp.name for i in high_iocs for hp in i.honeypots.all()})
        self.assertEqual(sorted(high_item["honeypots"]), expected_honeypots)

    def test_200_asn_feed_default_ordering(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        # high_asn has ioc_count=2 > low_asn ioc_count=1
        self.assertEqual(str(results[0]["asn"]), self.high_asn)
        self.assertEqual(str(results[1]["asn"]), self.low_asn)

    def test_200_asn_feed_ordering_desc_ioc_count(self):
        response = self.client.get(self.url + "?ordering=-ioc_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_200_asn_feed_ordering_asc_ioc_count(self):
        response = self.client.get(self.url + "?ordering=ioc_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)
        self.assertEqual(str(results[0]["asn"]), self.low_asn)

    def test_200_asn_feed_ordering_desc_interaction_count(self):
        response = self.client.get(self.url + "?ordering=-total_interaction_count")
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)
        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_200_asn_feed_with_asn_filter(self):
        response = self.client.get(self.url + f"?asn={self.high_asn}")
        self.assertEqual(response.status_code, 200)

        results = self._get_results(response)
        self.assertEqual(len(results), 1)
        self.assertEqual(str(results[0]["asn"]), self.high_asn)

    def test_400_asn_feed_invalid_ordering_honeypots(self):
        response = self.client.get(self.url + "?ordering=honeypots")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("honeypots", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_invalid_ordering_random(self):
        response = self.client.get(self.url + "?ordering=xyz123")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("xyz123", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_invalid_ordering_model_field_not_in_agg(self):
        response = self.client.get(self.url + "?ordering=attack_count")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("attack_count", error_msg)
        self.assertIn("invalid", error_msg)

    def test_400_asn_feed_ordering_empty_param(self):
        response = self.client.get(self.url + "?ordering=")
        self.assertEqual(response.status_code, 400)
        data = response.json()
        errors_container = data.get("errors", data)
        error_list = errors_container.get("ordering", [])
        self.assertTrue(error_list)
        error_msg = error_list[0].lower()
        self.assertIn("blank", error_msg)

    def test_asn_feed_ignores_feed_size(self):
        response = self.client.get(self.url + "?feed_size=1")
        results = response.json()
        # aggregation should return all ASNs regardless of feed_size
        self.assertEqual(len(results), 2)

    def test_asn_feed_includes_as_name(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        results = self._get_results(response)

        high_item = next((item for item in results if str(item["asn"]) == self.high_asn), None)

        self.assertIsNotNone(high_item)
        self.assertIn("as_name", high_item)
        self.assertEqual(high_item["as_name"], "CLOUDFLARE")

    def test_asn_feed_with_empty_as_name(self):
        """
        Ensure ASN feed works even if the AS name is empty,
        """
        # Temporarily blank the name of the low AS
        original_name = self.as_low.name
        self.as_low.name = ""
        self.as_low.save(update_fields=["name"])

        try:
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
            results = self._get_results(response)

            # Find the low ASN in results
            item = next((r for r in results if str(r["asn"]) == self.low_asn), None)
            self.assertIsNotNone(item)

            # as_name should exist and be blank
            self.assertIn("as_name", item)
            self.assertEqual(item["as_name"], "")
        finally:
            # Restore original name
            self.as_low.name = original_name
            self.as_low.save(update_fields=["name"])

    def test_asn_feed_caching_behavior(self):
        """
        Verify that identical requests to the ASN feed return cached results,
        and that bumping the IOC data version forces a re-computation.
        """
        # 1. First request computes and caches the result
        response1 = self.client.get(self.url)
        self.assertEqual(response1.status_code, 200)
        results1 = self._get_results(response1)
        high_item1 = next((item for item in results1 if str(item["asn"]) == self.high_asn), None)
        self.assertIsNotNone(high_item1)

        # 2. Modify DB (e.g. change an IOC's attack count)
        original_attack_count = self.ioc_high1.attack_count
        self.ioc_high1.attack_count += 100
        self.ioc_high1.save(update_fields=["attack_count"])

        # 3. Second request should hit the cache and return SAME old value
        response2 = self.client.get(self.url)
        results2 = self._get_results(response2)
        high_item2 = next((item for item in results2 if str(item["asn"]) == self.high_asn), None)

        self.assertEqual(high_item1["total_attack_count"], high_item2["total_attack_count"])

        # 4. Invalidate the cache (simulate extraction cronjob behavior)
        self.cache.bump_data_version(IOC_DATA_VERSION_KEY)

        # 5. Third request should re-compute and show UPDATED DB value
        response3 = self.client.get(self.url)
        results3 = self._get_results(response3)
        high_item3 = next((item for item in results3 if str(item["asn"]) == self.high_asn), None)

        self.assertEqual(high_item3["total_attack_count"], high_item1["total_attack_count"] + 100)

        # Cleanup DB
        self.ioc_high1.attack_count = original_attack_count
        self.ioc_high1.save(update_fields=["attack_count"])
