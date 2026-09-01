from rest_framework.test import APIClient

from greedybear.models import Tag
from tests import CustomTestCase


class FeedsTagsTestCase(CustomTestCase):
    """Tests for tag integration in feed responses."""

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        # Create tags for test IOCs
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="threat_type", value="botnet_cc", source="threatfox")
        Tag.objects.create(ioc=self.ioc_2, key="confidence_of_abuse", value="84%", source="abuseipdb")

    def test_200_feeds_advanced_includes_tags(self):
        """Tags should appear in feeds_advanced JSON response."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("tags", target_ioc)
        self.assertEqual(len(target_ioc["tags"]), 2)

        tag_keys = {t["key"] for t in target_ioc["tags"]}
        self.assertIn("malware", tag_keys)
        self.assertIn("threat_type", tag_keys)

    def test_200_feeds_advanced_tags_structure(self):
        """Each tag dict should have key, value, source fields."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)

        for tag in target_ioc["tags"]:
            self.assertIn("key", tag)
            self.assertIn("value", tag)
            self.assertIn("source", tag)

    def test_200_feeds_advanced_ioc_without_tags(self):
        """IOCs without tags should have an empty tags list."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc_domain.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("tags", target_ioc)
        self.assertEqual(target_ioc["tags"], [])

    def test_200_feeds_advanced_no_id_in_response(self):
        """The internal 'id' field should not leak into the API response."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        for ioc in iocs:
            self.assertNotIn("id", ioc)

    def test_200_filter_by_tag_key(self):
        """Filtering by tag_key should return only IOCs with matching tags."""
        response = self.client.get("/api/feeds/advanced/?tag_key=malware")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        values = {i["value"] for i in iocs}
        self.assertIn(self.ioc.name, values)
        self.assertNotIn(self.ioc_domain.name, values)

    def test_200_filter_by_tag_value(self):
        """Filtering by tag_value should use case-insensitive substring match."""
        response = self.client.get("/api/feeds/advanced/?tag_value=mirai")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        values = {i["value"] for i in iocs}
        self.assertIn(self.ioc.name, values)

    def test_200_filter_by_tag_key_and_value(self):
        """Filtering by both tag_key and tag_value should narrow results."""
        response = self.client.get("/api/feeds/advanced/?tag_key=malware&tag_value=Mirai")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        values = {i["value"] for i in iocs}
        self.assertIn(self.ioc.name, values)

    def test_200_filter_by_tag_key_case_insensitive(self):
        """tag_key filtering must match regardless of the key's case in the DB or the query."""
        Tag.objects.create(ioc=self.ioc_2, key="Campaign", value="emotet", source="threatfox")

        for query_key in ("campaign", "CAMPAIGN", "Campaign"):
            with self.subTest(tag_key=query_key):
                response = self.client.get(f"/api/feeds/advanced/?tag_key={query_key}")
                self.assertEqual(response.status_code, 200)
                values = {i["value"] for i in response.json()["iocs"]}
                self.assertIn(self.ioc_2.name, values)

    def test_200_filter_by_tag_key_no_match(self):
        """Filtering by a non-existent tag_key should return no IOCs."""
        response = self.client.get("/api/feeds/advanced/?tag_key=nonexistent")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 0)

    def test_200_feeds_advanced_paginated_includes_tags(self):
        """Tags should appear in paginated feeds_advanced response."""
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["results"]["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("tags", target_ioc)
        self.assertEqual(len(target_ioc["tags"]), 2)

    def test_401_feeds_advanced_unauthenticated(self):
        """Unauthenticated requests should be rejected."""
        self.client.logout()
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 401)

    def test_200_public_feeds_ignores_tag_filter(self):
        """Tag filtering should be ignored on the public feeds endpoint."""
        # Public endpoint should return all IOCs regardless of tag_key param
        response = self.client.get("/api/feeds/?tag_key=nonexistent&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["results"]["iocs"]
        # Should still return IOCs (filter not applied)
        self.assertGreater(len(iocs), 0)

    def test_200_public_feeds_includes_tags(self):
        """Public feeds endpoint should also include tags in JSON response."""
        response = self.client.get("/api/feeds/?page_size=10&page=1")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["results"]["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("tags", target_ioc)
        self.assertEqual(len(target_ioc["tags"]), 2)

    def test_200_tags_do_not_bleed_between_iocs(self):
        """Tags from one IOC should not appear on another IOC."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        ioc_1 = next((i for i in iocs if i["value"] == self.ioc.name), None)
        ioc_2 = next((i for i in iocs if i["value"] == self.ioc_2.name), None)
        self.assertIsNotNone(ioc_1)
        self.assertIsNotNone(ioc_2)

        # ioc has malware + threat_type (2 tags), ioc_2 has confidence_of_abuse (1 tag)
        self.assertEqual(len(ioc_1["tags"]), 2)
        self.assertEqual(len(ioc_2["tags"]), 1)
        ioc_1_keys = {t["key"] for t in ioc_1["tags"]}
        ioc_2_keys = {t["key"] for t in ioc_2["tags"]}
        self.assertNotIn("confidence_of_abuse", ioc_1_keys)
        self.assertNotIn("malware", ioc_2_keys)

    def test_200_multi_source_tags_on_same_ioc(self):
        """Tags from multiple sources should all appear on the same IOC."""
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="90%", source="abuseipdb")

        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        # 2 threatfox tags + 1 abuseipdb tag
        self.assertEqual(len(target_ioc["tags"]), 3)
        sources = {t["source"] for t in target_ioc["tags"]}
        self.assertEqual(sources, {"threatfox", "abuseipdb"})


class EnrichmentTagsTestCase(CustomTestCase):
    """Tests for tag integration in enrichment API responses."""

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        Tag.objects.create(ioc=self.ioc, key="malware", value="Mirai", source="threatfox")
        Tag.objects.create(ioc=self.ioc, key="confidence_of_abuse", value="84%", source="abuseipdb")

    def test_200_enrichment_includes_tags(self):
        """Enrichment response should include tags for found IOC."""
        response = self.client.get(f"/api/enrichment?query={self.ioc.name}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["found"])

        ioc_data = response.json()["ioc"]
        self.assertIn("tags", ioc_data)
        self.assertEqual(len(ioc_data["tags"]), 2)

    def test_200_enrichment_tags_structure(self):
        """Each tag in enrichment response should have key, value, source."""
        response = self.client.get(f"/api/enrichment?query={self.ioc.name}")
        self.assertEqual(response.status_code, 200)

        tags = response.json()["ioc"]["tags"]
        for tag in tags:
            self.assertIn("key", tag)
            self.assertIn("value", tag)
            self.assertIn("source", tag)

    def test_200_enrichment_not_found_no_tags(self):
        """Enrichment response for unfound IOC should have no ioc/tags data."""
        response = self.client.get("/api/enrichment?query=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["found"])
        self.assertIsNone(response.json()["ioc"])
