import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from rest_framework.test import APIClient

from api.throttles import SharedFeedRateThrottle
from greedybear.models import IOC, AutonomousSystem, Credential, IocType, Sensor, ShareToken
from tests import CustomTestCase


class FeedsAdvancedViewTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_200_all_feeds(self):
        response = self.client.get("/api/feeds/advanced/")
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

    def test_200_general_feeds(self):
        response = self.client.get("/api/feeds/advanced/?feed_type=heralding")
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

    def test_400_feeds(self):
        response = self.client.get("/api/feeds/advanced/?attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 4)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_include(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&include_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_mass(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=mass%20scanner")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_200_feeds_pagination_exclude_tor(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&exclude_reputation=tor%20exit%20node")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 3)
        self.assertEqual(response.json()["total_pages"], 1)

    def test_400_feeds_pagination(self):
        response = self.client.get("/api/feeds/advanced/?paginate=true&page_size=10&page=1&attack_type=test")
        self.assertEqual(response.status_code, 400)

    def test_200_feed_contains_attacker_country(self):
        """
        Ensures that the response includes the attacker_country field.
        """
        self.ioc.attacker_country = "Nepal"
        self.ioc.save()

        response = self.client.get("/api/feeds/advanced/")

        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)

        self.assertIsNotNone(target_ioc)
        self.assertEqual(target_ioc["attacker_country"], "Nepal")

    def test_200_feed_contains_attacker_country_code(self):
        """
        Ensures that the response includes the attacker_country_code field.
        """
        self.ioc.attacker_country_code = "NP"
        self.ioc.save()
        response = self.client.get("/api/feeds/advanced/")
        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertEqual(target_ioc["attacker_country_code"], "NP")

    def test_400_invalid_credential_count_range(self):
        """min_credential_count greater than max_credential_count returns 400."""
        response = self.client.get("/api/feeds/advanced/?min_credential_count=10&max_credential_count=5")
        self.assertEqual(response.status_code, 400)

    def test_feeds_advanced_includes_sensors(self):
        """Sensors field appears in feeds_advanced response for authenticated users."""
        sensor = Sensor.objects.create(address="10.0.0.1", label="test-sensor")
        self.ioc.sensors.add(sensor)
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("sensors", target_ioc)
        self.assertEqual(len(target_ioc["sensors"]), 1)
        self.assertEqual(target_ioc["sensors"][0]["address"], "10.0.0.1")
        self.assertEqual(target_ioc["sensors"][0]["label"], "test-sensor")

    def test_public_feeds_excludes_sensors(self):
        """Sensors field must NOT appear in public feeds response."""
        sensor = Sensor.objects.create(address="10.0.0.2", label="secret-sensor")
        self.ioc.sensors.add(sensor)
        self.client.logout()
        response = self.client.get("/api/feeds/cowrie/all/recent.json")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        for ioc in iocs:
            self.assertNotIn("sensors", ioc)

    def test_min_credential_count_filter(self):
        """IOCs with fewer credentials than min_credential_count are excluded."""
        cred1 = Credential.objects.create(username="admin", password="admin")
        cred2 = Credential.objects.create(username="root", password="1234")
        self.ioc.credentials.add(cred1, cred2)

        response = self.client.get("/api/feeds/advanced/?min_credential_count=2")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertGreaterEqual(target_ioc["credential_count"], 2)

    def test_max_credential_count_filter(self):
        """IOCs with more credentials than max_credential_count are excluded."""
        cred1 = Credential.objects.create(username="admin", password="admin")
        cred2 = Credential.objects.create(username="root", password="1234")
        self.ioc.credentials.add(cred1, cred2)

        response = self.client.get("/api/feeds/advanced/?max_credential_count=1")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        # self.ioc has 2 credentials so it should be excluded
        self.assertIsNone(target_ioc)

    def test_credential_count_in_response(self):
        """credential_count field is present in JSON response when filtering by credential count."""
        cred1 = Credential.objects.create(username="admin", password="admin")
        self.ioc.credentials.add(cred1)
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        target_ioc = next((i for i in iocs if i["value"] == self.ioc.name), None)
        self.assertIsNotNone(target_ioc)
        self.assertIn("credential_count", target_ioc)
        self.assertEqual(target_ioc["credential_count"], 1)


class FeedsEnhancementsTestCase(CustomTestCase):
    """Tests for advanced filtering, STIX export, and shareable feeds functionality."""

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

        as_obj1, _ = AutonomousSystem.objects.get_or_create(asn=11111, defaults={"name": ""})
        as_obj2, _ = AutonomousSystem.objects.get_or_create(asn=22222, defaults={"name": ""})
        self.ioc.autonomous_system = as_obj1
        # Give the base IOC unique values to isolate filter tests
        self.ioc.destination_ports = [9001, 9002]
        self.ioc.recurrence_probability = 0.8
        self.ioc.expected_interactions = 10.0
        self.ioc.save()

        # Second IOC for contrast
        self.ioc2 = IOC.objects.create(
            name="10.0.0.50",
            type=IocType.IP.value,
            days_seen=[datetime.now()],
            number_of_days_seen=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            first_seen=datetime.now() - timedelta(days=1),
            last_seen=datetime.now(),
            recurrence_probability=0.2,
            expected_interactions=1.0,
            autonomous_system=as_obj2,
            destination_ports=[9003],
            attack_count=1,
            interaction_count=1,
            login_attempts=0,
        )
        self.ioc2.honeypots.add(self.cowrie_hp)
        self.ioc2.save()

    # ── Advanced filtering ────────────────────────────────────────────────────

    def test_filter_by_asn(self):
        """Filter by ASN returns only matching IOC."""
        response = self.client.get("/api/feeds/advanced/?asn=11111")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)
        self.assertEqual(iocs[0]["asn"], 11111)

    def test_filter_by_min_score(self):
        """Filter by min_score=0.5 excludes low-score IOC."""
        response = self.client.get("/api/feeds/advanced/?min_score=0.5")
        self.assertEqual(response.status_code, 200)
        values = [i["value"] for i in response.json()["iocs"]]
        self.assertIn(self.ioc.name, values)
        self.assertNotIn(self.ioc2.name, values)

    def test_filter_by_min_score_zero(self):
        """Edge case: min_score=0 must NOT be ignored (previously a bug)."""
        response = self.client.get("/api/feeds/advanced/?asn=11111&min_score=0")
        self.assertEqual(response.status_code, 200)
        # ioc has recurrence_probability=0.8 >= 0, so it should be returned
        values = [i["value"] for i in response.json()["iocs"]]
        self.assertIn(self.ioc.name, values)

    def test_filter_by_min_expected_interactions(self):
        """Filter by min_expected_interactions=5.0 excludes low-score IOC."""
        response = self.client.get("/api/feeds/advanced/?min_expected_interactions=5.0")
        self.assertEqual(response.status_code, 200)
        values = [i["value"] for i in response.json()["iocs"]]
        self.assertIn(self.ioc.name, values)
        self.assertNotIn(self.ioc2.name, values)

    def test_filter_by_min_expected_interactions_zero(self):
        """Edge case: min_expected_interactions=0 must NOT be ignored."""
        response = self.client.get("/api/feeds/advanced/?asn=11111&min_expected_interactions=0")
        self.assertEqual(response.status_code, 200)
        # ioc has expected_interactions=10.0 >= 0, so it should be returned
        values = [i["value"] for i in response.json()["iocs"]]
        self.assertIn(self.ioc.name, values)

    def test_filter_by_port(self):
        """Filter by destination port returns only matching IOC."""
        response = self.client.get("/api/feeds/advanced/?port=9001")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)

        response = self.client.get("/api/feeds/advanced/?port=9003")
        self.assertEqual(len(response.json()["iocs"]), 1)
        self.assertEqual(response.json()["iocs"][0]["value"], self.ioc2.name)

    def test_filter_combined(self):
        """Combined filter (asn + min_score + min_expected_interactions + port) narrows results correctly."""
        response = self.client.get("/api/feeds/advanced/?asn=11111&min_score=0.5&min_expected_interactions=5.0&port=9001")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)

    def test_filter_by_date_range(self):
        """Date range filter: today range returns IOCs, future range returns none."""
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

        response = self.client.get(f"/api/feeds/advanced/?start_date={today}&end_date={tomorrow}")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()["iocs"]), 1)

        future_start = (datetime.now() + timedelta(days=2)).strftime("%Y-%m-%d")
        response = self.client.get(f"/api/feeds/advanced/?start_date={future_start}")
        self.assertEqual(response.json()["iocs"], [])

    def test_filter_by_country_code(self):
        """Filter by country_code returns only matching IOCs."""
        self.ioc.attacker_country_code = "IT"
        self.ioc.save()
        self.ioc2.attacker_country_code = "FR"
        self.ioc2.save()

        response = self.client.get("/api/feeds/advanced/?country_code=IT")
        self.assertEqual(response.status_code, 200)
        iocs = response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)

    # ── STIX 2.1 export ──────────────────────────────────────────────────────

    def test_stix_21_export_ip(self):
        """STIX export for IP-type IOC produces a valid bundle with ipv4-addr indicator."""
        response = self.client.get("/api/feeds/advanced/?format_=stix21")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["type"], "bundle")
        patterns = [obj["pattern"] for obj in data["objects"]]
        self.assertIn(f"[ipv4-addr:value = '{self.ioc.name}']", patterns)

    def test_stix_21_export_domain(self):
        """STIX export for domain-type IOC produces a domain-name indicator."""
        # ioc_domain is built by CustomTestCase.setUpTestData
        response = self.client.get("/api/feeds/advanced/?format_=stix21")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        patterns = [obj["pattern"] for obj in data["objects"]]
        self.assertIn(f"[domain-name:value = '{self.ioc_domain.name}']", patterns)

    # ── Shareable feeds ───────────────────────────────────────────────────────

    def test_shareable_feeds_flow(self):
        """Full flow: share → consume unauthenticated returns correct IOCs."""
        share_response = self.client.get("/api/feeds/share?asn=11111&port=9001")
        self.assertEqual(share_response.status_code, 200)
        share_data = share_response.json()
        share_url = share_data["url"]
        self.assertIn("/api/feeds/consume/", share_url)
        self.assertIn("revoke_url", share_data)
        self.assertIn("/api/feeds/revoke/", share_data["revoke_url"])

        token = share_url.split("/")[-1]

        self.client.logout()
        consume_response = self.client.get(f"/api/feeds/consume/{token}")
        self.assertEqual(consume_response.status_code, 200)
        iocs = consume_response.json()["iocs"]
        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["value"], self.ioc.name)

    def test_shareable_feed_invalid_token(self):
        """Consuming a malformed token returns 400."""
        self.client.logout()
        response = self.client.get("/api/feeds/consume/invalid-token-123")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Invalid or expired token")

    def test_shareable_feed_expired_token(self):
        """Consuming a tampered/expired token returns 400."""
        data = {
            "feed_type": "all",
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "3",
            "min_days_seen": "1",
            "include_reputation": [],
            "exclude_reputation": [],
            "feed_size": "5000",
            "ordering": "-last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
            "asn": None,
            "min_score": None,
            "port": None,
            "start_date": None,
            "end_date": None,
        }
        token = signing.dumps(data, salt="greedybear-feeds")
        tampered = token + "TAMPERED"
        self.client.logout()
        response = self.client.get(f"/api/feeds/consume/{tampered}")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_consume_valid_token_without_db_record_is_rejected(self):
        """A valid signed token that was never saved to the DB is rejected (allowlist check)."""
        data = {
            "feed_type": "all",
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "3",
            "min_days_seen": "1",
            "include_reputation": [],
            "exclude_reputation": [],
            "feed_size": "5000",
            "ordering": "-last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
            "asn": None,
            "min_score": None,
            "port": None,
            "start_date": None,
            "end_date": None,
        }
        token = signing.dumps(data, salt="greedybear-feeds")
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        self.assertFalse(ShareToken.objects.filter(token_hash=token_hash).exists())

        self.client.logout()
        response = self.client.get(f"/api/feeds/consume/{token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Invalid or expired token")

    def test_consume_token_deleted_from_db_is_rejected(self):
        """A token whose DB record has been deleted is rejected even though the signature is valid."""
        share_response = self.client.get("/api/feeds/share?asn=11111")
        self.assertEqual(share_response.status_code, 200)
        token = share_response.json()["url"].split("/")[-1]

        self.client.logout()
        self.assertEqual(self.client.get(f"/api/feeds/consume/{token}").status_code, 200)

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        ShareToken.objects.filter(token_hash=token_hash).delete()

        response = self.client.get(f"/api/feeds/consume/{token}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Invalid or expired token")

    def test_rate_limiting_consume(self):
        """
        Shared feed endpoint enforces rate limiting on the /feeds/consume/ endpoint.

        Patches SharedFeedRateThrottle.THROTTLE_RATES to enforce a 1/minute rate,
        then verifies the second request within the window returns 429.
        cache.clear() is scoped to this test to avoid leaking throttle state.
        """
        share_response = self.client.get("/api/feeds/share")
        token = share_response.json()["url"].split("/")[-1]
        anon = APIClient()

        cache.clear()
        with patch.object(SharedFeedRateThrottle, "THROTTLE_RATES", {"feeds_shared": "1/minute"}):
            r1 = anon.get(f"/api/feeds/consume/{token}")
            r2 = anon.get(f"/api/feeds/consume/{token}")
        cache.clear()

        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 429)

    def test_token_revocation(self):
        """Revoking a token makes subsequent consume calls return 400."""
        share_response = self.client.get("/api/feeds/share?asn=11111")
        self.assertEqual(share_response.status_code, 200)
        token = share_response.json()["url"].split("/")[-1]

        revoke_response = self.client.get(f"/api/feeds/revoke/{token}")
        self.assertEqual(revoke_response.status_code, 200)

        self.client.logout()
        consume_response = self.client.get(f"/api/feeds/consume/{token}")
        self.assertEqual(consume_response.status_code, 400)
        self.assertEqual(consume_response.json()["error"], "Token has been revoked")

    def test_token_revoke_already_revoked(self):
        """Revoking an already-revoked token returns 200 (idempotent)."""
        share_response = self.client.get("/api/feeds/share?asn=11111")
        token = share_response.json()["url"].split("/")[-1]

        self.client.get(f"/api/feeds/revoke/{token}")
        second = self.client.get(f"/api/feeds/revoke/{token}")
        self.assertEqual(second.status_code, 200)
        self.assertIn("already revoked", second.json()["detail"])

    def test_token_revoke_invalid_token(self):
        """Revoking an invalid/expired token returns 400."""
        revoke_response = self.client.get("/api/feeds/revoke/not-a-valid-token")
        self.assertEqual(revoke_response.status_code, 400)
        self.assertIn("error", revoke_response.json())

    def test_200_format_txt(self):
        """Ensures ?format=txt returns plain text, not JSON."""
        response = self.client.get("/api/feeds/advanced/?format=txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")

    def test_200_format_csv(self):
        """Ensures ?format=csv returns CSV, not JSON."""
        response = self.client.get("/api/feeds/advanced/?format=csv")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
