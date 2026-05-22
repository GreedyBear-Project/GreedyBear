from rest_framework.test import APIClient

from greedybear.models import Sensor, Statistics, ViewType
from tests import CustomTestCase


class EnrichmentViewTestCase(CustomTestCase):
    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_for_vaild_unregistered_ip(self):
        """Check for a valid IP that is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=192.168.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_for_invaild_unregistered_ip(self):
        """Check for a IP that Fails Regex Checks and is unavaliable in DB"""
        response = self.client.get("/api/enrichment?query=30.168.1.255.1")
        self.assertEqual(response.status_code, 400)

    def test_for_vaild_registered_ip(self):
        """Check for a valid IP that is avaliable in DB"""
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], True)
        self.assertEqual(response.json()["ioc"]["name"], self.ioc.name)
        self.assertEqual(response.json()["ioc"]["type"], self.ioc.type)
        self.assertEqual(
            response.json()["ioc"]["first_seen"],
            self.ioc.first_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(
            response.json()["ioc"]["last_seen"],
            self.ioc.last_seen.isoformat(sep="T", timespec="microseconds"),
        )
        self.assertEqual(response.json()["ioc"]["number_of_days_seen"], self.ioc.number_of_days_seen)
        self.assertEqual(response.json()["ioc"]["attack_count"], self.ioc.attack_count)
        # Honeypots are now via M2M relationship (serialized as list of strings)
        honeypot_names = response.json()["ioc"]["general_honeypot"]
        self.assertIn(self.heralding.name, honeypot_names)
        self.assertIn(self.ciscoasa.name, honeypot_names)
        self.assertIn(self.cowrie_hp.name, honeypot_names)
        self.assertIn(self.log4pot_hp.name, honeypot_names)
        self.assertEqual(response.json()["ioc"]["scanner"], self.ioc.scanner)
        self.assertEqual(response.json()["ioc"]["payload_request"], self.ioc.payload_request)
        self.assertEqual(
            response.json()["ioc"]["recurrence_probability"],
            self.ioc.recurrence_probability,
        )
        self.assertEqual(
            response.json()["ioc"]["expected_interactions"],
            self.ioc.expected_interactions,
        )

    def test_for_invalid_authentication(self):
        """Check for a invalid authentication"""
        self.client.logout()
        response = self.client.get("/api/enrichment?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)

    def test_invalid_ip_octet_over_255(self):
        """IPs with octets > 255 should be rejected (fixes #881)"""
        response = self.client.get("/api/enrichment?query=999.999.999.999")
        self.assertEqual(response.status_code, 400)

    def test_invalid_ip_octet_256(self):
        """IP with octet = 256 should be rejected"""
        response = self.client.get("/api/enrichment?query=256.1.1.1")
        self.assertEqual(response.status_code, 400)

    def test_valid_ipv6_address(self):
        """Valid IPv6 addresses should be accepted"""
        response = self.client.get("/api/enrichment?query=2001:db8::1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_query_with_whitespace(self):
        """Query with leading/trailing whitespace should be handled"""
        response = self.client.get("/api/enrichment?query=  192.168.0.1  ")
        self.assertEqual(response.status_code, 200)

    def test_valid_domain(self):
        """Valid domain names should be accepted"""
        response = self.client.get("/api/enrichment?query=example.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], False)

    def test_enrichment_includes_sensors(self):
        """Sensors field appears in enrichment response for authenticated users."""

        sensor = Sensor.objects.create(address="10.0.0.3", label="enrichment-sensor")
        self.ioc.sensors.add(sensor)
        response = self.client.get(f"/api/enrichment?query={self.ioc.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["found"], True)
        sensors = response.json()["ioc"]["sensors"]
        self.assertEqual(len(sensors), 1)
        self.assertEqual(sensors[0]["address"], "10.0.0.3")
        self.assertEqual(sensors[0]["label"], "enrichment-sensor")

    def test_statistics_source_prefers_forwarded_ipv6(self):
        """Statistics source should store the first valid forwarded IPv6 address."""
        response = self.client.get(
            "/api/enrichment?query=192.168.0.1",
            HTTP_X_FORWARDED_FOR="2001:db8::1, 198.51.100.5",
            REMOTE_ADDR="10.0.0.1",
        )

        self.assertEqual(response.status_code, 200)
        latest = Statistics.objects.filter(view=ViewType.ENRICHMENT_VIEW.value).order_by("-id").first()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.source, "2001:db8::1")
