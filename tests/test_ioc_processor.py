from datetime import date, datetime
from unittest.mock import Mock

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.enums import IpReputation
from greedybear.models import IocType

from . import ExtractionTestCase


class TestAddIoc(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_filters_sensor_ips(self):
        self.mock_sensor_repo.cache = {"192.168.1.1": Mock()}
        ioc = self._create_mock_ioc(name="192.168.1.1")

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertIsNone(result)
        self.mock_ioc_repo.save.assert_not_called()

    def test_filters_whatsmyip_domains(self):
        self.processor._whatsmyip_domains = {"some.domain.com"}
        ioc = self._create_mock_ioc(name="some.domain.com", ioc_type=IocType.DOMAIN)

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertIsNone(result)
        self.mock_ioc_repo.save.assert_not_called()

    def test_creates_new_ioc_when_not_exists(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        new_ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = new_ioc

        result = self.processor.add_ioc(new_ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once_with("1.2.3.4")
        self.mock_ioc_repo.save.assert_called()
        self.assertIsNotNone(result)

    def test_updates_existing_ioc_when_exists(self):
        self.mock_sensor_repo.cache = {}
        existing_ioc = self._create_mock_ioc(attack_count=5)
        self.mock_ioc_repo.get_ioc_by_name.return_value = existing_ioc
        new_ioc = self._create_mock_ioc(attack_count=1)
        self.mock_ioc_repo.save.return_value = existing_ioc

        result = self.processor.add_ioc(new_ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once_with("1.2.3.4")
        self.assertEqual(result.attack_count, 6)

    def test_sets_scanner_flag_for_scanner_attack_type(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertTrue(result.scanner)
        self.assertFalse(result.payload_request)

    def test_sets_payload_request_flag_for_payload_attack_type(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)

        self.assertFalse(result.scanner)
        self.assertTrue(result.payload_request)

    def test_adds_honeypot_when_provided(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc
        self.mock_ioc_repo.add_honeypot_to_ioc.return_value = ioc

        self.processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name="TestHoneypot")

        self.mock_ioc_repo.add_honeypot_to_ioc.assert_called_once_with("TestHoneypot", ioc)

    def test_skips_honeypot_when_not_provided(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        self.mock_ioc_repo.save.return_value = ioc

        self.processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name=None)

        self.mock_ioc_repo.add_honeypot_to_ioc.assert_not_called()

    def test_adds_sensors_from_attribute(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc()
        sensor1 = Mock()
        sensor2 = Mock()
        ioc._sensors_to_add = [sensor1, sensor2]

        self.mock_ioc_repo.save.return_value = ioc

        self.processor.add_ioc(ioc, attack_type=SCANNER)

        ioc.sensors.add.assert_called_once_with(sensor1, sensor2)

    def test_updates_days_seen_on_add(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc(days_seen=[], last_seen=datetime(2025, 1, 1, 12, 0, 0))
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)

    def test_full_create_flow(self):
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None

        ioc = self._create_mock_ioc(
            name="1.2.3.4",
            related_urls=["http://example.com"],
            destination_ports=[80, 443],
            days_seen=[],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.mock_ioc_repo.get_ioc_by_name.assert_called_once()
        self.assertEqual(self.mock_ioc_repo.save.call_count, 2)  # Once for create, once at end
        self.assertTrue(result.scanner)
        self.assertEqual(len(result.days_seen), 1)

    def test_full_update_flow(self):
        self.mock_sensor_repo.cache = {}

        existing = self._create_mock_ioc(
            attack_count=5,
            interaction_count=10,
            related_urls=["http://a.com"],
            destination_ports=[80],
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
            protocols=["ssh"],
            cves=["CVE-XXXXX-XXXXX"],
        )
        self.mock_ioc_repo.get_ioc_by_name.return_value = existing

        new = self._create_mock_ioc(
            attack_count=1,
            interaction_count=5,
            related_urls=["http://b.com"],
            destination_ports=[443],
            last_seen=datetime(2025, 1, 2, 12, 0, 0),
        )

        self.mock_ioc_repo.save.return_value = existing

        result = self.processor.add_ioc(new, attack_type=PAYLOAD_REQUEST)

        self.assertEqual(result.attack_count, 6)
        self.assertEqual(result.interaction_count, 15)
        self.assertEqual(len(result.related_urls), 2)
        self.assertEqual(len(result.destination_ports), 2)
        self.assertEqual(len(result.days_seen), 2)
        self.assertTrue(result.payload_request)

    def test_only_checks_whatsmyip_for_domains(self):
        self.processor._whatsmyip_domains = {"1.2.3.4"}
        self.mock_sensor_repo.cache = {}
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        ioc = self._create_mock_ioc(name="1.2.3.4", ioc_type=IocType.IP)
        self.mock_ioc_repo.save.return_value = ioc

        result = self.processor.add_ioc(ioc, attack_type=SCANNER)

        self.assertIsNotNone(result)


class TestMergeIocs(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_increment_and_add(self):
        existing = self._create_mock_ioc(
            attack_count=5,
            interaction_count=10,
            login_attempts=5,
        )
        new = self._create_mock_ioc(
            attack_count=1,
            interaction_count=3,
            login_attempts=2,
        )

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.attack_count, 6)
        self.assertEqual(result.interaction_count, 13)
        self.assertEqual(result.login_attempts, 7)

    def test_deduplication(self):
        existing = self._create_mock_ioc(
            related_urls=["http://a.com", "http://b.com"],
            destination_ports=[80, 443],
        )
        new = self._create_mock_ioc(
            related_urls=["http://b.com", "http://c.com"],
            destination_ports=[443, 8080],
        )

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(
            sorted(result.related_urls),
            ["http://a.com", "http://b.com", "http://c.com"],
        )
        self.assertEqual(result.destination_ports, [80, 443, 8080])

    def test_updating(self):
        old_time = datetime(2025, 1, 1, 12, 0, 0)
        new_time = datetime(2025, 1, 2, 12, 0, 0)
        existing = self._create_mock_ioc(first_seen=old_time, last_seen=old_time, ip_reputation="old", asn=12)
        new = self._create_mock_ioc(first_seen=new_time, last_seen=new_time, ip_reputation="new", asn=23)
        result = self.processor._merge_iocs(existing, new)
        self.assertEqual(result.last_seen, new_time)
        self.assertEqual(result.autonomous_system.asn, 23)
        self.assertEqual(result.first_seen, old_time)
        self.assertEqual(result.ip_reputation, "old")

    def test_last_seen_not_regressed(self):
        later = datetime(2025, 1, 2, 12, 0, 0)
        earlier = datetime(2025, 1, 1, 12, 0, 0)
        existing = self._create_mock_ioc(first_seen=earlier, last_seen=later)
        new = self._create_mock_ioc(first_seen=earlier, last_seen=earlier)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.last_seen, later)

    def test_first_seen_updated_to_earlier(self):
        later = datetime(2025, 1, 2, 12, 0, 0)
        earlier = datetime(2025, 1, 1, 12, 0, 0)
        existing = self._create_mock_ioc(first_seen=later, last_seen=later)
        new = self._create_mock_ioc(first_seen=earlier, last_seen=later)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.first_seen, earlier)

    def test_first_seen_not_advanced(self):
        later = datetime(2025, 1, 2, 12, 0, 0)
        earlier = datetime(2025, 1, 1, 12, 0, 0)
        existing = self._create_mock_ioc(first_seen=earlier, last_seen=later)
        new = self._create_mock_ioc(first_seen=later, last_seen=later)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.first_seen, earlier)

    def test_preserves_reputation_when_new_is_empty(self):
        """Existing ip_reputation must not be overwritten by an empty value."""
        existing = self._create_mock_ioc(ip_reputation=IpReputation.MASS_SCANNER)
        new = self._create_mock_ioc(ip_reputation="")

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.ip_reputation, IpReputation.MASS_SCANNER)

    def test_preserves_reputation_when_existing_is_set(self):
        """Existing ip_reputation must not be overwritten even if new has a value."""
        existing = self._create_mock_ioc(ip_reputation=IpReputation.TOR_EXIT_NODE)
        new = self._create_mock_ioc(ip_reputation=IpReputation.MASS_SCANNER)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.ip_reputation, IpReputation.TOR_EXIT_NODE)

    def test_fills_reputation_when_existing_is_empty(self):
        """Empty existing ip_reputation should be filled by a non-empty new value."""
        existing = self._create_mock_ioc(ip_reputation="")
        new = self._create_mock_ioc(ip_reputation=IpReputation.MASS_SCANNER)

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.ip_reputation, IpReputation.MASS_SCANNER)

    def test_handles_empty_urls_and_ports(self):
        existing = self._create_mock_ioc(related_urls=[], destination_ports=[])
        new = self._create_mock_ioc(related_urls=[], destination_ports=[])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.related_urls, [])
        self.assertEqual(result.destination_ports, [])

    def test_updates_firehol_categories(self):
        existing = self._create_mock_ioc(firehol_categories=[])
        new = self._create_mock_ioc(firehol_categories=["blocklist_de", "greensnow"])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(sorted(result.firehol_categories), ["blocklist_de", "greensnow"])

    def test_clears_stale_firehol_categories(self):
        existing = self._create_mock_ioc(firehol_categories=["greensnow"])
        new = self._create_mock_ioc(firehol_categories=[])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.firehol_categories, [])

    def test_updates_attacker_country_code(self):
        existing = self._create_mock_ioc(attacker_country_code="")
        new = self._create_mock_ioc(attacker_country_code="NP")

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.attacker_country_code, "NP")

    def test_preserves_attacker_country_code_when_new_is_empty(self):
        existing = self._create_mock_ioc(attacker_country_code="US")
        new = self._create_mock_ioc(attacker_country_code="")

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.attacker_country_code, "US")

    def test_rejects_invalid_length_attacker_country_code(self):
        existing = self._create_mock_ioc(attacker_country_code="US")
        new = self._create_mock_ioc(attacker_country_code="NPL")

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.attacker_country_code, "US")

    def test_merges_protocols(self):
        """Protocols from both IOCs are merged and deduplicated."""
        existing = self._create_mock_ioc(protocols=["tcp"])
        new = self._create_mock_ioc(protocols=["udp", "tcp"])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.protocols, ["tcp", "udp"])

    def test_merges_cves(self):
        """CVEs from both IOCs are merged and deduplicated."""
        existing = self._create_mock_ioc(cves=["CVE-2021-44228"])
        new = self._create_mock_ioc(cves=["CVE-2021-44228", "CVE-2022-0001"])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.cves, ["CVE-2021-44228", "CVE-2022-0001"])

    def test_handles_empty_protocols_and_cves(self):
        """Empty protocols and cves on both sides stay empty after merge."""
        existing = self._create_mock_ioc(protocols=[], cves=[])
        new = self._create_mock_ioc(protocols=[], cves=[])

        result = self.processor._merge_iocs(existing, new)

        self.assertEqual(result.protocols, [])
        self.assertEqual(result.cves, [])


class TestUpdateDaysSeen(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.processor = IocProcessor(self.mock_ioc_repo, self.mock_sensor_repo)

    def test_appends_new_date(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 2, 12, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertIn(date(2025, 1, 2), result.days_seen)
        self.assertEqual(result.number_of_days_seen, 2)

    def test_skips_duplicate_date(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 2)],
            last_seen=datetime(2025, 1, 2, 15, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)

    def test_handles_empty_days_seen(self):
        ioc = self._create_mock_ioc(
            days_seen=[],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        ioc.number_of_days_seen = 0

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)
        self.assertIn(date(2025, 1, 1), result.days_seen)

    def test_multiple_updates_same_day(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 12, 0, 0),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)
        self.assertEqual(len(result.days_seen), 1)

        result.last_seen = datetime(2025, 1, 1, 18, 0, 0)
        result = self.processor._update_days_seen(result)
        self.assertEqual(len(result.days_seen), 1)

    def test_handles_date_boundaries(self):
        ioc = self._create_mock_ioc(
            days_seen=[date(2025, 1, 1)],
            last_seen=datetime(2025, 1, 1, 23, 59, 59),
        )
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)
        self.assertEqual(len(result.days_seen), 1)

        result.last_seen = datetime(2025, 1, 2, 0, 0, 0)
        result = self.processor._update_days_seen(result)
        self.assertEqual(len(result.days_seen), 2)

    def test_sort_guard_non_chronological(self):
        """Sort guard heals non-chronological days_seen."""
        ioc = self._create_mock_ioc(
            last_seen=datetime(2025, 1, 4, 12, 0, 0),
        )
        ioc.days_seen = [date(2025, 1, 5)]
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(
            result.days_seen,
            [date(2025, 1, 4), date(2025, 1, 5)],
        )
        self.assertEqual(result.number_of_days_seen, 2)

    def test_sort_guard_adjacent_day_reversal(self):
        """Adjacent-day reversal is sorted — no ZeroDivisionError path."""
        ioc = self._create_mock_ioc(
            last_seen=datetime(2025, 1, 4, 23, 58, 0),
        )
        ioc.days_seen = [date(2025, 1, 5)]
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(
            result.days_seen,
            [date(2025, 1, 4), date(2025, 1, 5)],
        )
        self.assertEqual(result.number_of_days_seen, 2)

    def test_sort_guard_no_duplicate(self):
        """Duplicate date is not appended."""
        ioc = self._create_mock_ioc(
            last_seen=datetime(2025, 1, 5, 10, 0, 0),
        )
        ioc.days_seen = [date(2025, 1, 5)]
        ioc.number_of_days_seen = 1

        result = self.processor._update_days_seen(ioc)

        self.assertEqual(len(result.days_seen), 1)
        self.assertEqual(result.number_of_days_seen, 1)
