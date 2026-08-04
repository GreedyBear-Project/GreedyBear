"""
Tests for the Heralding credential-catching honeypot extraction strategy.
"""

from unittest.mock import Mock, patch

from django.test import override_settings

from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies.heralding import (
    HERALDING_HONEYPOT,
    HERALDING_PROTOCOLS,
    HeraldingExtractionStrategy,
    normalize_credential_field,
)

from . import ExtractionTestCase


@override_settings(THREATFOX_API_KEY="")
class TestHeraldingExtractionStrategy(ExtractionTestCase):
    """Tests for the main extract_from_hits entrypoint."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_extract_scanner_ips(self, mock_threatfox, mock_credential_objects, mock_iocs_from_hits):
        """Scanner IPs are extracted as SCANNER-type IOCs linked to Heralding."""
        mock_credential_objects.get_or_create.return_value = (Mock(), True)
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "proto": "ssh", "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        mock_iocs_from_hits.assert_called_once_with(hits)
        self.strategy.ioc_processor.add_ioc.assert_any_call(
            mock_ioc,
            attack_type=SCANNER,
            honeypot_name=HERALDING_HONEYPOT,
        )
        self.assertEqual(len(self.strategy.ioc_records), 1)
        mock_threatfox.assert_called_once()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_none_ioc_record_skipped(self, mock_credential_objects, mock_iocs_from_hits):
        """IOC records that resolve to None are silently skipped."""
        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]
        mock_credential_objects.get_or_create.return_value = (Mock(), True)
        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_multiple_scanners(self, mock_threatfox, mock_credential_objects, mock_iocs_from_hits):
        """Multiple scanner IPs from the same batch are all processed."""
        mock_credential_objects.get_or_create.return_value = (Mock(), True)
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [ioc1, ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[ioc1, ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "dest_port": 22, "proto": "ssh", "@timestamp": "2025-01-01T00:00:00"},
            {"src_ip": "5.6.7.8", "dest_port": 21, "proto": "ftp", "@timestamp": "2025-01-01T00:00:00"},
        ]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 2)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_extract_from_hits_calls_both_phases(self, mock_credential_objects, mock_iocs_from_hits):
        """extract_from_hits runs both scanner extraction and credential classification."""
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "proto": "ssh", "@timestamp": "2025-01-01T00:00:00"}]

        with (
            patch.object(self.strategy, "_get_scanners", wraps=self.strategy._get_scanners) as spy_scanners,
            patch.object(self.strategy, "_classify_credential_attacks", wraps=self.strategy._classify_credential_attacks) as spy_classify,
        ):
            self.strategy.extract_from_hits(hits)

        spy_scanners.assert_called_once_with(hits)
        spy_classify.assert_called_once_with(hits)


class TestHeraldingProtocolExtraction(ExtractionTestCase):
    """Tests for _extract_protocol helper."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_known_protocol_returned(self):
        for proto in ["ssh", "ftp", "telnet", "http", "https", "pop3", "imap", "smtp", "vnc", "rdp", "socks5"]:
            with self.subTest(protocol=proto):
                hit = {"src_ip": "1.2.3.4", "proto": proto}
                result = self.strategy._extract_protocol(hit)
                self.assertEqual(result, proto)

    def test_protocol_normalised_to_lowercase(self):
        hit = {"src_ip": "1.2.3.4", "proto": "SSH"}
        result = self.strategy._extract_protocol(hit)
        self.assertEqual(result, "ssh")

    def test_protocol_with_whitespace_stripped(self):
        hit = {"src_ip": "1.2.3.4", "proto": "  ftp  "}
        result = self.strategy._extract_protocol(hit)
        self.assertEqual(result, "ftp")

    def test_missing_protocol_field_returns_none(self):
        hit = {"src_ip": "1.2.3.4"}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)

    def test_empty_protocol_field_returns_none(self):
        hit = {"src_ip": "1.2.3.4", "proto": ""}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)

    def test_unknown_protocol_returns_none(self):
        hit = {"src_ip": "1.2.3.4", "proto": "unknown_proto"}
        result = self.strategy._extract_protocol(hit)
        self.assertIsNone(result)


@override_settings(THREATFOX_API_KEY="")
class TestHeraldingCredentialClassification(ExtractionTestCase):
    """Tests for _classify_credential_attacks and credential persistence logic."""

    def setUp(self):
        super().setUp()
        self.strategy = HeraldingExtractionStrategy(
            honeypot="Heralding",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_protocol_persisted_on_credential(self, mock_credential_objects, mock_iocs_from_hits):
        """A valid protocol and credential pair is persisted on Credential."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_called_once_with(
            username="root",
            password="toor",
            protocol="ssh",
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_multiple_protocols_all_stored(self, mock_credential_objects, mock_iocs_from_hits):
        """Credential tuples for multiple protocols are all stored."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "u1", "password": "p1"},
            {"src_ip": "1.2.3.4", "proto": "ftp", "username": "u2", "password": "p2"},
            {"src_ip": "1.2.3.4", "proto": "telnet", "username": "u3", "password": "p3"},
        ]
        self.strategy.extract_from_hits(hits)

        stored_protocols = {call[1]["protocol"] for call in mock_credential_objects.get_or_create.call_args_list}
        self.assertEqual(stored_protocols, {"ssh", "ftp", "telnet"})

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_duplicate_credential_protocol_deduplicated(self, mock_credential_objects, mock_iocs_from_hits):
        """Repeated hits for same username/password/protocol are deduplicated per batch."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor"},
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor"},
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor"},
        ]
        self.strategy.extract_from_hits(hits)

        ssh_calls = [c for c in mock_credential_objects.get_or_create.call_args_list if c[1]["protocol"] == "ssh"]
        self.assertEqual(len(ssh_calls), 1)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_missing_credentials_skipped(self, mock_credential_objects, mock_iocs_from_hits):
        """Hits with protocol but no credentials are ignored in classification."""
        mock_iocs_from_hits.return_value = []
        hits = [{"src_ip": "1.2.3.4", "proto": "ssh"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_unknown_protocol_not_stored(self, mock_credential_objects, mock_iocs_from_hits):
        """Hits with an unknown protocol value do not produce credentials."""
        mock_iocs_from_hits.return_value = []

        hits = [{"src_ip": "1.2.3.4", "proto": "bogus_protocol", "username": "root", "password": "root"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_missing_password_stores_empty_string(self, mock_credential_objects, mock_iocs_from_hits):
        """Missing password is normalized to empty string for persistence."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "9.9.9.9", "proto": "ssh", "username": "root"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_called_once_with(
            username="root",
            password="",
            protocol="ssh",
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_new_credential_increments_counter(self, mock_credential_objects, mock_iocs_from_hits):
        """Creating a new credential increments credentials_added."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "proto": "ftp", "username": "root", "password": "root"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.credentials_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_existing_credential_not_counted(self, mock_credential_objects, mock_iocs_from_hits):
        """Existing credentials (get_or_create returns created=False) do not increment counter."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), False)

        hits = [{"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "root"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(self.strategy.credentials_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_two_credentials_same_protocol_both_stored(self, mock_credential_objects, mock_iocs_from_hits):
        """Different username/password tuples are both stored for the same protocol."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor"},
            {"src_ip": "5.6.7.8", "proto": "ssh", "username": "admin", "password": "admin"},
        ]
        self.strategy.extract_from_hits(hits)

        stored_users = {call[1]["username"] for call in mock_credential_objects.get_or_create.call_args_list}
        self.assertEqual(stored_users, {"root", "admin"})

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_hits_without_protocol_produce_no_credentials(self, mock_credential_objects, mock_iocs_from_hits):
        """Hits without protocol are ignored during credential classification."""
        mock_iocs_from_hits.return_value = []

        hits = [{"src_ip": "1.2.3.4", "dest_port": 22, "username": "root", "password": "root"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_not_called()

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_null_byte_credentials_are_normalized(self, mock_credential_objects, mock_iocs_from_hits):
        """NUL bytes in credentials are replaced before persistence."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        hits = [{"src_ip": "1.2.3.4", "proto": "ssh", "username": "ro\x00ot", "password": "pa\x00ss"}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_called_once_with(
            username="ro[NUL]ot",
            password="pa[NUL]ss",
            protocol="ssh",
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_credential_fields_are_truncated_to_model_length(self, mock_credential_objects, mock_iocs_from_hits):
        """Credential fields longer than model max_length are truncated."""
        mock_iocs_from_hits.return_value = []
        mock_credential_objects.get_or_create.return_value = (Mock(), True)

        long_username = "u" * 400
        long_password = "p" * 500
        hits = [{"src_ip": "1.2.3.4", "proto": "ssh", "username": long_username, "password": long_password}]
        self.strategy.extract_from_hits(hits)

        mock_credential_objects.get_or_create.assert_called_once_with(
            username="u" * 256,
            password="p" * 256,
            protocol="ssh",
        )

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_credential_sources_linked(self, mock_threatfox, mock_credential_objects, mock_iocs_from_hits):
        """Credentials are linked to their source IOC via credential.sources.add()."""
        mock_credential = Mock()
        mock_credential_objects.get_or_create.return_value = (mock_credential, True)
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor", "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        mock_credential.sources.add.assert_called_once_with(mock_ioc)

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.threatfox_submission")
    def test_credential_sources_multiple_ips(self, mock_threatfox, mock_credential_objects, mock_iocs_from_hits):
        """Same credential from two IPs links both sources."""
        mock_credential = Mock()
        mock_credential_objects.get_or_create.return_value = (mock_credential, True)
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [ioc1, ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[ioc1, ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "proto": "ssh", "username": "root", "password": "toor", "@timestamp": "2025-01-01T00:00:00"},
            {"src_ip": "5.6.7.8", "proto": "ssh", "username": "root", "password": "toor", "@timestamp": "2025-01-01T00:00:00"},
        ]
        self.strategy.extract_from_hits(hits)

        linked_iocs = {call[0][0] for call in mock_credential.sources.add.call_args_list}
        self.assertEqual(linked_iocs, {ioc1, ioc2})

    @patch("greedybear.cronjobs.extraction.strategies.heralding.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.heralding.Credential.objects")
    def test_credential_sources_skipped_without_ioc(self, mock_credential_objects, mock_iocs_from_hits):
        """Credentials from IPs without a matching IOC record are not linked."""
        mock_credential = Mock()
        mock_credential_objects.get_or_create.return_value = (mock_credential, True)
        mock_iocs_from_hits.return_value = []

        hits = [{"src_ip": "9.9.9.9", "proto": "ssh", "username": "root", "password": "toor"}]
        self.strategy.extract_from_hits(hits)

        mock_credential.sources.add.assert_not_called()


class TestHeraldingCredentialNormalization(ExtractionTestCase):
    """Tests for normalize_credential_field helper."""

    def test_none_becomes_empty_string(self):
        self.assertEqual(normalize_credential_field(None), "")

    def test_truncates_to_max_length(self):
        self.assertEqual(normalize_credential_field("x" * 300), "x" * 256)


class TestHeraldingProtocolSet(ExtractionTestCase):
    """Validate the HERALDING_PROTOCOLS set for completeness and correctness."""

    def test_common_protocols_present(self):
        expected = {"ssh", "telnet", "ftp", "http", "https", "pop3", "imap", "smtp", "vnc", "rdp", "socks5"}
        for proto in expected:
            self.assertIn(proto, HERALDING_PROTOCOLS, f"Protocol {proto!r} missing from HERALDING_PROTOCOLS")

    def test_protocols_all_lowercase(self):
        for proto in HERALDING_PROTOCOLS:
            self.assertEqual(proto, proto.lower(), f"Protocol {proto!r} is not lowercase")

    def test_is_frozenset(self):
        self.assertIsInstance(HERALDING_PROTOCOLS, frozenset)

    def test_database_protocols_present(self):
        db_protocols = {"postgresql", "mysql", "mssql"}
        for proto in db_protocols:
            self.assertIn(proto, HERALDING_PROTOCOLS, f"DB protocol {proto!r} missing from HERALDING_PROTOCOLS")


class TestHeraldingFactoryIntegration(ExtractionTestCase):
    """Integration test: factory produces a HeraldingExtractionStrategy for 'Heralding'."""

    def test_factory_returns_heralding_strategy(self):
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory

        factory = ExtractionStrategyFactory(
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )
        strategy = factory.get_strategy("Heralding")
        self.assertIsInstance(strategy, HeraldingExtractionStrategy)

    def test_factory_returns_generic_for_unknown(self):
        from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
        from greedybear.cronjobs.extraction.strategies.generic import GenericExtractionStrategy

        factory = ExtractionStrategyFactory(
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )
        strategy = factory.get_strategy("UnknownHoneypot")
        self.assertIsInstance(strategy, GenericExtractionStrategy)
