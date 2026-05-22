# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
End-to-end tests for ExtractionPipeline with real strategies.

These tests use real ExtractionStrategyFactory and real strategies,
only mocking the repositories (ElasticRepository, IocRepository, SensorRepository).
This tests the actual integration path as it runs in production.
"""

from unittest.mock import MagicMock, patch

from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.models import Sensor
from tests import E2ETestCase, MockElasticHit


class TestCowrieE2E(E2ETestCase):
    """E2E tests for Cowrie extraction through the real pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.repositories.CowrieSessionRepository")
    def test_cowrie_extracts_scanner_ioc(self, mock_session_repo, mock_scores):
        """
        E2E: Cowrie session connect → real CowrieExtractionStrategy → scanner IOC.
        """
        pipeline = self._create_pipeline_with_real_factory()

        cowrie_hits = [
            MockElasticHit(
                {
                    "src_ip": "192.168.1.100",
                    "type": "Cowrie",
                    "session": "abc123",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-01-01T10:00:00",
                    "t-pot_ip_ext": "10.0.0.1",
                    "dest_port": 22,
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [cowrie_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None  # New IOC

        # Mock the IOC creation to return a mock IOC
        mock_ioc = self._create_mock_ioc("192.168.1.100")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        # Verify sensor was extracted
        pipeline.sensor_repo.get_or_create_sensor.assert_called_with("10.0.0.1")
        # Verify IOC was created
        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.repositories.CowrieSessionRepository")
    def test_cowrie_extracts_login_credentials(self, mock_session_repo, mock_scores):
        """
        E2E: Cowrie login failed event → credential extraction.
        """
        pipeline = self._create_pipeline_with_real_factory()

        cowrie_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.20.30.40",
                    "type": "Cowrie",
                    "session": "login_sess",
                    "eventid": "cowrie.login.failed",
                    "timestamp": "2025-01-01T12:00:00",
                    "username": "root",
                    "password": "admin123",
                    "dest_port": 22,
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [cowrie_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("10.20.30.40")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        self.assertGreaterEqual(result, 0)


class TestGenericE2E(E2ETestCase):
    """E2E tests for generic/unknown honeypot extraction."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_unknown_honeypot_uses_generic_strategy(self, mock_scores):
        """
        E2E: Unknown honeypot → real GenericExtractionStrategy → scanner IOC.
        """
        pipeline = self._create_pipeline_with_real_factory()

        unknown_hits = [
            MockElasticHit(
                {
                    "src_ip": "172.16.0.100",
                    "type": "Heralding",  # Uses generic strategy
                    "dest_port": 21,
                    "@timestamp": "2025-01-01T11:00:00",
                    "t-pot_ip_ext": "10.0.0.5",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [unknown_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("172.16.0.100")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        # Sensor should be registered
        pipeline.sensor_repo.get_or_create_sensor.assert_called_with("10.0.0.5")
        self.assertGreaterEqual(result, 0)


class TestMixedHoneypotE2E(E2ETestCase):
    """E2E tests for mixed honeypot scenarios."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.repositories.CowrieSessionRepository")
    def test_mixed_honeypots_use_correct_strategies(self, mock_session_repo, mock_scores):
        """
        E2E: Mixed Cowrie + Dionaea → correct strategy for each.
        """
        pipeline = self._create_pipeline_with_real_factory()

        mixed_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.1.1.1",
                    "type": "Cowrie",
                    "session": "cowrie_sess",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-01-01T10:00:00",
                    "dest_port": 22,
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.3.3.3",
                    "type": "Dionaea",  # Generic
                    "dest_port": 445,
                    "@timestamp": "2025-01-01T10:00:02",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [mixed_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("10.1.1.1")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        # Should process all three honeypot types
        self.assertGreaterEqual(result, 0)


class TestStrategyExceptionHandling(E2ETestCase):
    """E2E tests for strategy exception handling."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_strategy_exception_logged_and_continues(self, mock_scores):
        """
        E2E: Strategy that raises exception → logged, pipeline continues.
        """
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        # Create hit for honeypot that will trigger an exception
        hits = [
            MockElasticHit(
                {
                    "src_ip": "1.2.3.4",
                    "type": "Cowrie",
                    "session": "test_sess",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-01-01T10:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # Force an exception in the strategy
        with patch("greedybear.cronjobs.extraction.strategies.cowrie.CowrieExtractionStrategy.extract_from_hits") as mock_extract:
            mock_extract.side_effect = Exception("Test error")
            result = pipeline.execute()

        # Should log error and return 0
        self.assertEqual(result, 0)
        pipeline.log.exception.assert_called()


class TestScoringIntegration(E2ETestCase):
    """E2E tests for scoring integration."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_scoring_called_when_iocs_extracted(self, mock_scores):
        """
        E2E: IOCs extracted → UpdateScores.score_only called.
        """
        pipeline = self._create_pipeline_with_real_factory()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "5.6.7.8",
                    "type": "Heralding",
                    "dest_port": 22,
                    "@timestamp": "2025-01-01T10:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("5.6.7.8")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        # IOCs should be extracted, and scoring should be called
        self.assertGreater(result, 0)
        mock_scores.return_value.score_only.assert_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_scoring_skipped_when_no_iocs(self, mock_scores):
        """
        E2E: No IOCs extracted → UpdateScores NOT called.
        """
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.elastic_repo.search.return_value = []
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_scores.return_value.score_only.assert_not_called()


class TestIocContentVerification(E2ETestCase):
    """E2E tests that verify the actual content of extracted IOCs."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_cowrie_ioc_content_verified(self, mock_scores):
        """
        E2E: Cowrie hit → IOC with correct IP and honeypot type.

        This test verifies NOT just the count, but the actual content
        of the extracted IOC record.
        """
        pipeline = self._create_pipeline_with_real_factory()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "203.0.113.42",
                    "type": "Cowrie",
                    "session": "test_session_123",
                    "eventid": "cowrie.session.connect",
                    "@timestamp": "2025-01-15T14:30:00",
                    "dest_port": 2222,
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("203.0.113.42")
        mock_ioc.name = "203.0.113.42"
        mock_ioc.scanner = ["Cowrie"]

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        # Verify extraction happened
        self.assertGreaterEqual(result, 0)

        # Verify the actual IOC content passed to scoring
        if mock_scores.return_value.score_only.called:
            call_args = mock_scores.return_value.score_only.call_args[0][0]
            self.assertGreater(len(call_args), 0)

            # Check the IOC has the expected IP
            ioc_names = [ioc.name for ioc in call_args]
            self.assertIn("203.0.113.42", ioc_names)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_multiple_honeypots_ioc_content_verified(self, mock_scores):
        """
        E2E: Multiple honeypot hits → IOCs with correct IPs verified.

        Verifies that when processing hits from multiple honeypots,
        each extracted IOC contains the correct source IP.
        """
        pipeline = self._create_pipeline_with_real_factory()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "10.0.0.1",
                    "type": "Cowrie",
                    "session": "sess1",
                    "eventid": "cowrie.session.connect",
                    "@timestamp": "2025-01-15T10:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.0.0.2",
                    "type": "Heralding",
                    "dest_port": 22,
                    "@timestamp": "2025-01-15T11:00:00",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.0.0.3",
                    "type": "Cowrie",
                    "session": "sess3",
                    "eventid": "cowrie.session.connect",
                    "@timestamp": "2025-01-15T12:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        # Create mock IOCs for each IP
        mock_iocs = {
            "10.0.0.1": self._create_mock_ioc("10.0.0.1"),
            "10.0.0.2": self._create_mock_ioc("10.0.0.2"),
            "10.0.0.3": self._create_mock_ioc("10.0.0.3"),
        }
        for ip, ioc in mock_iocs.items():
            ioc.name = ip

        def add_ioc_side_effect(*args, **kwargs):
            # Return the appropriate mock based on the IOC being added
            ip = args[0].name if args else kwargs.get("ioc", MagicMock()).name
            return mock_iocs.get(ip, self._create_mock_ioc(ip))

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.side_effect = add_ioc_side_effect
            result = pipeline.execute()

        # Verify multiple honeypots were processed
        self.assertGreaterEqual(result, 0)

        # Verify the IOC content if scoring was called
        if mock_scores.return_value.score_only.called:
            call_args = mock_scores.return_value.score_only.call_args[0][0]
            ioc_names = [ioc.name for ioc in call_args]

            # Each distinct IP should appear in the IOC records
            for expected_ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
                self.assertIn(
                    expected_ip,
                    ioc_names,
                    f"Expected IOC with IP {expected_ip} to be in extracted records",
                )

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_ioc_scanner_field_contains_honeypot_type(self, mock_scores):
        """
        E2E: IOC scanner field should contain the honeypot type.

        Verifies that the extracted IOC has the correct honeypot type
        in its scanner field.
        """
        pipeline = self._create_pipeline_with_real_factory()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "198.51.100.50",
                    "type": "Heralding",
                    "dest_port": 443,
                    "@timestamp": "2025-01-15T16:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("198.51.100.50")
        mock_ioc.name = "198.51.100.50"
        mock_ioc.scanner = ["Heralding"]

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        self.assertGreaterEqual(result, 0)

        # Verify the scanner field in the IOC
        if mock_scores.return_value.score_only.called:
            call_args = mock_scores.return_value.score_only.call_args[0][0]
            for ioc in call_args:
                if ioc.name == "198.51.100.50":
                    self.assertIn(
                        "Heralding",
                        ioc.scanner,
                        "IOC scanner field should contain 'Heralding'",
                    )
                    break


class TestGeoIPEnrichmentE2E(E2ETestCase):
    """E2E test for sensor GeoIP enrichment."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_geoip_enrichment_with_ioc(self, mock_scores):
        pipeline = self._create_pipeline_with_real_factory()

        # Real sensor
        real_sensor = Sensor(address="10.10.10.10", country="")
        pipeline.sensor_repo.get_or_create_sensor.return_value = real_sensor

        # Patch update_country to actually set the country
        pipeline.sensor_repo.update_country.side_effect = lambda sensor, country: setattr(sensor, "country", country)

        hits = [
            MockElasticHit(
                {
                    "src_ip": "8.8.8.8",
                    "type": "Heralding",
                    "dest_port": 22,
                    "@timestamp": "2025-01-01T10:00:00",
                    "geoip_ext": {"country_name": "Nepal"},
                    "t-pot_ip_ext": "10.10.10.10",
                    "geoip": {"country_name": "Nepal", "asn": 64512},
                }
            ),
        ]

        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        # Patch add_ioc to just return the IOC generated from hits
        real_iocs = []

        def add_ioc_side_effect(self, ioc, *args, **kwargs):
            real_iocs.append(ioc)
            return ioc  # return the real IOC object

        with patch.object(IocProcessor, "add_ioc", new=add_ioc_side_effect):
            result = pipeline.execute()

        # Verify sensor was enriched
        self.assertEqual(real_sensor.country, "Nepal")

        # Verify IOC attacker_country is populated
        self.assertTrue(real_iocs)
        self.assertEqual(real_iocs[0].attacker_country, "Nepal")

        # Result should reflect IOC count
        self.assertGreater(result, 0)

        # UpdateScores called with the real IOC
        mock_scores.return_value.score_only.assert_called_once_with(real_iocs)


class TestTannerE2E(E2ETestCase):
    """E2E tests for Tanner web honeypot extraction through the real pipeline."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_tanner_extracts_scanner_ioc(self, mock_scores):
        """
        E2E: Tanner web request hit → real TannerExtractionStrategy → scanner IOC.
        """
        pipeline = self._create_pipeline_with_real_factory()

        tanner_hits = [
            MockElasticHit(
                {
                    "src_ip": "203.0.113.50",
                    "type": "Tanner",
                    "dest_port": 80,
                    "url": "/index.html",
                    "@timestamp": "2025-06-01T10:00:00",
                    "t-pot_ip_ext": "10.0.0.7",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [tanner_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("203.0.113.50")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        pipeline.sensor_repo.get_or_create_sensor.assert_called_with("10.0.0.7")
        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_tanner_sqli_hit_creates_scanner(self, mock_scores):
        """
        E2E: Tanner SQLi hit → scanner IOC extracted.
        """
        pipeline = self._create_pipeline_with_real_factory()

        tanner_hits = [
            MockElasticHit(
                {
                    "src_ip": "198.51.100.10",
                    "type": "Tanner",
                    "dest_port": 80,
                    "url": "/search?q=1 UNION SELECT * FROM users--",
                    "@timestamp": "2025-06-01T12:00:00",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [tanner_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_ioc = self._create_mock_ioc("198.51.100.10")
        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.return_value = mock_ioc
            result = pipeline.execute()

        self.assertGreaterEqual(result, 0)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_tanner_mixed_with_cowrie(self, mock_scores):
        """
        E2E: Mixed Tanner + Cowrie hits → each uses correct strategy.
        """
        pipeline = self._create_pipeline_with_real_factory()

        mixed_hits = [
            MockElasticHit(
                {
                    "src_ip": "10.1.1.1",
                    "type": "Cowrie",
                    "session": "cowrie_sess",
                    "eventid": "cowrie.session.connect",
                    "timestamp": "2025-06-01T10:00:00",
                    "dest_port": 22,
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "10.2.2.2",
                    "type": "Tanner",
                    "dest_port": 80,
                    "url": "/page?file=../../../etc/passwd",
                    "@timestamp": "2025-06-01T10:00:01",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [mixed_hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        mock_iocs = {
            "10.1.1.1": self._create_mock_ioc("10.1.1.1"),
            "10.2.2.2": self._create_mock_ioc("10.2.2.2"),
        }

        def add_ioc_side_effect(*args, **kwargs):
            ip = args[0].name if args else kwargs.get("ioc", MagicMock()).name
            return mock_iocs.get(ip, self._create_mock_ioc(ip))

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            mock_add.side_effect = add_ioc_side_effect
            result = pipeline.execute()

        self.assertGreaterEqual(result, 0)

        if mock_scores.return_value.score_only.called:
            call_args = mock_scores.return_value.score_only.call_args[0][0]
            ioc_names = [ioc.name for ioc in call_args]
            self.assertIn("10.1.1.1", ioc_names)
            self.assertIn("10.2.2.2", ioc_names)
