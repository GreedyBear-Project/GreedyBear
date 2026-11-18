from unittest.mock import Mock, patch

from django.test import override_settings

from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies import GenericExtractionStrategy

from . import ExtractionTestCase


@override_settings(THREATFOX_API_KEY="")
class TestGenericExtractionStrategy(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = GenericExtractionStrategy(
            honeypot="TestHoneypot",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.base.threatfox_submission")
    def test_processes_enabled_honeypot(self, mock_threatfox, mock_iocs_from_hits):
        self.mock_ioc_repo.is_enabled.return_value = True

        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]

        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]

        self.strategy.extract_from_hits(hits)

        mock_iocs_from_hits.assert_called_once_with(hits)
        self.strategy.ioc_processor.add_ioc.assert_called_once_with(mock_ioc, attack_type=SCANNER, honeypot_name="TestHoneypot")
        self.assertEqual(len(self.strategy.ioc_records), 1)
        mock_threatfox.assert_called_once()

    @patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits")
    def test_handles_none_ioc_record(self, mock_iocs_from_hits):
        self.mock_ioc_repo.is_enabled.return_value = True
        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]

        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]

        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 0)

    @patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits")
    def test_processes_multiple_iocs(self, mock_iocs_from_hits):
        self.mock_ioc_repo.is_enabled.return_value = True

        mock_ioc1 = self._create_mock_ioc("1.2.3.4")
        mock_ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [mock_ioc1, mock_ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[mock_ioc1, mock_ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"},
            {
                "src_ip": "5.6.7.8",
                "dest_port": 443,
                "@timestamp": "2025-01-01T00:00:00",
            },
        ]

        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 2)
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 2)

    @patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits")
    def test_logs_correct_honeypot_name(self, mock_iocs_from_hits):
        self.mock_ioc_repo.is_enabled.return_value = True

        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]

        self.strategy.extract_from_hits(hits)

        call_kwargs = self.strategy.ioc_processor.add_ioc.call_args[1]
        self.assertEqual(call_kwargs["honeypot_name"], "TestHoneypot")

    @patch("greedybear.cronjobs.extraction.strategies.generic.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.base.threatfox_submission")
    def test_processes_ioc_with_sensors(self, mock_threatfox, mock_iocs_from_hits):
        """Test that sensors are passed to add_ioc when present"""
        self.mock_ioc_repo.is_enabled.return_value = True

        mock_ioc = self._create_mock_ioc()
        mock_sensor1 = Mock()
        mock_sensor1.address = "10.0.0.1"
        mock_sensor2 = Mock()
        mock_sensor2.address = "10.0.0.2"
        # Attach sensors to IOC
        mock_ioc._sensors_to_add = [mock_sensor1, mock_sensor2]
        mock_iocs_from_hits.return_value = [mock_ioc]

        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]

        self.strategy.extract_from_hits(hits)

        # Should call add_ioc once with IOC object (sensors are attached to it)
        self.strategy.ioc_processor.add_ioc.assert_called_once_with(mock_ioc, attack_type=SCANNER, honeypot_name="TestHoneypot")
