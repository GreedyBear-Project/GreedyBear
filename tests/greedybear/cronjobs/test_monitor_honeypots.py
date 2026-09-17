from unittest.mock import MagicMock, patch

from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots
from greedybear.cronjobs.repositories import ElasticRepository
from tests import CustomTestCase


class MonitorHoneypotsTestCase(CustomTestCase):
    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_all_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value

        mock_elastic_repo.has_honeypot_been_hit.return_value = True
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 4)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 4)
        self.assertEqual(len(warning_calls), 0)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_some_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value
        mock_elastic_repo.has_honeypot_been_hit.side_effect = [True, False, True, False]
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 4)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 2)
        self.assertEqual(len(warning_calls), 2)

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_no_active_honeypots_are_hit(self, mock_elastic_repo_class):
        # Setup mock responses
        mock_elastic_repo = mock_elastic_repo_class.return_value
        mock_elastic_repo.has_honeypot_been_hit.return_value = False
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        # Run the cronjob
        cronjob.execute()

        self.assertEqual(mock_elastic_repo.has_honeypot_been_hit.call_count, 4)

        info_calls = [call[0][0] for call in cronjob.log.info.call_args_list]
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]

        self.assertEqual(len([msg for msg in info_calls if "logs available" in msg]), 0)
        self.assertEqual(len(warning_calls), 4)

    @patch("greedybear.cronjobs.repositories.elastic.settings")
    def test_run_with_real_repository_when_elasticsearch_unavailable(self, mock_settings):
        """MonitorHoneypots must complete using a REAL ElasticRepository when ELASTIC_CLIENT is None."""
        mock_settings.ELASTIC_CLIENT = None

        elastic_repo = ElasticRepository()
        self.assertIsNone(elastic_repo.elastic_client)
        self.assertFalse(elastic_repo.is_available)

        cronjob = MonitorHoneypots(elastic_repo=elastic_repo, minutes_back=60)
        cronjob.execute()

        self.assertTrue(cronjob.success)
