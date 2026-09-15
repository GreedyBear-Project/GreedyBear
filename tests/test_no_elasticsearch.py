# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Regression tests for running GreedyBear without an Elasticsearch instance.

Covers issue #1599: the application must start and the scheduled jobs must
complete gracefully when ELASTIC_ENDPOINT is not configured.
"""

import importlib
import io
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import greedybear.settings as greedybear_settings
from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline
from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots
from tests import CustomTestCase


class SettingsWithoutElasticsearchTestCase(CustomTestCase):
    """Settings must load without Elasticsearch, even in production mode."""

    def test_settings_load_without_elastic_endpoint(self):
        """Missing ELASTIC_ENDPOINT must only warn, never exit the application."""
        # restore the original module state after the test
        self.addCleanup(importlib.reload, greedybear_settings)

        with patch.dict("os.environ", {"ELASTIC_ENDPOINT": "", "DEBUG": "False"}):
            captured = io.StringIO()
            with redirect_stdout(captured):
                # raises SystemExit if the settings module still calls exit()
                reloaded = importlib.reload(greedybear_settings)

        self.assertIsNone(reloaded.ELASTIC_CLIENT)
        self.assertIn("WARNING", captured.getvalue())

    def test_settings_load_with_elastic_endpoint_keeps_client(self):
        """A configured ELASTIC_ENDPOINT must still create the Elasticsearch client."""
        self.addCleanup(importlib.reload, greedybear_settings)

        with patch.dict("os.environ", {"ELASTIC_ENDPOINT": "http://localhost:9200", "ENVIRONMENT": "local"}):
            reloaded = importlib.reload(greedybear_settings)

        self.assertIsNotNone(reloaded.ELASTIC_CLIENT)


class ExtractionPipelineWithoutElasticsearchTestCase(CustomTestCase):
    """ExtractionPipeline must skip gracefully when Elasticsearch is unavailable."""

    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_execute_returns_zero_when_elasticsearch_unconfigured(self, mock_elastic, mock_ioc, mock_sensor):
        """execute() must return 0 without touching Elasticsearch when unconfigured."""
        mock_elastic.return_value.elastic_client = None
        pipeline = ExtractionPipeline()
        pipeline.log = MagicMock()

        result = pipeline.execute()

        self.assertEqual(result, 0)
        pipeline.elastic_repo.search.assert_not_called()
        warning_calls = [call[0][0] for call in pipeline.log.warning.call_args_list]
        self.assertEqual(len([msg for msg in warning_calls if "Elasticsearch is not configured" in msg]), 1)


class MonitorHoneypotsWithoutElasticsearchTestCase(CustomTestCase):
    """MonitorHoneypots must skip gracefully when Elasticsearch is unavailable."""

    @patch("greedybear.cronjobs.monitor_honeypots.ElasticRepository")
    def test_run_skips_when_elasticsearch_unconfigured(self, mock_elastic_repo_class):
        """run() must log a warning and complete without querying Elasticsearch."""
        mock_elastic_repo = mock_elastic_repo_class.return_value
        mock_elastic_repo.elastic_client = None
        cronjob = MonitorHoneypots(minutes_back=60)
        cronjob.log = MagicMock()

        cronjob.execute()

        self.assertTrue(cronjob.success)
        mock_elastic_repo.has_honeypot_been_hit.assert_not_called()
        warning_calls = [call[0][0] for call in cronjob.log.warning.call_args_list]
        self.assertEqual(len([msg for msg in warning_calls if "Elasticsearch is not configured" in msg]), 1)
