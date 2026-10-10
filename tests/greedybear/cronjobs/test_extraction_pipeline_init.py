# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Tests for ExtractionPipeline initialization and time window calculation.
"""

from datetime import datetime
from unittest.mock import patch

from greedybear.models import ExtractionJobName, ExtractionRun
from tests import ExtractionTestCase


class TestExtractionPipelineInit(ExtractionTestCase):
    """Tests for ExtractionPipeline initialization."""

    @patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
    @patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
    def test_initializes_repositories(self, mock_elastic, mock_ioc, mock_sensor):
        """Pipeline should initialize all required repositories."""
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()

        mock_elastic.assert_called_once()
        mock_ioc.assert_called_once()
        mock_sensor.assert_called_once()
        self.assertIsNotNone(pipeline.log)


@patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 10)
@patch("greedybear.cronjobs.extraction.pipeline.INITIAL_EXTRACTION_TIMESPAN", 60 * 24 * 3)
@patch("greedybear.cronjobs.extraction.pipeline.SensorRepository")
@patch("greedybear.cronjobs.extraction.pipeline.IocRepository")
@patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository")
class TestExtractionWindow(ExtractionTestCase):
    """Tests for the _extraction_window method."""

    NOW = datetime(2025, 1, 10, 14, 23)

    def _create_pipeline(self, ioc_db_empty=False):
        from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

        pipeline = ExtractionPipeline()
        pipeline.ioc_repo.is_empty.return_value = ioc_db_empty
        return pipeline

    def _set_watermark(self, watermark, job_name=ExtractionJobName.EXTRACTION):
        ExtractionRun.objects.create(job_name=job_name, window_start=watermark, window_end=watermark)

    def test_first_run_backfills_initial_timespan(self, *mocks):
        """Without a watermark and without IOCs, the first run backfills INITIAL_EXTRACTION_TIMESPAN."""
        pipeline = self._create_pipeline(ioc_db_empty=True)

        start, end = pipeline._extraction_window(datetime(2025, 1, 10, 0, 3))

        self.assertEqual(start, datetime(2025, 1, 7, 0, 0))
        self.assertEqual(end, datetime(2025, 1, 10, 0, 0))

    def test_existing_instance_without_watermark_looks_back_one_interval(self, *mocks):
        """An instance that extracted before runs were recorded must not extract the same data twice."""
        pipeline = self._create_pipeline(ioc_db_empty=False)

        start, end = pipeline._extraction_window(self.NOW)

        self.assertEqual(start, datetime(2025, 1, 10, 14, 10))
        self.assertEqual(end, datetime(2025, 1, 10, 14, 20))

    def test_continues_from_watermark(self, *mocks):
        """After downtime, the window covers everything since the watermark."""
        self._set_watermark(datetime(2025, 1, 10, 9, 40))
        pipeline = self._create_pipeline()

        start, end = pipeline._extraction_window(self.NOW)

        self.assertEqual(start, datetime(2025, 1, 10, 9, 40))
        self.assertEqual(end, datetime(2025, 1, 10, 14, 20))

    def test_uses_latest_watermark(self, *mocks):
        self._set_watermark(datetime(2025, 1, 10, 9, 40))
        self._set_watermark(datetime(2025, 1, 10, 13, 50))
        self._set_watermark(datetime(2025, 1, 10, 11, 0))
        pipeline = self._create_pipeline()

        start, _ = pipeline._extraction_window(self.NOW)

        self.assertEqual(start, datetime(2025, 1, 10, 13, 50))

    def test_ignores_watermark_of_other_jobs(self, *mocks):
        self._set_watermark(datetime(2025, 1, 10, 13, 50), job_name=ExtractionJobName.PAYLOAD_EXTRACTION)
        pipeline = self._create_pipeline(ioc_db_empty=False)

        start, _ = pipeline._extraction_window(self.NOW)

        self.assertEqual(start, datetime(2025, 1, 10, 14, 10))

    def test_catch_up_is_capped(self, *mocks):
        """Data older than INITIAL_EXTRACTION_TIMESPAN is not fetched, however long the downtime was."""
        self._set_watermark(datetime(2024, 12, 1, 0, 0))
        pipeline = self._create_pipeline()

        start, end = pipeline._extraction_window(datetime(2025, 1, 10, 0, 3))

        self.assertEqual(start, datetime(2025, 1, 7, 0, 0))
        self.assertEqual(end, datetime(2025, 1, 10, 0, 0))

    def test_window_crossing_midnight_ends_at_midnight(self, *mocks):
        """A late or catching-up run on day d never extracts data from day d before the training."""
        self._set_watermark(datetime(2025, 1, 9, 22, 0))
        pipeline = self._create_pipeline()

        start, end = pipeline._extraction_window(datetime(2025, 1, 10, 10, 7))

        self.assertEqual(start, datetime(2025, 1, 9, 22, 0))
        self.assertEqual(end, datetime(2025, 1, 10, 0, 0))

    def test_window_after_midnight_is_not_cut(self, *mocks):
        self._set_watermark(datetime(2025, 1, 10, 0, 0))
        pipeline = self._create_pipeline()

        start, end = pipeline._extraction_window(datetime(2025, 1, 10, 10, 7))

        self.assertEqual(start, datetime(2025, 1, 10, 0, 0))
        self.assertEqual(end, datetime(2025, 1, 10, 10, 0))

    def test_up_to_date_watermark_gives_empty_window(self, *mocks):
        self._set_watermark(datetime(2025, 1, 10, 14, 20))
        pipeline = self._create_pipeline()

        start, end = pipeline._extraction_window(self.NOW)

        self.assertGreaterEqual(start, end)
