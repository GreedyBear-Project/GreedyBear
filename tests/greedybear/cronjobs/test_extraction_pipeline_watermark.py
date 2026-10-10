# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Tests for how ExtractionPipeline tracks its progress across runs.

These tests use the real run, IOC and sensor repositories, so watermarks and
rollbacks are checked against the database. Only Elasticsearch, the
strategies and the scoring are mocked.
"""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

from greedybear.cronjobs.exceptions import ElasticServerDownError
from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline
from greedybear.models import ExtractionJobName, ExtractionRun, ExtractionRunStatus, Sensor
from tests import ExtractionTestCase, MockElasticHit


def frozen_datetime(now: datetime) -> type[datetime]:
    """Return a datetime class whose now() always returns the given time."""

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    return FrozenDatetime


def cowrie_chunk(sensor_ip: str = "10.0.0.1") -> list[MockElasticHit]:
    return [MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie", "t-pot_ip_ext": sensor_ip})]


@patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 10)
@patch("greedybear.cronjobs.extraction.pipeline.INITIAL_EXTRACTION_TIMESPAN", 60 * 24 * 3)
@patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
@patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
class TestExtractionWatermark(ExtractionTestCase):
    def _create_pipeline(self) -> ExtractionPipeline:
        with patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository"):
            pipeline = ExtractionPipeline()
        pipeline.log = MagicMock()
        return pipeline

    def _mock_strategies(self, mock_factory):
        """Every strategy call produces one IOC record."""

        def get_strategy(honeypot):
            strategy = Mock()
            strategy.ioc_records = [Mock()]
            return strategy

        mock_factory.return_value.get_strategy.side_effect = get_strategy

    def _set_watermark(self, watermark: datetime) -> None:
        ExtractionRun.objects.create(
            job_name=ExtractionJobName.EXTRACTION,
            window_start=watermark,
            window_end=watermark,
            status=ExtractionRunStatus.SUCCESS,
        )

    def _execute(self, pipeline: ExtractionPipeline, now: datetime) -> int:
        with patch("greedybear.cronjobs.extraction.pipeline.datetime", frozen_datetime(now)):
            return pipeline.execute()

    def _latest_run(self) -> ExtractionRun:
        return ExtractionRun.objects.filter(job_name=ExtractionJobName.EXTRACTION).latest("created_at")

    def _watermark(self) -> datetime:
        return max(ExtractionRun.objects.filter(job_name=ExtractionJobName.EXTRACTION).values_list("window_end", flat=True))

    def test_successful_run_advances_watermark_to_window_end(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        self._set_watermark(datetime(2025, 1, 10, 11, 0))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk(), cowrie_chunk()]

        result = self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        self.assertEqual(result, 3)
        run = self._latest_run()
        self.assertEqual(run.window_start, datetime(2025, 1, 10, 11, 0))
        self.assertEqual(run.window_end, datetime(2025, 1, 10, 11, 30))
        self.assertEqual(run.status, ExtractionRunStatus.SUCCESS)
        self.assertEqual(run.ioc_count, 3)
        self.assertIsNotNone(run.finished_at)

    def test_retryable_failure_keeps_processed_chunks_and_retries_the_rest(self, mock_factory, mock_scores):
        """If chunk 2 of 3 fails, the next run continues with chunk 2 and never repeats chunk 1."""
        self._mock_strategies(mock_factory)
        self._set_watermark(datetime(2025, 1, 10, 11, 0))
        now = datetime(2025, 1, 10, 11, 33)

        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), ElasticServerDownError("elastic is down")]
        with self.assertRaises(ElasticServerDownError):
            self._execute(pipeline, now)

        failed_run = self._latest_run()
        self.assertEqual(failed_run.status, ExtractionRunStatus.FAILED_RETRYABLE)
        self.assertEqual(failed_run.window_end, datetime(2025, 1, 10, 11, 10))
        self.assertEqual(failed_run.ioc_count, 1)
        self.assertEqual(failed_run.last_error, "elastic is down")

        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk()]
        result = self._execute(pipeline, now)

        self.assertEqual(result, 2)
        searched_windows = [c.args for c in pipeline.elastic_repo.search.call_args_list]
        self.assertEqual(
            searched_windows,
            [
                (datetime(2025, 1, 10, 11, 10), datetime(2025, 1, 10, 11, 20)),
                (datetime(2025, 1, 10, 11, 20), datetime(2025, 1, 10, 11, 30)),
            ],
        )
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 11, 30))
        self.assertEqual(self._latest_run().status, ExtractionRunStatus.SUCCESS)

    def test_permanent_failure_skips_the_chunk_and_continues(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        mock_scores.return_value.score_only.side_effect = [None, ValueError("corrupted data"), None]
        self._set_watermark(datetime(2025, 1, 10, 11, 0))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk(), cowrie_chunk()]

        result = self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        self.assertEqual(result, 2)
        run = self._latest_run()
        self.assertEqual(run.status, ExtractionRunStatus.FAILED_PERMANENT)
        self.assertEqual(run.window_end, datetime(2025, 1, 10, 11, 30))
        self.assertEqual(run.ioc_count, 2)
        self.assertEqual(run.last_error, "corrupted data")
        self.assertIsNotNone(run.finished_at)

    def test_failed_chunk_is_rolled_back_and_caches_are_refreshed(self, mock_factory, mock_scores):
        """Writes of a failed chunk are undone, and no cache keeps objects that only existed in it."""
        self._mock_strategies(mock_factory)
        mock_scores.return_value.score_only.side_effect = [None, ValueError("corrupted data"), None]
        self._set_watermark(datetime(2025, 1, 10, 11, 0))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk("10.9.9.9"), []]

        self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        self.assertFalse(Sensor.objects.filter(address="10.9.9.9").exists())
        self.assertNotIn("10.9.9.9", pipeline.sensor_repo.cache)
        self.assertIn("10.0.0.1", pipeline.sensor_repo.cache)

    def test_sensor_from_failed_chunk_can_be_created_again(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        mock_scores.return_value.score_only.side_effect = [ValueError("corrupted data"), None]
        self._set_watermark(datetime(2025, 1, 10, 11, 10))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk("10.9.9.9"), cowrie_chunk("10.9.9.9")]

        self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        sensor = Sensor.objects.get(address="10.9.9.9")
        self.assertEqual(pipeline.sensor_repo.cache["10.9.9.9"].pk, sensor.pk)

    def test_failing_strategy_is_rolled_back_without_failing_the_chunk(self, mock_factory, mock_scores):
        """A strategy that fails halfway leaves no writes behind, but the chunk is still committed."""

        def failing_strategy(honeypot):
            strategy = Mock()
            strategy.ioc_records = []

            def extract_from_hits(hits):
                Sensor.objects.create(address="10.8.8.8")
                raise ValueError("strategy failed")

            strategy.extract_from_hits.side_effect = extract_from_hits
            return strategy

        mock_factory.return_value.get_strategy.side_effect = failing_strategy
        self._set_watermark(datetime(2025, 1, 10, 11, 20))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk()]

        self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        self.assertFalse(Sensor.objects.filter(address="10.8.8.8").exists())
        self.assertTrue(Sensor.objects.filter(address="10.0.0.1").exists())
        run = self._latest_run()
        self.assertEqual(run.status, ExtractionRunStatus.SUCCESS)
        self.assertEqual(run.window_end, datetime(2025, 1, 10, 11, 30))

    def test_empty_window_does_nothing(self, mock_factory, mock_scores):
        self._set_watermark(datetime(2025, 1, 10, 11, 30))
        pipeline = self._create_pipeline()

        result = self._execute(pipeline, datetime(2025, 1, 10, 11, 33))

        self.assertEqual(result, 0)
        pipeline.elastic_repo.search.assert_not_called()
        self.assertEqual(ExtractionRun.objects.count(), 1)
        self.assertFalse(pipeline.day_completed)

    def test_regular_midnight_run_completes_the_day(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        self._set_watermark(datetime(2025, 1, 9, 23, 50))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk()]

        self._execute(pipeline, datetime(2025, 1, 10, 0, 3))

        self.assertTrue(pipeline.day_completed)
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 0, 0))

        pipeline.elastic_repo.search.side_effect = [cowrie_chunk()]
        self._execute(pipeline, datetime(2025, 1, 10, 0, 13))

        self.assertFalse(pipeline.day_completed)

    def test_late_run_after_downtime_stops_at_midnight_and_completes_the_day(self, mock_factory, mock_scores):
        """A run on day d that catches up from day d-1 extracts nothing from day d before training."""
        self._mock_strategies(mock_factory)
        self._set_watermark(datetime(2025, 1, 9, 23, 40))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk()]

        self._execute(pipeline, datetime(2025, 1, 10, 10, 7))

        self.assertTrue(pipeline.day_completed)
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 0, 0))
        searched_windows = [c.args for c in pipeline.elastic_repo.search.call_args_list]
        self.assertTrue(all(end <= datetime(2025, 1, 10, 0, 0) for _, end in searched_windows))

        # the next run picks up day d from midnight
        pipeline.elastic_repo.search.side_effect = None
        pipeline.elastic_repo.search.return_value = []
        self._execute(pipeline, datetime(2025, 1, 10, 10, 17))

        self.assertFalse(pipeline.day_completed)
        self.assertEqual(self._latest_run().window_start, datetime(2025, 1, 10, 0, 0))
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 10, 10))

    def test_day_is_not_completed_while_a_retryable_failure_blocks_midnight(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        self._set_watermark(datetime(2025, 1, 9, 23, 40))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), ElasticServerDownError("elastic is down")]

        with self.assertRaises(ElasticServerDownError):
            self._execute(pipeline, datetime(2025, 1, 10, 0, 3))
        self.assertFalse(pipeline.day_completed)

        pipeline.elastic_repo.search.side_effect = [cowrie_chunk()]
        self._execute(pipeline, datetime(2025, 1, 10, 0, 13))

        self.assertTrue(pipeline.day_completed)
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 0, 0))

    def test_day_is_completed_when_the_last_chunk_before_midnight_is_skipped(self, mock_factory, mock_scores):
        self._mock_strategies(mock_factory)
        mock_scores.return_value.score_only.side_effect = [None, ValueError("corrupted data")]
        self._set_watermark(datetime(2025, 1, 9, 23, 40))
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.search.side_effect = [cowrie_chunk(), cowrie_chunk()]

        self._execute(pipeline, datetime(2025, 1, 10, 0, 3))

        self.assertTrue(pipeline.day_completed)
        self.assertEqual(self._watermark(), datetime(2025, 1, 10, 0, 0))

    def test_without_elasticsearch_day_is_completed_by_first_run_after_midnight(self, mock_factory, mock_scores):
        pipeline = self._create_pipeline()
        pipeline.elastic_repo.is_available = False

        self._execute(pipeline, datetime(2025, 1, 10, 0, 3))
        self.assertTrue(pipeline.day_completed)

        self._execute(pipeline, datetime(2025, 1, 10, 0, 13))
        self.assertFalse(pipeline.day_completed)
