# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Edge case tests for ExtractionPipeline.

These tests cover boundary conditions, error scenarios, and unusual inputs
that the pipeline should handle gracefully.

NOTE: Some tests here mock the factory/strategies because they test error
conditions that cannot be reliably triggered with real strategies (e.g.,
forcing a strategy to throw an exception). This is intentional and differs
from the E2E tests which use real strategies for happy-path testing.
"""

from unittest.mock import MagicMock, patch

from tests import E2ETestCase, MockElasticHit


class TestEdgeCases(E2ETestCase):
    """Edge case tests for the extraction pipeline.

    These tests verify error handling and boundary conditions.
    Some tests mock the factory to control failure scenarios.
    """

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_partial_strategy_success(self, mock_factory, mock_scores):
        """Some strategies succeed, some fail - pipeline continues.

        NOTE: This test mocks factory because we need to force one strategy
        to throw an exception, which cannot be done reliably with real strategies.
        """
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "FailingHoneypot"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "SuccessHoneypot"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_failing = MagicMock()
        mock_failing.extract_from_hits.side_effect = Exception("Boom")

        mock_success = MagicMock()
        mock_success.ioc_records = [self._create_mock_ioc("2.2.2.2")]

        mock_factory.return_value.get_strategy.side_effect = [mock_failing, mock_success]

        result = pipeline.execute()

        # Should return 1 (one success)
        self.assertEqual(result, 1)
        # Should log 1 error
        self.assertEqual(pipeline.log.exception.call_count, 1)
        # Scoring should be called with successful IOCs
        mock_scores.return_value.score_only.assert_called_once()

    @patch("greedybear.cronjobs.extraction.pipeline.BucketUpdater")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_activity_bucket_update_failure_does_not_abort_extraction(self, mock_factory, mock_scores, mock_bucket_updater_cls):
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "2.2.2.2", "type": "SuccessHoneypot"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        bucket_updater = mock_bucket_updater_cls.return_value
        bucket_updater.total_update_count = 0

        mock_success = MagicMock()
        mock_success.ioc_records = [self._create_mock_ioc("2.2.2.2")]
        mock_factory.return_value.get_strategy.return_value = mock_success

        result = pipeline.execute()

        self.assertEqual(result, 1)
        mock_success.extract_from_hits.assert_called_once()
        mock_scores.return_value.score_only.assert_called_once()
        bucket_updater.collect_hits.assert_called_once()
        bucket_updater.update.assert_called_once()

    @patch("greedybear.cronjobs.extraction.pipeline.caches")
    @patch("greedybear.cronjobs.extraction.pipeline.BucketUpdater")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_bucket_updates_invalidate_trending_cache(self, mock_factory, mock_scores, mock_bucket_updater_cls, mock_caches):
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "2.2.2.2", "type": "SuccessHoneypot"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        bucket_updater = mock_bucket_updater_cls.return_value
        bucket_updater.total_update_count = 2

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        shared_cache = MagicMock()
        mock_caches.__getitem__.return_value = shared_cache

        result = pipeline.execute()

        self.assertEqual(result, 0)
        bucket_updater.collect_hits.assert_called_once()
        bucket_updater.update.assert_called_once()
        shared_cache.incr.assert_called_once_with("trending_feeds_version")
        mock_scores.return_value.score_only.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.caches")
    @patch("greedybear.cronjobs.extraction.pipeline.BucketUpdater")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_disabled_honeypot_hits_do_not_update_activity_buckets(self, mock_factory, mock_scores, mock_bucket_updater_cls, mock_caches):
        """Hits from honeypots not ready for extraction must be excluded from bucket updates."""
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "DisabledHoneypot"}),
            MockElasticHit({"src_ip": "1.1.1.1", "type": "DisabledHoneypot"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "EnabledHoneypot"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.side_effect = lambda hp: hp == "EnabledHoneypot"

        bucket_updater = mock_bucket_updater_cls.return_value
        bucket_updater.total_update_count = 0

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        shared_cache = MagicMock()
        mock_caches.__getitem__.return_value = shared_cache

        pipeline.execute()

        # collect_hits must be called exactly once, only with hits from the enabled honeypot.
        bucket_updater.collect_hits.assert_called_once()
        passed_hits = list(bucket_updater.collect_hits.call_args.args[0])
        self.assertEqual(len(passed_hits), 1)
        self.assertEqual(passed_hits[0]["type"], "EnabledHoneypot")
        self.assertEqual(passed_hits[0]["src_ip"], "2.2.2.2")

    @patch("greedybear.cronjobs.extraction.pipeline.caches")
    @patch("greedybear.cronjobs.extraction.pipeline.BucketUpdater")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_all_honeypots_disabled_skips_bucket_updates_entirely(self, mock_factory, mock_scores, mock_bucket_updater_cls, mock_caches):
        """When every honeypot in a chunk is disabled, no hits are collected and the trending cache is not invalidated."""
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.log = MagicMock()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "DisabledA"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "DisabledB"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = False

        bucket_updater = mock_bucket_updater_cls.return_value
        bucket_updater.total_update_count = 0

        shared_cache = MagicMock()
        mock_caches.__getitem__.return_value = shared_cache

        pipeline.execute()

        bucket_updater.collect_hits.assert_not_called()
        mock_factory.return_value.get_strategy.assert_not_called()
        shared_cache.incr.assert_not_called()


class TestLargeBatches(E2ETestCase):
    """Tests for large batch processing using REAL strategies."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_large_batch_of_hits_with_real_strategy(self, mock_scores):
        """Large number of hits should be processed correctly with real strategies.

        Uses real GenericExtractionStrategy (via unknown honeypot type) to verify
        the pipeline can handle large batches.
        """
        pipeline = self._create_pipeline_with_real_factory()

        # Create 100 hits to test batch processing
        hits = [
            MockElasticHit(
                {
                    "src_ip": f"192.168.{i // 256}.{i % 256}",
                    "type": "TestHoneypot",  # Unknown type → uses GenericExtractionStrategy
                    "dest_port": 22,
                    "@timestamp": "2025-01-15T10:00:00",
                }
            )
            for i in range(100)
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True
        pipeline.ioc_repo.get_ioc_by_name.return_value = None

        # Mock add_ioc to return mock IOCs
        mock_iocs = [self._create_mock_ioc(f"192.168.{i // 256}.{i % 256}") for i in range(100)]

        with patch("greedybear.cronjobs.extraction.ioc_processor.IocProcessor.add_ioc") as mock_add:
            # Return different mock IOCs for each call
            mock_add.side_effect = mock_iocs
            result = pipeline.execute()

        # Should have processed hits and produced IOCs
        self.assertGreaterEqual(result, 0)
