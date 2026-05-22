# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
"""
Tests for hit filtering, grouping, and sensor extraction in ExtractionPipeline.
"""

from unittest.mock import MagicMock, patch

from tests import ExtractionTestCase, MockElasticHit


class ExtractionPipelineTestCase(ExtractionTestCase):
    """Base test case for extraction pipeline tests."""

    def _create_pipeline_with_mocks(self):
        """Helper to create a pipeline with mocked dependencies."""
        with (
            patch("greedybear.cronjobs.extraction.pipeline.SensorRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.IocRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository"),
        ):
            from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

            return ExtractionPipeline()


class TestHitFiltering(ExtractionPipelineTestCase):
    """Tests for hit filtering logic in execute()."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_hits_without_src_ip(self, mock_factory, mock_scores):
        """Hits without src_ip should be skipped."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            [
                MockElasticHit({"type": "Cowrie"}),  # missing src_ip
                MockElasticHit({"src_ip": "", "type": "Cowrie"}),  # empty src_ip
                MockElasticHit({"src_ip": "   ", "type": "Cowrie"}),  # whitespace-only src_ip
            ]
        ]
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_skips_hits_without_type(self, mock_factory, mock_scores):
        """Hits without type (honeypot) should be skipped."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            [
                MockElasticHit({"src_ip": "1.2.3.4"}),  # missing type
                MockElasticHit({"src_ip": "1.2.3.4", "type": ""}),  # empty type
                MockElasticHit({"src_ip": "1.2.3.4", "type": "   "}),  # whitespace-only type
            ]
        ]
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_handles_empty_search_result(self, mock_factory, mock_scores):
        """Should handle empty Elasticsearch response gracefully."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = []
        pipeline.ioc_repo.is_empty.return_value = False

        result = pipeline.execute()

        self.assertEqual(result, 0)
        mock_factory.return_value.get_strategy.assert_not_called()
        mock_scores.return_value.score_only.assert_not_called()


class TestSensorExtraction(ExtractionPipelineTestCase):
    """Tests for sensor extraction from hits."""

    @patch("greedybear.cronjobs.extraction.pipeline.EXTRACTION_INTERVAL", 10)
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_extracts_sensor_from_hits(self, mock_factory, mock_scores):
        """
        Should extract and register sensors from t-pot_ip_ext field.
        Also verifies correct time window is passed to search().
        """
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            [MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie", "t-pot_ip_ext": "10.0.0.1"})],
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = False  # Skip strategy for this test

        pipeline.execute()

        pipeline.sensor_repo.get_or_create_sensor.assert_called_once_with("10.0.0.1")
        pipeline.elastic_repo.search.assert_called_once_with(10)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_sensor_not_extracted_for_invalid_hits(self, mock_factory, mock_scores):
        """
        Sensors should NOT be extracted for hits that fail validation.
        Even if t-pot_ip_ext is present, missing required fields should skip sensor extraction.
        """
        pipeline = self._create_pipeline_with_mocks()

        # Hit with sensor but missing type
        hits = [
            MockElasticHit(
                {
                    "src_ip": "192.168.1.1",
                    "t-pot_ip_ext": "10.0.0.99",
                    # Missing 'type' field
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False

        pipeline.execute()

        # Sensor should NOT be extracted for invalid hits (missing type)
        pipeline.sensor_repo.get_or_create_sensor.assert_not_called()


class TestHitGrouping(ExtractionPipelineTestCase):
    """Tests for hit grouping by honeypot type."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_groups_hits_by_honeypot_type(self, mock_factory, mock_scores):
        """Hits should be grouped by honeypot type before extraction."""
        pipeline = self._create_pipeline_with_mocks()
        pipeline.elastic_repo.search.return_value = [
            [
                MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"}),
                MockElasticHit({"src_ip": "5.6.7.8", "type": "Cowrie"}),
                MockElasticHit({"src_ip": "9.10.11.12", "type": "Log4pot"}),
            ]
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        # Should be called for both honeypot types
        self.assertEqual(mock_factory.return_value.get_strategy.call_count, 2)

        # Verify strategy is called with correct honeypot types
        calls = mock_factory.return_value.get_strategy.call_args_list
        honeypot_names = {call[0][0] for call in calls}
        self.assertEqual(honeypot_names, {"Cowrie", "Log4pot"})

        # Verify extract_from_hits is called twice
        self.assertEqual(mock_strategy.extract_from_hits.call_count, 2)

        # Verify each strategy received correct number of hits
        extraction_calls = mock_strategy.extract_from_hits.call_args_list
        hits_counts = sorted([len(call[0][0]) for call in extraction_calls])
        self.assertEqual(hits_counts, [1, 2])  # 1 Log4pot hit, 2 Cowrie hits

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_duplicate_honeypot_hits_grouped(self, mock_factory, mock_scores):
        """Multiple hits from same honeypot type are grouped together."""
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "3.3.3.3", "type": "Cowrie"}),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("1.1.1.1")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        # Strategy should be called only ONCE with all 3 hits grouped
        mock_factory.return_value.get_strategy.assert_called_once_with("Cowrie")
        self.assertEqual(mock_strategy.extract_from_hits.call_count, 1)

        # Verify all 3 hits were passed together
        call_args = mock_strategy.extract_from_hits.call_args[0][0]
        self.assertEqual(len(call_args), 3)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_honeypot_skipped_when_not_ready(self, mock_factory, mock_scores):
        """Honeypots not ready for extraction should be skipped."""
        pipeline = self._create_pipeline_with_mocks()

        hits = [
            MockElasticHit(
                {
                    "src_ip": "1.2.3.4",
                    "type": "DisabledHoneypot",
                    "t-pot_ip_ext": "10.0.0.1",
                }
            ),
            MockElasticHit(
                {
                    "src_ip": "5.6.7.8",
                    "type": "EnabledHoneypot",
                    "t-pot_ip_ext": "10.0.0.2",
                }
            ),
        ]
        pipeline.elastic_repo.search.return_value = [hits]
        pipeline.ioc_repo.is_empty.return_value = False

        # First honeypot disabled, second enabled
        pipeline.ioc_repo.is_ready_for_extraction.side_effect = [False, True]

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("5.6.7.8")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        # Should only process the enabled honeypot
        self.assertEqual(result, 1)
        # Factory should only be called once (for EnabledHoneypot)
        mock_factory.return_value.get_strategy.assert_called_once_with("EnabledHoneypot")


class TestMultiChunkProcessing(ExtractionPipelineTestCase):
    """Tests for multi-chunk processing behavior."""

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_ioc_count_accumulated_across_chunks(self, mock_factory, mock_scores):
        """IOC records from all chunks should be counted in the total."""
        pipeline = self._create_pipeline_with_mocks()

        chunk1 = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "2.2.2.2", "type": "Cowrie"}),
        ]
        chunk2 = [
            MockElasticHit({"src_ip": "3.3.3.3", "type": "Cowrie"}),
        ]
        chunk3 = [
            MockElasticHit({"src_ip": "4.4.4.4", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "5.5.5.5", "type": "Cowrie"}),
            MockElasticHit({"src_ip": "6.6.6.6", "type": "Cowrie"}),
        ]
        pipeline.elastic_repo.search.return_value = [chunk1, chunk2, chunk3]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []

        def set_ioc_records(hits):
            mock_strategy.ioc_records = [self._create_mock_ioc(h["src_ip"]) for h in hits]

        mock_strategy.extract_from_hits.side_effect = set_ioc_records
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        result = pipeline.execute()

        self.assertEqual(result, 6)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_scoring_called_per_chunk(self, mock_factory, mock_scores):
        """UpdateScores should be called once per chunk that produces IOCs."""
        pipeline = self._create_pipeline_with_mocks()

        chunk_with_hits = [
            MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"}),
        ]
        empty_chunk = []
        pipeline.elastic_repo.search.return_value = [
            chunk_with_hits,
            empty_chunk,
            chunk_with_hits,
        ]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc("1.1.1.1")]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        self.assertEqual(mock_scores.return_value.score_only.call_count, 2)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_factory_created_once_across_chunks(self, mock_factory, mock_scores):
        """ExtractionStrategyFactory should be instantiated once, not per chunk."""
        pipeline = self._create_pipeline_with_mocks()

        chunk = [MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"})]
        pipeline.elastic_repo.search.return_value = [chunk, chunk, chunk]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = []
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        mock_factory.assert_called_once()

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    def test_each_chunk_groups_hits_independently(self, mock_factory, mock_scores):
        """Each chunk should group its own hits by honeypot type independently."""
        pipeline = self._create_pipeline_with_mocks()

        chunk1 = [MockElasticHit({"src_ip": "1.1.1.1", "type": "Cowrie"})]
        chunk2 = [MockElasticHit({"src_ip": "2.2.2.2", "type": "Log4pot"})]
        pipeline.elastic_repo.search.return_value = [chunk1, chunk2]
        pipeline.ioc_repo.is_empty.return_value = False
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        mock_strategy = MagicMock()
        mock_strategy.ioc_records = [self._create_mock_ioc()]
        mock_factory.return_value.get_strategy.return_value = mock_strategy

        pipeline.execute()

        calls = mock_factory.return_value.get_strategy.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0][0], "Cowrie")
        self.assertEqual(calls[1][0][0], "Log4pot")
