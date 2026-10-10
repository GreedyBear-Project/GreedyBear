import itertools
from datetime import datetime
from unittest.mock import Mock, patch

from elasticsearch import ConnectionError as ElasticConnectionError
from elasticsearch import ConnectionTimeout as ElasticConnectionTimeout

from greedybear.consts import FIELDS_TO_EXTRACT
from greedybear.cronjobs.exceptions import ElasticServerDownError, RecoverableError
from greedybear.cronjobs.repositories import ElasticRepository

from . import CustomTestCase


class TestElasticRepository(CustomTestCase):
    def setUp(self):
        self.mock_client = Mock()
        self.mock_client.ping.return_value = True

        patcher = patch("greedybear.cronjobs.repositories.elastic.settings")
        self.mock_settings = patcher.start()
        self.mock_settings.ELASTIC_CLIENT = self.mock_client
        self.addCleanup(patcher.stop)

        self.repo = ElasticRepository()

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_true_when_hits_exist(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.filter.return_value = mock_search
        mock_search.count.return_value = 1
        mock_get_time_window.return_value = (datetime(2025, 1, 1), datetime(2025, 1, 1, 0, 10))

        result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")
        self.assertTrue(result)
        mock_search.query.assert_called_once()
        mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
        mock_search.count.assert_called_once()

    @patch("greedybear.cronjobs.repositories.elastic.get_time_window")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_has_honeypot_been_hit_returns_false_when_no_hits(self, mock_search_class, mock_get_time_window):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.filter.return_value = mock_search
        mock_search.count.return_value = 0
        mock_get_time_window.return_value = (datetime(2025, 1, 1), datetime(2025, 1, 1, 0, 10))

        result = self.repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")

        self.assertFalse(result)
        mock_search.query.assert_called_once()
        mock_search.filter.assert_called_once_with("term", **{"type.keyword": "test_honeypot"})
        mock_search.count.assert_called_once()

    def test_healthcheck_passes_when_ping_succeeds(self):
        self.mock_client.ping.return_value = True
        self.repo._healthcheck()
        self.mock_client.ping.assert_called_once()

    def test_healthcheck_raises_when_ping_fails(self):
        self.mock_client.ping.return_value = False
        with self.assertRaises(ElasticServerDownError) as ctx:
            self.repo._healthcheck()
        self.assertIn("not reachable", str(ctx.exception))

    def test_elastic_server_down_error_is_recoverable(self):
        self.assertTrue(issubclass(ElasticServerDownError, RecoverableError))

    def _mock_search(self, mock_search_class, hits):
        mock_search = Mock()
        mock_search_class.return_value = mock_search
        mock_search.query.return_value = mock_search
        mock_search.source.return_value = mock_search
        mock_search.scan.return_value = iter(hits)
        return mock_search

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_returns_all_hits(self, mock_search_class):
        self._mock_search(mock_search_class, [{"name": f"hit{i}", "@timestamp": i} for i in range(20_000)])

        hits = self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

        self.assertEqual(len(hits), 20_000)

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_returns_ordered_hits(self, mock_search_class):
        self._mock_search(mock_search_class, [{"name": f"hit{i}", "@timestamp": i % 7} for i in range(20_000)])

        hits = self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

        self.assertTrue(all(a["@timestamp"] <= b["@timestamp"] for a, b in itertools.pairwise(hits)))

    @patch("greedybear.cronjobs.repositories.elastic.Q")
    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_queries_the_given_window(self, mock_search_class, mock_q):
        self._mock_search(mock_search_class, [])
        window_start = datetime(2025, 1, 1, 12, 0)
        window_end = datetime(2025, 1, 1, 12, 10)

        self.repo.search(window_start, window_end)

        mock_q.assert_called_once_with("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_scans_reassigned_source_filtered_search(self, mock_search_class):
        base_search = Mock()
        filtered_search = Mock()
        mock_search_class.return_value = base_search
        base_search.query.return_value = base_search
        base_search.source.return_value = filtered_search
        filtered_search.scan.return_value = iter([{"@timestamp": 1}])

        hits = self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

        self.assertEqual(hits, [{"@timestamp": 1}])
        base_search.source.assert_called_once_with(FIELDS_TO_EXTRACT)
        filtered_search.scan.assert_called_once()
        base_search.scan.assert_not_called()

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_raises_when_ping_fails(self, mock_search_class):
        mock_search = self._mock_search(mock_search_class, [])
        self.mock_client.ping.return_value = False

        with self.assertRaises(ElasticServerDownError):
            self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))
        mock_search.scan.assert_not_called()

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_raises_recoverable_error_on_lost_connection(self, mock_search_class):
        """A connection lost during the scan is worth retrying, like a failed ping."""
        for error in (ElasticConnectionError("connection refused"), ElasticConnectionTimeout("timed out")):
            with self.subTest(error=type(error).__name__):
                mock_search = self._mock_search(mock_search_class, [])
                mock_search.scan.side_effect = error

                with self.assertRaises(ElasticServerDownError):
                    self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

    @patch("greedybear.cronjobs.repositories.elastic.Search")
    def test_search_does_not_mask_other_errors(self, mock_search_class):
        """Errors other than a lost connection are not marked as recoverable."""
        mock_search = self._mock_search(mock_search_class, [])
        mock_search.scan.side_effect = ValueError("malformed response")

        with self.assertRaises(ValueError):
            self.repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))

    def test_fields_to_extract_include_type_for_trending_bucketing(self):
        self.assertIn("type", FIELDS_TO_EXTRACT)

    def test_search_returns_nothing_when_elasticsearch_unavailable(self):
        """search() must return no hits when Elasticsearch is not configured."""
        patcher = patch("greedybear.cronjobs.repositories.elastic.settings")
        mock_settings = patcher.start()
        mock_settings.ELASTIC_CLIENT = None
        self.addCleanup(patcher.stop)

        repo = ElasticRepository()
        hits = repo.search(datetime(2025, 1, 1, 12, 0), datetime(2025, 1, 1, 12, 10))
        self.assertEqual(hits, [])

    def test_has_honeypot_been_hit_returns_false_when_elasticsearch_unavailable(self):
        """has_honeypot_been_hit() must return False when Elasticsearch is not configured."""
        patcher = patch("greedybear.cronjobs.repositories.elastic.settings")
        mock_settings = patcher.start()
        mock_settings.ELASTIC_CLIENT = None
        self.addCleanup(patcher.stop)

        repo = ElasticRepository()
        result = repo.has_honeypot_been_hit(minutes_back_to_lookup=10, honeypot_name="test_honeypot")
        self.assertFalse(result)
