import logging
from datetime import datetime

from django.conf import settings
from elasticsearch import ConnectionError as ElasticConnectionError
from elasticsearch import ConnectionTimeout as ElasticConnectionTimeout
from elasticsearch.dsl import Q, Search

from greedybear.consts import FIELDS_TO_EXTRACT
from greedybear.cronjobs.exceptions import ElasticServerDownError
from greedybear.utils import get_time_window


class ElasticRepository:
    """
    Repository for querying honeypot log data from a T-Pot Elasticsearch instance.

    Provides a search interface for retrieving log entries within
    a specified time window from logstash indices.
    """

    def __init__(self):
        """Initialize the repository with an Elasticsearch client."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT
        if self.elastic_client is None:
            self.log.warning("Elasticsearch is not configured")

    @property
    def is_available(self) -> bool:
        """Return True when an Elasticsearch client is configured."""
        return self.elastic_client is not None

    def has_honeypot_been_hit(self, minutes_back_to_lookup: int, honeypot_name: str) -> bool:
        """
        Check if a specific honeypot has been hit within a given time window.

        Returns False immediately when Elasticsearch is not configured.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current
                time when searching for honeypot hits.
            honeypot_name: The name/type of the honeypot to check for hits.

        Returns:
            True if at least one hit was recorded for the specified honeypot within
            the time window, False otherwise.
        """
        if not self.is_available:
            return False
        search = Search(using=self.elastic_client, index="logstash-*")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
        search = search.query(q)
        search = search.filter("term", **{"type.keyword": honeypot_name})
        return search.count() > 0

    def search(self, window_start: datetime, window_end: datetime) -> list:
        """
        Search for log entries within a time window.

        Callers keep the window short (one extraction interval) so the result fits in memory.
        Returns an empty list when Elasticsearch is not configured.

        Args:
            window_start: Start of the time window (inclusive).
            window_end: End of the time window (exclusive).

        Returns:
            list: Log entries sorted by @timestamp, containing only FIELDS_TO_EXTRACT.

        Raises:
            ElasticServerDownError: If Elasticsearch is unreachable.
        """
        if not self.is_available:
            return []
        self._healthcheck()
        self.log.debug(f"querying elastic, time window: {window_start} - {window_end}")
        search = Search(using=self.elastic_client, index="logstash-*")
        q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
        search = search.query(q)
        search = search.source([*FIELDS_TO_EXTRACT])
        try:
            result = list(search.scan())
        except (ElasticConnectionError, ElasticConnectionTimeout) as exc:
            raise ElasticServerDownError("lost connection to elastic server during search") from exc
        self.log.debug(f"found {len(result)} hits")
        result.sort(key=lambda hit: hit["@timestamp"])
        return result

    def _healthcheck(self):
        """
        Verify Elasticsearch connectivity.

        Raises:
            ElasticServerDownError: If the server does not respond to ping.
        """
        self.log.debug("performing healthcheck")
        if not self.elastic_client.ping():
            raise ElasticServerDownError("elastic server is not reachable, could be down")
        self.log.debug("elastic server is reachable")
