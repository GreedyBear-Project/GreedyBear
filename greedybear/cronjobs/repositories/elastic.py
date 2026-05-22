import logging
from collections.abc import Iterator
from datetime import datetime, timedelta

from django.conf import settings
from elasticsearch.dsl import Q, Search

from greedybear.consts import FIELDS_TO_EXTRACT
from greedybear.settings import EXTRACTION_INTERVAL


class ElasticRepository:
    """
    Repository for querying honeypot log data from a T-Pot Elasticsearch instance.

    Provides a chunked search interface for retrieving log entries within
    a specified time window from logstash indices.
    """

    class ElasticServerDownError(Exception):
        """Raised when the Elasticsearch server is unreachable."""

    def __init__(self):
        """Initialize the repository with an Elasticsearch client."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_client = settings.ELASTIC_CLIENT

    def has_honeypot_been_hit(self, minutes_back_to_lookup: int, honeypot_name: str) -> bool:
        """
        Check if a specific honeypot has been hit within a given time window.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current
                time when searching for honeypot hits.
            honeypot_name: The name/type of the honeypot to check for hits.

        Returns:
            True if at least one hit was recorded for the specified honeypot within
            the time window, False otherwise.
        """
        search = Search(using=self.elastic_client, index="logstash-*")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        q = Q("range", **{"@timestamp": {"gte": window_start, "lt": window_end}})
        search = search.query(q)
        search = search.filter("term", **{"type.keyword": honeypot_name})
        return search.count() > 0

    def search(self, minutes_back_to_lookup: int) -> Iterator[list]:
        """
        Search for log entries within a specified time window, yielding results
        in chunks of at most EXTRACTION_INTERVAL minutes.

        Args:
            minutes_back_to_lookup: Number of minutes to look back from the current time.

        Yields:
            list: Log entries sorted by @timestamp for each chunk, containing only FIELDS_TO_EXTRACT.

        Raises:
            ElasticServerDownError: If Elasticsearch is unreachable.
        """
        self._healthcheck()
        self.log.debug(f"minutes_back_to_lookup: {minutes_back_to_lookup}")
        window_start, window_end = get_time_window(datetime.now(), minutes_back_to_lookup)
        chunk_start = window_start
        while chunk_start < window_end:
            self.log.debug("querying elastic")
            chunk_end = min(chunk_start + timedelta(minutes=EXTRACTION_INTERVAL), window_end)
            self.log.debug(f"time window: {chunk_start} - {chunk_end}")
            search = Search(using=self.elastic_client, index="logstash-*")
            q = Q("range", **{"@timestamp": {"gte": chunk_start, "lt": chunk_end}})
            search = search.query(q)
            search = search.source(FIELDS_TO_EXTRACT)
            result = list(search.scan())
            self.log.debug(f"found {len(result)} hits")
            result.sort(key=lambda hit: hit["@timestamp"])
            yield result
            chunk_start = chunk_end

    def _healthcheck(self):
        """
        Verify Elasticsearch connectivity.

        Raises:
            ElasticServerDownError: If the server does not respond to ping.
        """
        self.log.debug("performing healthcheck")
        if not self.elastic_client.ping():
            raise self.ElasticServerDownError("elastic server is not reachable, could be down")
        self.log.debug("elastic server is reachable")


def get_time_window(
    reference_time: datetime,
    lookback_minutes: int,
    extraction_interval: int = EXTRACTION_INTERVAL,
) -> tuple[datetime, datetime]:
    """
    Calculates a time window that ends at the last completed extraction interval and looks back a specified number of minutes.

    Args:
        reference_time (datetime): Reference point in time
        lookback_minutes (int): Minutes to look back
        extraction_interval (int): Minutes between two subsequent extraction runs

    Returns:
        tuple: A tuple containing the start and end time of the time window as datetime objects

    Raises:
        ValueError: If lookback_minutes is less than extraction_interval
        ValueError: If extraction_interval is not a positive divisor of 60
    """
    if extraction_interval <= 0 or 60 % extraction_interval > 0:
        raise ValueError("Argument extraction_interval must be a positive divisor of 60.")

    if lookback_minutes < extraction_interval:
        raise ValueError(f"Argument lookback_minutes size must be at least {extraction_interval} minutes.")

    rounded_minute = (reference_time.minute // extraction_interval) * extraction_interval
    window_end = reference_time.replace(minute=rounded_minute, second=0, microsecond=0)
    window_start = window_end - timedelta(minutes=lookback_minutes)
    return (window_start, window_end)
