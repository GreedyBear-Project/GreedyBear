import logging
from collections import defaultdict
from datetime import datetime, time

from django.db import transaction

from greedybear.cache import Cache, invalidate_ioc_cache
from greedybear.consts import API_CACHE_ALIAS, TRENDING_FEEDS_DATA_VERSION_KEY
from greedybear.cronjobs.exceptions import RecoverableError
from greedybear.cronjobs.extraction.bucket_updater import BucketUpdater
from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
from greedybear.cronjobs.repositories import (
    ElasticRepository,
    ExtractionRunRepository,
    IocRepository,
    SensorRepository,
)
from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
from greedybear.models import ExtractionJobName, ExtractionRun
from greedybear.settings import (
    EXTRACTION_INTERVAL,
    INITIAL_EXTRACTION_TIMESPAN,
)
from greedybear.utils import get_catch_up_window, split_time_window


class ExtractionPipeline:
    """
    Pipeline for extracting IOCs from T-Pot's honeypot logs.
    Orchestrates the extraction workflow.
    """

    def __init__(self):
        """Initialize the pipeline with required repositories."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.elastic_repo = ElasticRepository()
        self.ioc_repo = IocRepository()
        self.sensor_repo = SensorRepository()
        self.run_repo = ExtractionRunRepository()
        # True once a run has extracted everything up to today's midnight,
        # which is when the daily training may use the data.
        self.day_completed = False

    def _extraction_window(self, now: datetime) -> tuple[datetime, datetime]:
        """
        Calculate the time window for this run.

        The window continues from where the last run stopped, but reaches back
        at most INITIAL_EXTRACTION_TIMESPAN minutes, so the first run on an
        empty database backfills that much. An instance that extracted before
        runs were recorded has IOCs but no watermark yet; it looks back a single
        interval as before, so it does not extract the same data twice.

        A window that starts before today's midnight is cut off at midnight, so
        the training that follows never sees data from today, no matter how late
        the run starts or how far it has to catch up.

        Args:
            now: Current point in time.

        Returns:
            The start and end of the time window. The window is empty if start >= end.
        """
        watermark = self.run_repo.get_watermark(ExtractionJobName.EXTRACTION)
        max_lookback = INITIAL_EXTRACTION_TIMESPAN
        if watermark is None and not self.ioc_repo.is_empty():
            max_lookback = EXTRACTION_INTERVAL
        window_start, window_end = get_catch_up_window(now, watermark, max_lookback, EXTRACTION_INTERVAL)
        midnight = datetime.combine(now.date(), time.min)
        if window_start < midnight:
            window_end = min(window_end, midnight)
        return window_start, window_end

    def execute(self) -> int:
        """
        Execute the extraction pipeline.

        Processes the time window from _extraction_window in chunks of at most
        EXTRACTION_INTERVAL minutes. Each chunk is committed in a single
        transaction together with the run's new window_end, so a run that
        stops halfway never processes a committed chunk twice.

        If a chunk fails with a RecoverableError, the run stops and the next
        run retries that chunk. Any other failure skips the chunk, records the
        error and moves on to the next one.

        Returns:
            Number of IOC records processed.

        Raises:
            RecoverableError: If a chunk could not be processed for a reason worth retrying.
        """
        self.day_completed = False
        now = datetime.now()

        if not self.elastic_repo.is_available:
            # Nothing to extract and no watermark to follow. Training still
            # has to happen daily, so it falls back to the first run after midnight.
            self.day_completed = now.hour == 0 and now.minute < EXTRACTION_INTERVAL
            return 0

        window_start, window_end = self._extraction_window(now)
        if window_start >= window_end:
            self.log.info(f"Nothing to extract, data up to {window_start} was already extracted")
            return 0

        self.log.info(f"Extracting honeypot hits from {window_start} to {window_end}")
        run = self.run_repo.start_run(ExtractionJobName.EXTRACTION, window_start)
        ioc_record_count = 0
        bucket_updater = BucketUpdater()
        factory = ExtractionStrategyFactory(self.ioc_repo, self.sensor_repo)

        try:
            for chunk_start, chunk_end in split_time_window(window_start, window_end, EXTRACTION_INTERVAL):
                self.log.info(f"Processing chunk {chunk_start} - {chunk_end}")
                try:
                    chunk = self.elastic_repo.search(chunk_start, chunk_end)
                    with transaction.atomic():
                        ioc_records = self._process_chunk(chunk, factory, bucket_updater)
                        self.run_repo.advance(run, chunk_end, len(ioc_records))
                except RecoverableError as exc:
                    self.log.warning(f"Chunk {chunk_start} - {chunk_end} failed, the next run will retry it")
                    self._reset_after_failure(run, bucket_updater)
                    self.run_repo.finish(run, error=str(exc), retryable=True)
                    raise
                except Exception as exc:
                    self.log.exception(f"Chunk {chunk_start} - {chunk_end} failed, skipping it")
                    self._reset_after_failure(run, bucket_updater)
                    self.run_repo.skip(run, chunk_end, str(exc))
                else:
                    ioc_record_count += len(ioc_records)
            self.run_repo.finish(run)
        finally:
            self._invalidate_caches(ioc_record_count, bucket_updater)

        midnight = datetime.combine(now.date(), time.min)
        self.day_completed = window_start < midnight and run.window_end == midnight
        return ioc_record_count

    def _process_chunk(self, chunk: list, factory: ExtractionStrategyFactory, bucket_updater: BucketUpdater) -> list:
        """
        Extract IOCs from one chunk of honeypot hits.

        Performs the following steps:
        1. Group hits by honeypot type and extract sensors
        2. Apply honeypot-specific extraction strategies
        3. Update IOC scores
        4. Update activity buckets

        Args:
            chunk: Honeypot hits from Elasticsearch.
            factory: Factory providing the extraction strategies.
            bucket_updater: Collects the hits for the activity buckets.

        Returns:
            The IOC records extracted from the chunk.
        """
        ioc_records = []
        hits_by_honeypot = defaultdict(list)

        # 1. Group by honeypot
        self.log.info("Grouping hits by honeypot type")
        for hit in chunk:
            # convert hit to dict for easier handling
            hit = hit.to_dict()
            # skip hits with non-existing or empty sources
            if "src_ip" not in hit or not hit["src_ip"].strip():
                continue
            # skip hits with non-existing or empty types (=honeypots)
            if "type" not in hit or not hit["type"].strip():
                continue

            if "t-pot_ip_ext" in hit:
                sensor = self.sensor_repo.get_or_create_sensor(hit["t-pot_ip_ext"])
                hit["_sensor"] = sensor  # include sensor for strategies

                sensor_country = hit.get("geoip_ext", {}).get("country_name")
                if sensor_country is not None:
                    self.sensor_repo.update_country(sensor, sensor_country)

            hits_by_honeypot[hit["type"]].append(hit)

        # 2. Extract using strategies
        for honeypot, hits in sorted(hits_by_honeypot.items()):
            if not self.ioc_repo.is_ready_for_extraction(honeypot):
                self.log.info(f"Skipping honeypot {honeypot}")
                continue

            self.log.info(f"Collect hits for activity buckets from honeypot {honeypot}")
            bucket_updater.collect_hits(hits)

            self.log.info(f"Extracting hits from honeypot {honeypot}")
            strategy = factory.get_strategy(honeypot)
            try:
                # A savepoint confines a failing strategy to its own honeypot,
                # so the rest of the chunk can still be committed.
                with transaction.atomic():
                    strategy.extract_from_hits(hits)
                ioc_records += strategy.ioc_records
            except Exception:
                self.log.exception(f"Extraction failed for honeypot {honeypot}")
                self._refresh_caches()

        # 3. Update scores
        self.log.info("Updating scores")
        if ioc_records:
            UpdateScores().score_only(ioc_records)

        # 4. Update activity buckets
        self.log.info("Updating activity buckets")
        bucket_updater.update()

        return ioc_records

    def _reset_after_failure(self, run: ExtractionRun, bucket_updater: BucketUpdater) -> None:
        """
        Bring the in-memory state back in line with the database after a chunk failed.

        Args:
            run: The current run, whose unsaved progress is dropped.
            bucket_updater: The bucket updater, whose collected hits are dropped.
        """
        run.refresh_from_db()
        bucket_updater.discard()
        self._refresh_caches()

    def _refresh_caches(self) -> None:
        """Reload the repository caches, which may hold objects from a rolled back transaction."""
        self.ioc_repo.refresh_cache()
        self.sensor_repo.refresh_cache()

    def _invalidate_caches(self, ioc_record_count: int, bucket_updater: BucketUpdater) -> None:
        """
        Invalidate the API caches affected by this run.

        Args:
            ioc_record_count: Number of IOC records committed by this run.
            bucket_updater: The bucket updater used by this run.
        """
        # Invalidate API caches only if any IOC records were processed.
        # Bumping the version orphans every cached feed response at once; the
        # bump lands in the shared DB-backed cache so gunicorn workers see it.
        if ioc_record_count > 0:
            self.log.info("Invalidating feeds cache")
            invalidate_ioc_cache()

        if bucket_updater.total_update_count > 0:
            self.log.info("Invalidating feeds trending cache")
            Cache(API_CACHE_ALIAS).bump_data_version(TRENDING_FEEDS_DATA_VERSION_KEY)
