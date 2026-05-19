import logging
from collections import defaultdict

from django.core.cache import caches

from greedybear.cronjobs.extraction.bucket_updater import BucketUpdater
from greedybear.cronjobs.extraction.strategies.factory import ExtractionStrategyFactory
from greedybear.cronjobs.repositories import (
    ElasticRepository,
    IocRepository,
    SensorRepository,
)
from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
from greedybear.settings import (
    EXTRACTION_INTERVAL,
    INITIAL_EXTRACTION_TIMESPAN,
)


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

    @property
    def _minutes_back_to_lookup(self) -> int:
        """
        Calculate the time window size for Elasticsearch queries.
        Returns a larger window on first run to backfill historical data,
        otherwise uses the configured extraction interval.

        Returns:
            Number of minutes to look back in the search query.
        """
        if self.ioc_repo.is_empty():
            return INITIAL_EXTRACTION_TIMESPAN
        return EXTRACTION_INTERVAL

    def execute(self) -> int:
        """
        Execute the extraction pipeline.

        Performs the following steps:
        1. Search Elasticsearch for honeypot log entries in chunks
        2. For each chunk, group hits by honeypot type and extract sensors
        3. Apply honeypot-specific extraction strategies
        4. Update IOC scores
        5. Update activity buckets

        Returns:
            Number of IOC records processed.
        """
        ioc_record_count = 0
        bucket_updater = BucketUpdater()
        factory = ExtractionStrategyFactory(self.ioc_repo, self.sensor_repo)

        # 1. Search in chunks
        self.log.info("Getting honeypot hits from Elasticsearch")
        for chunk in self.elastic_repo.search(self._minutes_back_to_lookup):
            ioc_records = []
            hits_by_honeypot = defaultdict(list)

            # 2. Group by honeypot
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

            # 3. Extract using strategies
            for honeypot, hits in sorted(hits_by_honeypot.items()):
                if not self.ioc_repo.is_ready_for_extraction(honeypot):
                    self.log.info(f"Skipping honeypot {honeypot}")
                    continue

                self.log.info(f"Collect hits for activity buckets from honeypot {honeypot}")
                bucket_updater.collect_hits(hits)

                self.log.info(f"Extracting hits from honeypot {honeypot}")
                strategy = factory.get_strategy(honeypot)
                try:
                    strategy.extract_from_hits(hits)
                    ioc_records += strategy.ioc_records
                except Exception:
                    self.log.exception(f"Extraction failed for honeypot {honeypot}")

            # 4. Update scores
            self.log.info("Updating scores")
            if ioc_records:
                UpdateScores().score_only(ioc_records)
            ioc_record_count += len(ioc_records)

            # 5. Update activity buckets
            self.log.info("Updating activity buckets")
            bucket_updater.update()

        # 6. Invalidate API caches only if any IOC records were processed
        if ioc_record_count > 0:
            # Use the shared DB-backed cache so the version bump is visible to
            # gunicorn API workers (LocMemCache is per-process).
            self.log.info("Invalidating feeds ASN cache")
            shared_cache = caches["django-q"]
            try:
                shared_cache.incr("asn_feeds_version")
            except ValueError:
                shared_cache.set("asn_feeds_version", 2, timeout=None)

        if bucket_updater.total_update_count > 0:
            self.log.info("Invalidating feeds trending cache")
            shared_cache = caches["django-q"]
            try:
                shared_cache.incr("trending_feeds_version")
            except ValueError:
                shared_cache.set("trending_feeds_version", 2, timeout=None)

        return ioc_record_count
