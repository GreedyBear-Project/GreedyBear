import logging
from abc import ABCMeta, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager

from django.db import transaction

from greedybear.cronjobs.extraction.hit import Hit, InvalidHitError
from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.cronjobs.extraction.utils import threatfox_submission
from greedybear.cronjobs.repositories import IocRepository, SensorRepository


class BaseExtractionStrategy(metaclass=ABCMeta):
    """
    Abstract base class for T-Pot extraction strategies.

    Subclasses implement `extract_from_hits` to define honeypot-specific
    logic for processing log entries into IOC records.

    Attributes:
        honeypot: Name of the honeypot this strategy handles.
        ioc_repo: Repository for IOC data access.
        sensor_repo: Repository for sensor data access.
        log: Logger instance for this class.
        ioc_processor: Processor for creating and updating IOC records.
        ioc_records: List of IOC records extracted during processing.
        skipped: Number of records dropped because processing them failed.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        self.honeypot = honeypot
        self.ioc_repo = ioc_repo
        self.sensor_repo = sensor_repo

        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.ioc_processor = IocProcessor(self.ioc_repo, self.sensor_repo)
        self.ioc_records = []
        self.skipped = 0
        self._threatfox_queue: list[tuple] = []

    def queue_threatfox(self, ioc_record, related_urls) -> None:
        """
        Hold a ThreatFox submission back until its transaction has closed.

        Submitting inside a guarded block would keep a database transaction
        open across an HTTP call, and a submission that already went out
        cannot be taken back when the block rolls back.

        Args:
            ioc_record: The saved IOC to submit.
            related_urls: URLs to submit with it.
        """
        self._threatfox_queue.append((ioc_record, related_urls))

    def flush_threatfox(self) -> None:
        """Send the queued submissions, once their records have been committed."""
        queued, self._threatfox_queue = self._threatfox_queue, []
        for ioc_record, related_urls in queued:
            threatfox_submission(ioc_record, related_urls, self.log)

    @contextmanager
    def skip_on_error(self, what: str) -> Iterator[None]:
        """
        Isolate one record so that failing to process it costs only that record.

        Hits are attacker influenced, so a single malformed one can raise
        anywhere in a strategy. Without this the exception leaves the strategy
        and is caught per honeypot, which drops every remaining record in the
        chunk as well.

        An InvalidHitError is expected and logged quietly. Anything else is a bug
        worth seeing, so it is logged with its traceback, but it is still
        contained so the rest of the chunk goes through.

        The body runs in its own atomic block for two reasons. Postgres aborts
        the whole transaction on a failed statement, so without a savepoint to
        roll back to, catching a database error would leave the connection
        unusable and every later record would fail anyway. It also means a
        record that fails half way leaves no partial rows behind.

        Args:
            what: Short description of the record, used in the log line.
        """
        try:
            with transaction.atomic():
                yield
        except InvalidHitError as exc:
            self.skipped += 1
            self.log.debug(f"skipping {what}: {exc}")
        except Exception:
            self.skipped += 1
            self.log.exception(f"failed to process {what} from honeypot {self.honeypot}")

    @abstractmethod
    def extract_from_hits(self, hits: list[Hit]) -> None:
        """
        Extract IOC records from honeypot log hits.
        Subclasses must implement this method to define honeypot-specific
        extraction logic. Extracted records should be stored in `ioc_records`.

        Args:
            hits: List of Elasticsearch hit dictionaries to process.
        """

    def _add_fks(self, scanner_ip: str, hostname: str) -> None:
        """
        Link related IOCs bidirectionally (scanner IP <-> hostname).

        Args:
            scanner_ip: Scanner IP address.
            hostname: Hostname to link with scanner.
        """
        scanner_ip_instance = self.ioc_repo.get_ioc_by_name(scanner_ip)
        hostname_instance = self.ioc_repo.get_ioc_by_name(hostname)

        if not scanner_ip_instance or not hostname_instance:
            self.log.warning(
                f"Cannot link IOCs - missing from database: scanner_ip={scanner_ip_instance is not None}, hostname={hostname_instance is not None}"
            )
            return

        scanner_ip_instance.related_ioc.add(hostname_instance)
        hostname_instance.related_ioc.add(scanner_ip_instance)
