from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.hit import Hit
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import iocs_from_hits


class GenericExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for generic honeypots.

    Processes log hits as scanner-type IOCs and submits qualifying
    records to ThreatFox. Used for honeypots without specialized
    extraction logic.
    """

    def extract_from_hits(self, hits: list[Hit]) -> None:
        """
        Extract IOCs from honeypot log hits.
        Converts hits to IOC records, persists them via the IOC processor,
        and submits qualifying records to ThreatFox.

        Args:
            hits: List of Elasticsearch hits to process.
        """
        for ioc in iocs_from_hits(hits):
            with self.skip_on_error(f"IoC {ioc.name}"):
                self.log.info(f"IoC {ioc.name} found by honeypot {self.honeypot}")
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name=self.honeypot)
                if ioc_record:
                    self.queue_threatfox(ioc_record, ioc.related_urls)
                    # appended last: anything above can raise and roll the
                    # savepoint back, and the record must not outlive that
                    self.ioc_records.append(ioc_record)
        self.flush_threatfox()
        self.log.info(f"added {len(self.ioc_records)} IoCs from {self.honeypot}, skipped {self.skipped}")
