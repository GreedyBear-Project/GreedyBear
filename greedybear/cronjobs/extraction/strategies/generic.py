from greedybear.consts import SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import iocs_from_hits, threatfox_submission


class GenericExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for generic honeypots.

    Processes log hits as scanner-type IOCs and submits qualifying
    records to ThreatFox. Used for honeypots without specialized
    extraction logic.
    """

    def extract_from_hits(self, hits: list[dict]) -> None:
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
                    self.ioc_records.append(ioc_record)
                    threatfox_submission(ioc_record, ioc.related_urls, self.log)
        self.log.info(f"added {len(self.ioc_records)} IoCs from {self.honeypot}, skipped {self.skipped}")
