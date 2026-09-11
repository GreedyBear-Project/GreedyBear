from abc import abstractmethod

import requests

from greedybear.cronjobs.enrichment.base_enrichment import BaseEnrichmentJob
from greedybear.models import IOC


class HttpEnrichmentJob(BaseEnrichmentJob):
    """
    Shared base for enrichment jobs that fetch data via HTTP API calls.
    """

    @abstractmethod
    def _should_skip(self) -> bool:
        pass

    @abstractmethod
    def _fetch_feed(self):
        pass

    @abstractmethod
    def _parse_tags(self, raw_data) -> dict:
        pass

    @abstractmethod
    def _build_tag_entries(self, matching_iocs, feed_by_ip) -> list[dict]:
        pass

    def _match_iocs(self, ip_dict):
        return IOC.objects.filter(name__in=ip_dict.keys()).values_list("id", "name")

    def run(self) -> None:
        if self._should_skip():
            self.log.warning(f"{self.SOURCE_NAME} skipped.")
            return

        try:
            self.log.info(f"Starting {self.SOURCE_NAME} feed download for enrichment")
            raw_data = self._fetch_feed()

            feed_by_ip = self._parse_tags(raw_data)
            self.log.info(f"Parsed {len(feed_by_ip)} unique IPs from {self.SOURCE_NAME} feed")

            if not feed_by_ip:
                self._write_tags([])
                return

            matching_iocs = self._match_iocs(feed_by_ip)
            tag_entries = self._build_tag_entries(matching_iocs, feed_by_ip)

            created_count = self._write_tags(tag_entries)
            self.log.info(f"{self.SOURCE_NAME} enrichment completed, created {created_count} tags.")

        except requests.RequestException:
            self.log.exception(f"Failed to fetch {self.SOURCE_NAME} feed")
            raise
