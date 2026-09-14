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
        """
        Whether this job should skip its run (e.g. missing API key).

        Returns:
            True if the job should skip, False otherwise.
        """

    @abstractmethod
    def _fetch_feed(self):
        """
        Fetch raw data from the external source.

        Returns:
            The raw response data (implementation-specific format),
            or None if the fetch failed and existing tags should be
            preserved.
        """

    @abstractmethod
    def _parse_feed(self, raw_data) -> dict:
        """
        Parse the raw feed data into a dict keyed by IP address.

        Args:
            raw_data: The raw data returned by _fetch_feed.

        Returns:
            Dict mapping IP address -> enrichment data for that IP.
        """

    @abstractmethod
    def _build_tag_entries(self, matching_iocs, feed_by_ip) -> list[dict]:
        """
        Build the final list of tag entries from matched IOCs and feed data.

        Args:
            matching_iocs: List of (ioc_id, ip_address) tuples returned
                by _match_iocs.
            feed_by_ip: Dict mapping IP address -> enrichment data,
                as returned by _parse_feed.

        Returns:
            List of dicts with keys: ioc_id, key, value.
        """

    def _match_iocs(self, ip_dict):
        return IOC.objects.filter(name__in=ip_dict.keys()).values_list("id", "name")

    def run(self) -> None:
        if self._should_skip():
            self.log.warning(f"{self.SOURCE_NAME} skipped.")
            return

        try:
            self.log.info(f"Starting {self.SOURCE_NAME} feed download for enrichment")
            raw_data = self._fetch_feed()

            if raw_data is None:
                # Fetch failed - preserve existing tags, don't touch the database
                return

            feed_by_ip = self._parse_feed(raw_data)
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
