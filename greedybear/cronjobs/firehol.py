from ipaddress import ip_address

import requests

from greedybear.cronjobs.enrichment.base_enrichment import BaseEnrichmentJob
from greedybear.cronjobs.http_client import HttpClient
from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.models import IOC, IocType
from greedybear.utils import is_valid_cidr, is_valid_ipv4


class FireHolCron(BaseEnrichmentJob):
    """
    Fetch and store IP blocklists from FireHol repository.

    Downloads IP blocklists from multiple sources and stores them in the database.
    Automatically cleans up entries older than 30 days.
    """

    SOURCE_NAME = "firehol"
    WRITE_METHOD = "replace"

    def __init__(self, firehol_repo=None, tag_repo=None):
        """
        Initialize the FireHol cronjob with repository dependency.

        Args:
            firehol_repo: Optional FireHolRepository instance for testing.
            tag_repo: Optional TagRepository instance for testing.
        """
        super().__init__(tag_repo=tag_repo)
        self.firehol_repo = firehol_repo if firehol_repo is not None else FireHolRepository()

    def run(self) -> None:
        """
        Fetch blocklists from FireHol sources and store them in the database.

        Processes multiple sources (blocklist_de, greensnow, bruteforceblocker, dshield),
        parses IP addresses and CIDR blocks, and stores new entries.
        Finally cleans up old entries.
        """
        base_path = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
        sources = {
            "blocklist_de": f"{base_path}/blocklist_de.ipset",
            "greensnow": f"{base_path}/greensnow.ipset",
            "bruteforceblocker": f"{base_path}/bruteforceblocker.ipset",
            "dshield": f"{base_path}/dshield.netset",
        }

        for source, url in sources.items():
            self.log.info(f"Processing {source} from {url}")
            try:
                try:
                    with HttpClient() as client:
                        response = client.get(url, timeout=60)
                except requests.RequestException:
                    self.log.exception(f"Network error fetching {source}")
                    continue

                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Validate the extracted candidate
                    if not (is_valid_ipv4(line)[0] or is_valid_cidr(line)[0]):
                        # Not a valid IPv4 or CIDR, log at DEBUG level
                        self.log.debug(f"Invalid IPv4 address or CIDR in line: {line}")
                        continue

                    # FireHol .ipset and .netset files contain IPs or CIDRs, one per line
                    # Comments (lines starting with #) are filtered out above

                    _, created = self.firehol_repo.get_or_create(line, source)
                    if created:
                        self.log.debug(f"Added new entry: {line} from {source}")

            except Exception:
                self.log.exception(f"Unexpected error processing {source}")

        # Clean up old FireHolList entries
        self._cleanup_old_entries()

        self._write_blocklist_tags()

    def _write_blocklist_tags(self) -> None:
        """
        Tag every IOC that appears on a stored blocklist.

        Runs after the lists are refreshed, so the tags reflect what was
        just downloaded. Both exact IP entries and CIDR ranges are matched.
        """
        entries_by_ip = self.firehol_repo.get_entries_by_ip()
        cidr_entries = self.firehol_repo.get_cidr_entries()

        # An empty table means every download failed. Rewriting now would
        # delete all existing tags and put nothing back, so keep them.
        if not entries_by_ip and not cidr_entries:
            self.log.warning("No FireHol entries stored, keeping existing tags")
            return

        self.log.info(f"Matching {len(entries_by_ip)} IPs and {len(cidr_entries)} ranges against known IOCs")

        matching_iocs = self._match_iocs(entries_by_ip)
        tag_entries = self._build_tag_entries(matching_iocs, entries_by_ip)
        tag_entries += self._match_cidr_entries(cidr_entries)

        created_count = self._write_tags(tag_entries)
        self.log.info(f"{self.SOURCE_NAME} enrichment completed, created {created_count} tags.")

    def _build_tag_entries(self, matching_iocs, entries_by_ip) -> list[dict]:
        """
        Turn matched IOCs into tag entries.

        Each blocklist an IOC appears on becomes one tag.

        Args:
            matching_iocs: List of (ioc_id, ip_address) tuples from _match_iocs.
            entries_by_ip: Dict mapping IP address to its list of sources.

        Returns:
            List of dicts with keys: ioc_id, key, value.
        """
        tag_entries = []
        for ioc_id, ioc_name in matching_iocs:
            tag_entries.extend({"ioc_id": ioc_id, "key": "blocklist", "value": source} for source in entries_by_ip[ioc_name])
        return tag_entries

    def _match_cidr_entries(self, cidr_entries: list[tuple]) -> list[dict]:
        """
        Match IP-type IOCs against the stored CIDR ranges.

        Ranges need a membership test, so this cannot be done with the
        name lookup used for exact entries. Domains are skipped, since
        they cannot sit inside a network.

        Args:
            cidr_entries: List of (ip_network, source) tuples.

        Returns:
            List of dicts with keys: ioc_id, key, value.
        """
        if not cidr_entries:
            return []

        tag_entries = []
        for ioc_id, ioc_name in IOC.objects.filter(type=IocType.IP).values_list("id", "name").iterator():
            try:
                parsed_ip = ip_address(ioc_name)
            except ValueError:
                continue
            tag_entries.extend({"ioc_id": ioc_id, "key": "blocklist", "value": source} for network, source in cidr_entries if parsed_ip in network)
        return tag_entries

    def _cleanup_old_entries(self):
        """
        Delete FireHolList entries older than 30 days to keep database clean.
        """
        deleted_count = self.firehol_repo.cleanup_old_entries(days=30)
        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old FireHolList entries")
