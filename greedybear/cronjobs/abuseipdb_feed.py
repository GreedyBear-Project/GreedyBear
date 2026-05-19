import requests
from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC
from greedybear.utils import is_valid_ipv4

SOURCE_NAME = "abuseipdb"


class AbuseIPDBCron(Cronjob):
    """
    Fetch AbuseIPDB blocklist and directly enrich matching IOCs with tags.

    Downloads the AbuseIPDB blocklist (top 10k malicious IPs), joins them
    directly against the IOC table, and writes Tag entries for any matches.
    Tags are only replaced on successful API responses; on errors, existing
    tags are preserved to avoid losing enrichment data.
    """

    MAX_ENTRIES = 10000  # Hard limit as per free API tier

    def __init__(self, tag_repo=None):
        """
        Initialize the AbuseIPDB cronjob.

        Args:
            tag_repo: Optional TagRepository instance for testing.
        """
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()

    def run(self) -> None:
        """
        Fetch AbuseIPDB blocklist, match against our IOC table, and create tags.

        1. Download the blocklist from AbuseIPDB /blacklist endpoint
        2. Validate IP addresses
        3. Query our IOC table for matching IPs (WHERE name IN ...)
        4. Replace all AbuseIPDB tags with fresh data

        On API errors, existing tags are intentionally preserved so
        enrichment data is not lost due to transient failures.
        """
        api_key = settings.ABUSEIPDB_API_KEY

        if not api_key:
            self.log.warning("AbuseIPDB API key not configured. Skipping enrichment.")
            return

        try:
            self.log.info("Starting AbuseIPDB blocklist download for enrichment")

            # Fetch blocklist from AbuseIPDB
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {
                "confidenceMinimum": 75,  # Only IPs with confidence >= 75%
                "limit": self.MAX_ENTRIES,  # Maximum 10k entries
            }

            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()

            json_data = response.json()
            blocklist_data = json_data.get("data", [])

            self.log.info(f"Retrieved {len(blocklist_data)} IPs from AbuseIPDB blocklist")

            # Parse feed into a dict keyed by IP
            score_by_ip = self._parse_feed(blocklist_data)
            self.log.info(f"Parsed {len(score_by_ip)} valid IPs from AbuseIPDB feed")

            if not score_by_ip:
                # No valid IPs found — clear stale tags and return
                self.tag_repo.replace_tags_for_source(SOURCE_NAME, [])
                return

            # Join against IOC table: find IOCs whose name matches feed IPs
            matching_iocs = IOC.objects.filter(name__in=score_by_ip.keys()).values_list("id", "name")

            # Build tag entries for matching IOCs
            tag_entries = []
            matched_count = 0
            for ioc_id, ioc_name in matching_iocs:
                matched_count += 1
                score = score_by_ip[ioc_name]

                if score is not None:
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "confidence_of_abuse",
                            "value": f"{score}%",
                        }
                    )

            # Replace all AbuseIPDB tags atomically
            created_count = self.tag_repo.replace_tags_for_source(SOURCE_NAME, tag_entries)
            self.log.info(f"AbuseIPDB enrichment completed. Matched {matched_count} IOCs, created {created_count} tags.")

        except requests.RequestException:
            self.log.exception("Failed to fetch AbuseIPDB blocklist")
            raise

    def _parse_feed(self, blocklist_data: list) -> dict[str, int]:
        """
        Parse AbuseIPDB blocklist data into a dict keyed by validated IP address.

        Args:
            blocklist_data: Raw blocklist data from AbuseIPDB API.

        Returns:
            Dict mapping IP address -> abuse confidence score.
        """
        score_by_ip: dict[str, int] = {}

        for entry in blocklist_data:
            ip_addr = entry.get("ipAddress")
            if not ip_addr:
                continue

            is_valid, validated_ip = is_valid_ipv4(ip_addr)
            if not is_valid:
                continue

            score_by_ip[validated_ip] = entry.get("abuseConfidenceScore")

        return score_by_ip
