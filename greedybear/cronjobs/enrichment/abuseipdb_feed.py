from django.conf import settings

from greedybear.cronjobs.enrichment.http_enrichment import HttpEnrichmentJob
from greedybear.cronjobs.http_client import HttpClient
from greedybear.utils import is_valid_ipv4


class AbuseIPDBCron(HttpEnrichmentJob):
    """
    Fetch AbuseIPDB blocklist and directly enrich matching IOCs with tags.

    Downloads the AbuseIPDB blocklist (top 10k malicious IPs), joins them
    directly against the IOC table, and writes Tag entries for any matches.
    Tags are only replaced on successful API responses; on errors, existing
    tags are preserved to avoid losing enrichment data.
    """

    SOURCE_NAME = "abuseipdb"
    WRITE_METHOD = "replace"
    MAX_ENTRIES = 10000  # Hard limit as per free API tier

    def _should_skip(self) -> bool:
        return not settings.ABUSEIPDB_API_KEY

    def _fetch_feed(self):
        api_key = settings.ABUSEIPDB_API_KEY
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {
            "confidenceMinimum": 75,  # Only IPs with confidence >= 75%
            "limit": self.MAX_ENTRIES,  # Maximum 10k entries
        }

        with HttpClient() as client:
            response = client.get(url, headers=headers, params=params, timeout=30)

        json_data = response.json()
        return json_data.get("data", [])

    def _parse_tags(self, blocklist_data: list) -> dict[str, int]:
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

    def _build_tag_entries(self, matching_iocs, feed_by_ip) -> list[dict]:
        tag_entries = []
        for ioc_id, ioc_name in matching_iocs:
            score = feed_by_ip[ioc_name]
            if score is not None:
                tag_entries.append(
                    {
                        "ioc_id": ioc_id,
                        "key": "confidence_of_abuse",
                        "value": f"{score}%",
                    }
                )
        return tag_entries
