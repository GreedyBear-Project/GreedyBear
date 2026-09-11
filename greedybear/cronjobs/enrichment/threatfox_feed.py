import re
from ipaddress import ip_address

from django.conf import settings

from greedybear.cronjobs.enrichment.http_enrichment import HttpEnrichmentJob
from greedybear.cronjobs.http_client import HttpClient
from greedybear.utils import is_valid_ipv4


class ThreatFoxCron(HttpEnrichmentJob):
    """
    Fetch ThreatFox IOC data and directly enrich matching IOCs with tags.

    Downloads IP-based IOCs from ThreatFox, joins them directly against
    the IOC table, and writes Tag entries for any matches. Tags are only
    replaced on successful API responses; on errors or non-OK status,
    existing tags are preserved to avoid losing enrichment data.
    """

    SOURCE_NAME = "threatfox"
    WRITE_METHOD = "replace"

    def _should_skip(self) -> bool:
        return not settings.THREATFOX_API_KEY

    def _fetch_feed(self):
        api_key = settings.THREATFOX_API_KEY
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {
            "Content-Type": "application/json",
            "Auth-Key": api_key,
        }
        data = {"query": "get_iocs", "days": 7}

        with HttpClient() as client:
            response = client.post(url, json=data, headers=headers, timeout=30)

        json_data = response.json()

        if json_data.get("query_status") != "ok":
            self.log.warning(f"ThreatFox API returned non-OK status: {json_data.get('query_status')}")
            return []

        return json_data.get("data", [])

    def _parse_tags(self, iocs_data: list) -> dict[str, list[dict]]:
        """
        Parse ThreatFox IOC data into a dict keyed by validated IP address.

        Args:
            iocs_data: Raw IOC data from ThreatFox API.

        Returns:
            Dict mapping IP address -> list of enrichment dicts.
        """
        feed_by_ip: dict[str, list[dict]] = {}

        for ioc_data in iocs_data:
            ioc_value = ioc_data.get("ioc", "")
            ioc_type = ioc_data.get("ioc_type", "")

            # Extract IP address based on IOC type
            ip_addr = self._extract_ip(ioc_value, ioc_type)
            if not ip_addr:
                continue

            # Validate the IP
            is_valid, validated_ip = is_valid_ipv4(ip_addr)
            if not is_valid:
                continue

            # Check if IP is global (not private, loopback, etc.)
            try:
                parsed_ip = ip_address(validated_ip)
                if parsed_ip.is_loopback or parsed_ip.is_private or parsed_ip.is_multicast or parsed_ip.is_link_local or parsed_ip.is_reserved:
                    self.log.debug(f"Skipping non-global IP: {validated_ip}")
                    continue
            except ValueError:
                continue

            enrichment = {
                "malware_printable": ioc_data.get("malware_printable", ""),
                "threat_type": ioc_data.get("threat_type", ""),
                "confidence_level": ioc_data.get("confidence_level"),
            }

            if validated_ip not in feed_by_ip:
                feed_by_ip[validated_ip] = []
            feed_by_ip[validated_ip].append(enrichment)

        return feed_by_ip

    def _build_tag_entries(self, matching_iocs, feed_by_ip) -> list[dict]:
        tag_entries = []
        for ioc_id, ioc_name in matching_iocs:
            for enrichment in feed_by_ip[ioc_name]:
                if enrichment.get("malware_printable"):
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "malware",
                            "value": enrichment["malware_printable"],
                        }
                    )
                if enrichment.get("threat_type"):
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "threat_type",
                            "value": enrichment["threat_type"],
                        }
                    )
                if enrichment.get("confidence_level") is not None:
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "confidence_level",
                            "value": str(enrichment["confidence_level"]),
                        }
                    )
        return tag_entries

    @staticmethod
    def _extract_ip(ioc_value: str, ioc_type: str) -> str | None:
        """
        Extract IP address from various ThreatFox IOC formats.

        Args:
            ioc_value: The raw IOC value string.
            ioc_type: The IOC type (e.g., "ip:port", "url").

        Returns:
            Extracted IP string or None.
        """
        if ioc_type == "ip:port":
            return ioc_value.split(":")[0] if ":" in ioc_value else None
        if ioc_type in ("ip", "ipv4"):
            return ioc_value
        if ioc_type == "url":
            ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
            match = re.search(ip_pattern, ioc_value)
            return match.group(1) if match else None
        return None
