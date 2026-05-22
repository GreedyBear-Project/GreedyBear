import re
from ipaddress import ip_address

import requests
from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC
from greedybear.utils import is_valid_ipv4

SOURCE_NAME = "threatfox"


class ThreatFoxCron(Cronjob):
    """
    Fetch ThreatFox IOC data and directly enrich matching IOCs with tags.

    Downloads IP-based IOCs from ThreatFox, joins them directly against
    the IOC table, and writes Tag entries for any matches. Tags are only
    replaced on successful API responses; on errors or non-OK status,
    existing tags are preserved to avoid losing enrichment data.
    """

    def __init__(self, tag_repo=None):
        """
        Initialize the ThreatFox cronjob.

        Args:
            tag_repo: Optional TagRepository instance for testing.
        """
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()

    def run(self) -> None:
        """
        Fetch ThreatFox IOCs, match against our IOC table, and create tags.

        1. Download recent IOCs from ThreatFox API (last 7 days)
        2. Extract and validate IP addresses
        3. Query our IOC table for matching IPs (WHERE name IN ...)
        4. Replace all ThreatFox tags with fresh data

        On API errors or non-OK query_status, existing tags are intentionally
        preserved so enrichment data is not lost due to transient failures.
        """
        api_key = settings.THREATFOX_API_KEY
        if not api_key:
            self.log.warning("ThreatFox API key not configured. Skipping enrichment.")
            return

        try:
            self.log.info("Starting ThreatFox feed download for enrichment")

            # Fetch recent IOCs from ThreatFox (last 7 days)
            url = "https://threatfox-api.abuse.ch/api/v1/"
            headers = {
                "Content-Type": "application/json",
                "Auth-Key": api_key,
            }
            data = {"query": "get_iocs", "days": 7}

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()

            json_data = response.json()

            if json_data.get("query_status") != "ok":
                self.log.warning(f"ThreatFox API returned non-OK status: {json_data.get('query_status')}")
                return

            iocs_data = json_data.get("data", [])
            self.log.info(f"Retrieved {len(iocs_data)} IOCs from ThreatFox")

            # Parse feed into a dict keyed by IP: list of enrichment data
            feed_by_ip = self._parse_feed(iocs_data)
            self.log.info(f"Parsed {len(feed_by_ip)} unique IPs from ThreatFox feed")

            if not feed_by_ip:
                # No valid IPs found — clear stale tags and return
                self.tag_repo.replace_tags_for_source(SOURCE_NAME, [])
                return

            # Join against IOC table: find IOCs whose name matches feed IPs
            matching_iocs = IOC.objects.filter(name__in=feed_by_ip.keys()).values_list("id", "name")

            # Build tag entries for matching IOCs
            tag_entries = []
            matched_count = 0
            for ioc_id, ioc_name in matching_iocs:
                matched_count += 1
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

            # Replace all ThreatFox tags atomically
            created_count = self.tag_repo.replace_tags_for_source(SOURCE_NAME, tag_entries)
            self.log.info(f"ThreatFox enrichment completed. Matched {matched_count} IOCs, created {created_count} tags.")

        except requests.RequestException:
            self.log.exception("Failed to fetch ThreatFox feed")
            raise

    def _parse_feed(self, iocs_data: list) -> dict[str, list[dict]]:
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
