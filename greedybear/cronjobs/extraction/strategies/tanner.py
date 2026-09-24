# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from urllib.parse import unquote, unquote_plus, urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (
    iocs_from_hits,
    threatfox_submission,
)
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.models import IOC
from greedybear.utils import get_ioc_type, parse_timestamp

# Attack classification regex patterns.
# Each pattern targets common signatures of its respective web attack class.
TANNER_ATTACK_PATTERNS = {
    "sqli": re.compile(
        r"(?i)"
        r"(?:union\s+(?:all\s+)?select|"
        r"(?:'\s*|\b)or\s+['\"]?[0-9].*?=|"
        r";\s*(?:drop|alter|delete|insert|update)\b|"
        r"(?:sleep|benchmark|waitfor|pg_sleep)\s*\(|"
        r"(?:concat|char|hex|unhex|load_file|group_concat)\s*\(|"
        r"(?:information_schema|sys\.objects|mysql\.user)|"
        r"--\s*$|"
        r"/\*.*?\*/|"
        r"'\s*;\s*\w)"
    ),
    "xss": re.compile(
        r"(?i)"
        r"(?:<\s*script[\s>]|"
        r"javascript\s*:|"
        r"\bon(?:error|load|mouseover|click|focus|blur)\s*=|"
        r"<\s*(?:img|svg|iframe|object|embed|video|audio|body|input|details|marquee)\b[^>]*"
        r"(?:on\w+\s*=|src\s*=\s*['\"]?javascript)|"
        r"(?:alert|confirm|prompt|eval|document\.(?:cookie|write|location))\s*\(|"
        r"<\s*/?\s*(?:script|iframe))"
    ),
    "lfi": re.compile(
        r"(?i)"
        r"(?:\.\.[\\/]|"
        r"/etc/(?:passwd|shadow|hosts|issue|motd)|"
        r"/proc/self/|"
        r"(?:php|zip|data|expect|phar)://|"
        r"(?:c:\\\\|%00|%2500))"
    ),
    "rfi": re.compile(
        r"(?i)"
        r"(?:(?:=|include|require|file)\s*(?:https?|ftp)://|"
        r"(?:https?|ftp)://[^\s'\"<>]+\.(?:php|txt|asp|jsp|cgi|pl))"
    ),
    "cmd_injection": re.compile(
        r"(?i)"
        r"(?:(?:;|\|{1,2}|&&|\$\(|`)\s*"
        r"(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php|nslookup|ping|ifconfig|ip\s+addr)|"
        r"/bin/(?:sh|bash|dash|zsh|csh)|"
        r"\$\{[^}]*\}|"
        r">\s*/(?:tmp|dev/null)|"
        r"\beval\s*\()"
    ),
}


TANNER_HONEYPOT = "Tanner"


class TannerExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Tanner (SNARE/Tanner web honeypot).

    Classifies web attack attempts (SQLi, XSS, LFI, RFI, command injection)
    by analyzing request URLs and POST bodies. Stores attack type classifications
    on IOC.http_attack_types and extracts RFI hostnames as PAYLOAD_REQUEST IOCs.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)
        self.iocs_with_attack_types = 0
        self.rfi_hostnames_added = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOCs from Tanner honeypot log hits.

        Finds the attack types in each hit, saves the scanner IPs with
        their attack types, then saves RFI hostnames as PAYLOAD_REQUEST IOCs.

        Args:
            hits: List of hits Elasticsearch.
        """
        detections = self._classify_hits(hits)

        attack_types_by_ip: dict[str, set[str]] = {}
        for _, scanner_ip, _, attack_types in detections:
            attack_types_by_ip.setdefault(scanner_ip, set()).update(attack_types)

        # The new types are added to the stored ones in _merge_iocs, not
        # swapped in, because each run only sees the newest hits. Swapping
        # them in would drop attack types found in earlier runs.
        self._get_scanners(hits, attack_types_by_ip)
        self._handle_rfi(detections)

        self.log.info(
            f"added {len(self.ioc_records)} scanners, attack types for {self.iocs_with_attack_types} IOCs, "
            f"{self.rfi_hostnames_added} RFI hostnames from {self.honeypot}"
        )

    def _get_scanners(self, hits: list[dict], attack_types_by_ip: dict[str, set[str]]) -> None:
        """
        Save each scanner IP with the attack types found for it.

        The types are set on the IOC before add_ioc runs. If the IP is
        already known, _merge_iocs adds the new types to the old ones.

        Args:
            hits: List of hits from Elasticsearch.
            attack_types_by_ip: Attack types found for each scanner IP.
        """
        for ioc in iocs_from_hits(hits):
            self.log.info(f"found IP {ioc.name} by honeypot {self.honeypot}")
            ioc.http_attack_types = sorted(attack_types_by_ip.get(ioc.name, set()))
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name=TANNER_HONEYPOT)
            if ioc_record:
                self.ioc_records.append(ioc_record)
                if ioc.http_attack_types:
                    self.iocs_with_attack_types += 1
                threatfox_submission(ioc_record, ioc.related_urls, self.log)

    def _classify_hits(self, hits: list[dict]) -> list[tuple[dict, str, str, list[str]]]:
        """
        Find the attack types in each hit, without using the database.

        This runs before _get_scanners, so the types can be set on each
        scanner IOC before it is saved.

        Args:
            hits: List of hits from Elasticsearch.

        Returns:
            One (hit, scanner_ip, request_text, attack_types) tuple for each
            hit where an attack was found.
        """
        detections = []
        for hit in hits:
            scanner_ip = hit.get("src_ip")
            if not scanner_ip:
                continue

            # Build the text to classify from URL and POST body
            request_text = self._extract_request_text(hit)
            if not request_text:
                continue

            attack_types = self._detect_attack_types(request_text)
            if not attack_types:
                continue

            detections.append((hit, scanner_ip, request_text, attack_types))
        return detections

    def _handle_rfi(self, detections: list[tuple[dict, str, str, list[str]]]) -> None:
        """
        Save the remote hostnames from RFI attacks as PAYLOAD_REQUEST IOCs.

        This runs after _get_scanners, because each hostname is linked to
        its scanner, and the scanner must be saved first.

        Args:
            detections: Output of _classify_hits.
        """
        # Seed cache from IOC records already loaded by _get_scanners to avoid
        # repeated DB lookups for the same scanner IP across many hits.
        ioc_cache: dict[str, object] = {ioc.name: ioc for ioc in self.ioc_records}

        for hit, scanner_ip, request_text, attack_types in detections:
            if "rfi" not in attack_types:
                continue

            # Only handle RFI for known scanners. Use the cache to avoid one
            # DB query per hit; fall back to the repo for IPs not loaded above.
            if scanner_ip not in ioc_cache:
                ioc_cache[scanner_ip] = self.ioc_repo.get_ioc_by_name(scanner_ip)
            if not ioc_cache[scanner_ip]:
                continue

            self._extract_rfi_hostnames(hit, scanner_ip, request_text)

    def _extract_request_text(self, hit: dict) -> str:
        """
        Build a combined text from the URL path, query string, and POST body.

        Args:
            hit: Elasticsearch hit document.

        Returns:
            Combined request text for classification, or empty string.
        """
        parts = []

        url = hit.get("url", "") or hit.get("path", "")
        if url:
            # Decode %xx sequences in the path and also decode + as space in the
            # query string (application/x-www-form-urlencoded convention), so
            # payloads like UNION+SELECT are normalised before regex matching.
            parsed = urlparse(url)
            decoded = unquote(parsed.path)
            if parsed.query:
                decoded += "?" + unquote_plus(parsed.query)
            parts.append(decoded)

        body = hit.get("post_data", "") or hit.get("body", "")
        if body:
            # POST form bodies use + as space; unquote_plus handles both.
            parts.append(unquote_plus(str(body)))

        return "\n".join(parts)

    def _detect_attack_types(self, text: str) -> list[str]:
        """
        Run all attack-type regexes against request text.

        A single request can match multiple attack types.

        Args:
            text: Combined request URL + body text.

        Returns:
            List of matched attack type keys (e.g., ["sqli", "xss"]).
        """
        return [attack_type for attack_type, pattern in TANNER_ATTACK_PATTERNS.items() if pattern.search(text)]

    def _extract_rfi_hostnames(self, hit: dict, scanner_ip: str, request_text: str) -> None:
        """
        Extract remote hostnames from RFI payloads as PAYLOAD_REQUEST IOCs.

        Finds URLs in the request text, extracts their hostnames,
        and creates PAYLOAD_REQUEST IOC records linked to the scanner.

        Args:
            hit: Original Elasticsearch hit.
            scanner_ip: Scanner IP address.
            request_text: Combined request text.
        """
        urls = re.findall(r"(?:https?|ftp)://[^\s'\"<>]+", request_text, re.IGNORECASE)
        seen_hostnames = set()

        timestamp_str = hit.get("@timestamp")
        hit_time = parse_timestamp(timestamp_str) if timestamp_str else None

        for url in urls:
            # Strip trailing characters that are almost never unencoded at the end of a URL
            url = url.rstrip("),;")
            # If there is no query string, any '&' must be an outer request parameter
            # separator (not part of the embedded URL's own query string) — strip it.
            if "?" not in url:
                url = url.split("&")[0]

            try:
                hostname = urlparse(url).hostname
            except (ValueError, AttributeError):
                continue

            if not hostname or hostname in seen_hostnames:
                continue
            seen_hostnames.add(hostname)

            self.log.info(f"found RFI hostname {hostname} from {url} in request from {scanner_ip}")

            ioc_kwargs: dict = {
                "name": hostname,
                "type": get_ioc_type(hostname),
                "related_urls": [url],
            }
            if hit_time is not None:
                ioc_kwargs["first_seen"] = hit_time
                ioc_kwargs["last_seen"] = hit_time
            ioc = IOC(**ioc_kwargs)
            sensor = hit.get("_sensor")
            if sensor:
                ioc._sensors_to_add = [sensor]

            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST, honeypot_name=TANNER_HONEYPOT)
            if ioc_record:
                self.rfi_hostnames_added += 1
                threatfox_submission(ioc_record, ioc.related_urls, self.log)

            self._add_fks(scanner_ip, hostname)
