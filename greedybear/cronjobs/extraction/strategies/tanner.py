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
        self.attack_types_set = set()
        self.iocs_with_attack_types = 0
        self.rfi_hostnames_added = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Extract IOCs from Tanner honeypot log hits.

        Processes scanner IPs, classifies web attacks by analyzing URLs
        and POST bodies, stores attack types on IOC.http_attack_types, and
        extracts RFI hostnames as PAYLOAD_REQUEST IOCs.

        Args:
            hits: List of Elasticsearch hit dictionaries to process.
        """
        self.attack_types_set = set()
        self._get_scanners(hits)
        self._classify_attacks(hits)

        attack_types_by_ioc = {}
        for ioc_id, attack_type in self.attack_types_set:
            attack_types_by_ioc.setdefault(ioc_id, set()).add(attack_type)

        # Merging into the existing values instead of replacing them because
        # this strategy only processes the current extraction chunk (new hits)
        # each run. Replacing would drop attack types found for the same IOC
        # in previous runs just because they aren't in today's chunk.
        self.iocs_with_attack_types += self.ioc_repo.bulk_add_http_attack_types(attack_types_by_ioc)

        self.log.info(
            f"added {len(self.ioc_records)} scanners, attack types for {self.iocs_with_attack_types} IOCs, "
            f"{self.rfi_hostnames_added} RFI hostnames from {self.honeypot}"
        )

    def _get_scanners(self, hits: list[dict]) -> None:
        """Extract scanner IPs from hits."""
        for ioc in iocs_from_hits(hits):
            self.log.info(f"found IP {ioc.name} by honeypot {self.honeypot}")
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name=TANNER_HONEYPOT)
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)

    def _classify_attacks(self, hits: list[dict]) -> None:
        """
        Classify web attacks from request data and record types + RFI IOCs.

        Analyzes URL and POST body of each hit against attack patterns.
        A single request can match multiple attack types.

        Args:
            hits: List of Elasticsearch hit documents.
        """
        # Seed cache from IOC records already loaded by _get_scanners to avoid
        # repeated DB lookups for the same scanner IP across many hits.
        ioc_cache: dict[str, object] = {ioc.name: ioc for ioc in self.ioc_records}

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

            # Find the IOC record for this scanner to record its attack types.
            # Use cache to avoid one DB query per hit; fall back to the repo
            # for IPs not already loaded by _get_scanners.
            if scanner_ip not in ioc_cache:
                ioc_cache[scanner_ip] = self.ioc_repo.get_ioc_by_name(scanner_ip)
            ioc_record = ioc_cache[scanner_ip]
            if not ioc_record:
                continue

            self._add_attack_types(ioc_record, attack_types)

            # If RFI detected, extract remote hostnames as PAYLOAD_REQUEST IOCs
            if "rfi" in attack_types:
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

    def _add_attack_types(self, ioc_record: IOC, attack_types: list[str]) -> None:
        """
        Buffer detected attack types for later storage on the IOC.

        Collects (ioc_id, attack_type) pairs so they can be written to
        IOC.http_attack_types in a single bulk operation once the whole
        chunk has been processed.

        Args:
            ioc_record: Persisted IOC instance.
            attack_types: List of attack type strings to store.
        """
        if not ioc_record.id:
            return
        for attack_type in attack_types:
            self.attack_types_set.add((ioc_record.id, attack_type))

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
