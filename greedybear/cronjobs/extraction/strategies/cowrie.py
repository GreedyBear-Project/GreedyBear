# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from collections import defaultdict
from hashlib import sha256
from urllib.parse import urlparse

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies import BaseExtractionStrategy
from greedybear.cronjobs.extraction.utils import (
    iocs_from_hits,
    normalize_credential_field,
    threatfox_submission,
)
from greedybear.cronjobs.repositories import (
    CowrieSessionRepository,
    IocRepository,
    SensorRepository,
)
from greedybear.models import IOC, CommandSequence, CowrieSession
from greedybear.regex import REGEX_URL_PROTOCOL
from greedybear.utils import get_ioc_type, parse_timestamp


def parse_url_hostname(url: str) -> str | None:
    """
    Extract hostname from URL safely.

    Args:
        url: URL string to parse

    Returns:
        Hostname if parsing succeeds, None otherwise
    """
    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError):
        return None
    else:
        return parsed.hostname


def normalize_command(message: str) -> str:
    """
    Normalize command string by removing CMD prefix and null characters.

    Args:
        message: Raw command message string

    Returns:
        Normalized command string, truncated to 1024 characters
    """
    # Truncate to 1024 chars to match CommandSequence.commands field max_length
    return message.removeprefix("CMD: ").replace("\x00", "[NUL]")[:1024]


class CowrieExtractionStrategy(BaseExtractionStrategy):
    """
    Extraction strategy for Cowrie SSH/Telnet honeypot.

    Extracts scanner IPs, payload URLs from login attempts and file
    downloads, and session data including credentials and command
    sequences. Links related IOCs (scanners to download URLs) and
    deduplicates command sequences by hash.
    """

    def __init__(
        self,
        honeypot: str,
        ioc_repo: IocRepository,
        sensor_repo: SensorRepository,
        session_repo: CowrieSessionRepository = None,
    ):
        super().__init__(honeypot, ioc_repo, sensor_repo)
        self.session_repo = session_repo or CowrieSessionRepository()
        self.payloads_in_message = 0
        self.added_url_downloads = 0

    def extract_from_hits(self, hits: list[dict]) -> None:
        """
        Main extraction entry point. Processes hits and extracts scanners,
        payloads, downloads, and sessions.

        Args:
            hits: List of Elasticsearch hit documents
        """
        self._get_scanners(hits)
        self._extract_possible_payload_in_messages(hits)
        self._get_url_downloads(hits)
        self.log.info(
            f"added {len(self.ioc_records)} scanners, {self.payloads_in_message} payloads found in messages, {self.added_url_downloads} download URLs"
        )

    def _get_scanners(self, hits: list[dict]) -> None:
        """Extract scanner IPs and sessions."""
        hits_by_ip = defaultdict(list)
        for hit in hits:
            hits_by_ip[hit["src_ip"]].append(hit)

        for ioc in iocs_from_hits(hits):
            self.log.info(f"found IP {ioc.name} by honeypot cowrie")
            ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=SCANNER, honeypot_name="Cowrie")
            if ioc_record:
                self.ioc_records.append(ioc_record)
                threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._get_sessions(ioc_record, hits_by_ip.get(ioc.name, []))

    def _extract_possible_payload_in_messages(self, hits: list[dict]) -> None:
        """
        Extract URLs hidden in attack payloads (login messages, file uploads).
        Processes all hits once for efficiency (O(M) instead of O(N*M)).

        Args:
            hits: List of hits to search for payloads
        """
        for hit in hits:
            if hit.get("eventid", "") not in [
                "cowrie.login.failed",
                "cowrie.session.file_upload",
            ]:
                continue

            match_url = re.search(REGEX_URL_PROTOCOL, hit.get("message", ""))
            if not match_url:
                continue

            scanner_ip = hit["src_ip"]
            payload_url = match_url.group()
            payload_hostname = parse_url_hostname(payload_url)

            if not payload_hostname:
                self.log.warning(f"Failed to parse hostname from URL: {payload_url}")
                continue

            self.log.info(f"found hidden URL {payload_url} in payload from attacker {scanner_ip}")
            self.log.info(f"extracted hostname {payload_hostname} from {payload_url}")

            hit_time = parse_timestamp(hit["@timestamp"])
            ioc = IOC(
                name=payload_hostname,
                type=get_ioc_type(payload_hostname),
                first_seen=hit_time,
                last_seen=hit_time,
                related_urls=[payload_url],
            )
            sensor = hit.get("_sensor")
            if sensor:
                ioc._sensors_to_add = [sensor]
            self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST, honeypot_name="Cowrie")
            self._add_fks(scanner_ip, payload_hostname)
            self.payloads_in_message += 1

    def _get_url_downloads(self, hits: list[dict]) -> None:
        """
        Extract file download attempts and associate scanners with download URLs.

        Args:
            hits: List of hits to search for download events
        """
        for hit in hits:
            if "url" not in hit:
                continue
            if hit.get("eventid", "") != "cowrie.session.file_download":
                continue

            scanner_ip = str(hit["src_ip"])
            download_url = str(hit["url"])
            shasum = hit.get("shasum")
            sha_suffix = f" (SHA256: {shasum})" if shasum else ""
            self.log.info(f"found IP {scanner_ip} downloading from {download_url}{sha_suffix}")

            # Extract and track download URL
            if download_url:
                hostname = parse_url_hostname(download_url)
                if not hostname:
                    self.log.warning(f"Failed to parse hostname from download URL: {download_url}")
                    continue

                hit_time = parse_timestamp(hit["@timestamp"])
                ioc = IOC(
                    name=hostname,
                    type=get_ioc_type(hostname),
                    first_seen=hit_time,
                    last_seen=hit_time,
                    related_urls=[download_url],
                )
                sensor = hit.get("_sensor")
                if sensor:
                    ioc._sensors_to_add = [sensor]
                ioc_record = self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST, honeypot_name="Cowrie")
                if ioc_record:
                    self.added_url_downloads += 1
                    threatfox_submission(ioc_record, ioc.related_urls, self.log)
                self._add_fks(scanner_ip, hostname)

    def _get_sessions(self, ioc: IOC, hits: list[dict]) -> None:
        """
        Extract and save session data for a given scanner IOC.

        Args:
            ioc: Scanner IOC object
            hits: List of hits to process
        """
        self.log.info(f"adding cowrie sessions from {ioc.name}")
        hits_per_session = defaultdict(list)

        for hit in hits:
            hits_per_session[hit["session"]].append(hit)

        for sid, session_hits in hits_per_session.items():
            session_record = self.session_repo.get_or_create_session(session_id=sid, source=ioc)

            for hit in sorted(session_hits, key=lambda hit: hit["timestamp"]):
                self._process_session_hit(session_record, hit, ioc)

            if session_record.commands is not None:
                self._deduplicate_command_sequence(session_record)
                self.session_repo.save_command_sequence(session_record.commands)
                self.log.info(f"saved new command execute from {ioc.name} with hash {session_record.commands.commands_hash}")

            self.ioc_repo.save(session_record.source)
            self.session_repo.save_session(session_record)

        self.log.info(f"{len(hits_per_session)} sessions added")

    def _process_session_hit(self, session_record: CowrieSession, hit: dict, ioc: IOC) -> None:
        """
        Process a single hit and update the session record.

        Args:
            session_record: CowrieSession instance to update
            hit: Hit document to process
            ioc: Associated IOC for logging
        """
        eventid = hit.get("eventid")

        match eventid:
            case "cowrie.session.connect":
                session_record.start_time = parse_timestamp(hit["timestamp"])

            case "cowrie.login.failed" | "cowrie.login.success":
                session_record.login_attempt = True
                username = normalize_credential_field(hit["username"])
                password = normalize_credential_field(hit["password"])
                self.session_repo.add_credential(session_record, username, password)

            case "cowrie.command.input":
                self.log.info(f"found a command execution from {ioc.name}")
                session_record.command_execution = True

                if session_record.commands is None:
                    session_record.commands = CommandSequence()
                    session_record.commands.first_seen = parse_timestamp(hit["timestamp"])

                command = normalize_command(hit["message"])
                session_record.commands.last_seen = parse_timestamp(hit["timestamp"])
                session_record.commands.commands.append(command)

            case "cowrie.session.closed":
                session_record.duration = hit["duration"]

            case "cowrie.session.file_download" | "cowrie.session.file_upload":
                shasum = hit.get("shasum")
                if shasum:
                    url = hit.get("url", "")
                    outfile = hit.get("outfile", "")
                    timestamp = parse_timestamp(hit["timestamp"])
                    self.log.info(f"found file with shasum {shasum[:8]}... from {ioc.name}")

                    self.session_repo.get_or_create_file_transfer(
                        session=session_record,
                        shasum=shasum,
                        url=url,
                        outfile=outfile,
                        timestamp=timestamp,
                    )

        session_record.interaction_count += 1

    def _deduplicate_command_sequence(self, session: CowrieSession) -> bool:
        """
        Deduplicate command sequences by hashing and merging with existing sequences.

        Args:
            session: CowrieSession instance containing command sequence data

        Returns:
            True if merged with existing sequence, False if new sequence
        """
        commands_str = "\n".join(session.commands.commands)
        commands_hash = sha256(commands_str.encode()).hexdigest()

        cmd_seq = self.session_repo.get_command_sequence_by_hash(commands_hash=commands_hash)
        if cmd_seq is None:
            session.commands.commands_hash = commands_hash
            return False

        last_seen = session.commands.last_seen
        session.commands = cmd_seq
        session.commands.last_seen = last_seen
        return True
