import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.db.models import F

from greedybear.consts import MASS_SCANNER_DOMAINS
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import IocRepository
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.enums import IpReputation
from greedybear.models import IOC, IocType

# Number of concurrent DNS lookups.
THREAD_POOL_SIZE = 20

# Maximum number of candidate IPs to check per run.
MAX_CANDIDATES = 500

# Timeout in seconds for each DNS lookup.
DNS_TIMEOUT = 2

SOURCE_NAME = "rdns"


class ReverseDNSCron(Cronjob):
    """
    Identify mass scanning services via reverse DNS lookups.

    Runs daily, selects the top candidates most likely to be mass scanners
    based on behavioral heuristics (persistent, no login attempts, low
    interaction-to-attack ratio), resolves their PTR records in parallel,
    and marks matches against a curated list of mass scanner domains.
    Only IPs with actual PTR records are tagged, so IPs without records
    are rechecked on subsequent runs.
    """

    def __init__(self, tag_repo=None, ioc_repo=None):
        """
        Initialize the cron job with repository dependencies.

        Args:
            tag_repo: Optional TagRepository instance for testing.
            ioc_repo: Optional IocRepository instance for testing.
        """
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def run(self) -> None:
        """
        Perform reverse DNS lookups on the most probable scanner candidates.

        1. Select top candidates using behavioral heuristics.
        2. Resolve PTR records in parallel.
        3. Store non-empty PTR results as tags.
        4. Update reputation for IPs matching mass scanner domains.
        """
        candidates = self._get_candidates()

        if not candidates:
            self.log.info("No IOCs to check")
            return

        ip_to_id = {name: ioc_id for ioc_id, name in candidates}

        # Resolve PTR records in parallel
        ptr_results = self._resolve_batch(list(ip_to_id.keys()))

        # Only tag IPs that have actual PTR records — IPs without PTR
        # are left untagged so they can be rechecked on future runs.
        tag_entries = []
        matched_ips = []

        for ip, ptr in ptr_results.items():
            if not ptr:
                continue

            tag_entries.append({"ioc_id": ip_to_id[ip], "key": "ptr_record", "value": ptr})

            if self._matches_scanner_domain(ptr):
                matched_ips.append(ip)

        if matched_ips:
            updated_count = self.ioc_repo.bulk_update_ioc_reputation(matched_ips, IpReputation.MASS_SCANNER.value)
            self.log.info(f"Marked {updated_count} IPs as mass scanners via rDNS")

        created_count = self.tag_repo.add_tags(SOURCE_NAME, tag_entries)
        self.log.info(f"Reverse DNS check completed. Checked {len(ptr_results)} IPs, created {created_count} tags, {len(matched_ips)} matched mass scanners")

    def _get_candidates(self):
        """
        Select the top IOCs most likely to be mass scanners.

        Behavioral heuristics:
        - Seen on more than 2 distinct days (persistent presence)
        - Zero login attempts (scanners don't try credentials)
        - Low interaction-to-attack ratio (interaction_count < 2 * attack_count)
        - No existing reputation classification
        - Not already tagged by this source (already has PTR on file)

        Returns the top MAX_CANDIDATES ordered by persistence.
        """
        return list(
            IOC.objects.filter(
                type=IocType.IP,
                ip_reputation="",
                number_of_days_seen__gt=2,
                login_attempts=0,
                interaction_count__lt=F("attack_count") * 2,
            )
            .exclude(tags__source=SOURCE_NAME)
            .order_by("-number_of_days_seen")
            .values_list("id", "name")
            .distinct()[:MAX_CANDIDATES]
        )

    def _resolve_batch(self, ips: list[str]) -> dict[str, str]:
        """
        Resolve PTR records for a batch of IPs in parallel.

        Sets an explicit socket timeout for the duration of the batch
        and restores the previous value afterwards.  Each IP is resolved
        independently — one failure does not affect the rest of the batch.

        Args:
            ips: List of IP addresses to resolve.

        Returns:
            Dict mapping IP address to PTR hostname (or empty string).
        """
        results = {}
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT)
        try:
            with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
                future_to_ip = {executor.submit(self._resolve_ptr, ip): ip for ip in ips}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        results[ip] = future.result()
                    except Exception:
                        self.log.exception(f"Unexpected error resolving PTR for {ip}")
                        results[ip] = ""
        finally:
            socket.setdefaulttimeout(old_timeout)
        return results

    def _resolve_ptr(self, ip: str) -> str:
        """
        Perform a reverse DNS lookup.

        The socket timeout is set once by _resolve_batch before threads
        are spawned, so all lookups share the configured DNS_TIMEOUT.

        Args:
            ip: IP address to resolve.

        Returns:
            The PTR hostname, or an empty string on any failure.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, TimeoutError, OSError):
            return ""
        else:
            return hostname

    @staticmethod
    def _matches_scanner_domain(hostname: str) -> bool:
        """
        Check whether a PTR hostname belongs to a mass scanning service.

        Args:
            hostname: The resolved PTR record.

        Returns:
            True if the hostname matches a mass scanner domain.
        """
        hostname_lower = hostname.lower()
        return any(hostname_lower == domain or hostname_lower.endswith("." + domain) for domain in MASS_SCANNER_DOMAINS)
