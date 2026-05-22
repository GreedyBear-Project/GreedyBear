import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.utils import is_valid_cidr, is_valid_ipv4


class FireHolCron(Cronjob):
    """
    Fetch and store IP blocklists from FireHol repository.

    Downloads IP blocklists from multiple sources and stores them in the database.
    Automatically cleans up entries older than 30 days.
    """

    def __init__(self, firehol_repo=None):
        """
        Initialize the FireHol cronjob with repository dependency.

        Args:
            firehol_repo: Optional FireHolRepository instance for testing.
        """
        super().__init__()
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
                    response = requests.get(url, timeout=60)
                    response.raise_for_status()
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

    def _cleanup_old_entries(self):
        """
        Delete FireHolList entries older than 30 days to keep database clean.
        """
        deleted_count = self.firehol_repo.cleanup_old_entries(days=30)
        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old FireHolList entries")
