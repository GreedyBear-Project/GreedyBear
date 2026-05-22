import json

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.utils import is_valid_cidr, is_valid_ipv4

SOURCE_NAME = "spamhaus_drop"
FEED_URL = "https://www.spamhaus.org/drop/drop_v4.json"


class SpamhausDropCron(Cronjob):
    """
    Fetch Spamhaus DROP v4 list and store malicious CIDR netblocks.

    DROP is a high-confidence blocklist of IPv4 netblocks used by spam and
    cyber-crime operations. Stored in FireHolList table (same as FireHOL).
    """

    def __init__(self, firehol_repo=None):
        super().__init__()
        self.firehol_repo = firehol_repo if firehol_repo is not None else FireHolRepository()

    def run(self) -> None:
        self.log.info("Starting Spamhaus DROP v4 import")
        self._fetch_drop_feed()
        self._cleanup_old_entries()

    def _fetch_drop_feed(self):
        """Fetch and process Spamhaus DROP v4 feed (JSON Lines format)."""
        try:
            self.log.info(f"Fetching from {FEED_URL}")
            response = requests.get(FEED_URL, timeout=60)
            response.raise_for_status()

            lines = response.text.strip().splitlines()
            self.log.info(f"Retrieved {len(lines)} entries from Spamhaus DROP v4")

            added_count = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    cidr = entry.get("cidr")
                    if not cidr:
                        continue

                    if not (is_valid_ipv4(cidr)[0] or is_valid_cidr(cidr)[0]):
                        self.log.debug(f"Invalid CIDR skipped: {cidr}")
                        continue

                    _, created = self.firehol_repo.get_or_create(cidr, SOURCE_NAME)
                    if created:
                        added_count += 1

                except json.JSONDecodeError:
                    self.log.debug(f"Failed to parse line: {line[:100]}")

            self.log.info(f"Added {added_count} new entries from Spamhaus DROP v4")

        except requests.RequestException:
            self.log.exception("Failed to fetch Spamhaus DROP v4")
            # do not re-raise, let the cronjob continue on network issues
        except Exception:
            self.log.exception("Unexpected error in Spamhaus DROP")
            # re-raise on some unexpected error
            raise

    def _cleanup_old_entries(self):
        """Delete old entries after 30 days (same as FireHOL)."""
        deleted_count = self.firehol_repo.cleanup_old_entries(days=30)
        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old Spamhaus DROP entries")
