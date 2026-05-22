import re

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.http_client import HttpClient
from greedybear.cronjobs.repositories import IocRepository, MassScannerRepository
from greedybear.enums import IpReputation
from greedybear.utils import is_valid_ipv4


class MassScannersCron(Cronjob):
    """
    Fetch and store mass scanner IP addresses from Maltrail repository.

    Downloads the mass scanner list from Maltrail's GitHub repository,
    validates IP addresses, and stores them in the database. Also updates
    the IP reputation of existing IOCs.
    """

    def __init__(self, mass_scanner_repo=None, ioc_repo=None):
        """
        Initialize the mass scanners cronjob with repository dependencies.

        Args:
            mass_scanner_repo: Optional MassScannerRepository instance for testing.
            ioc_repo: Optional IocRepository instance for testing.
        """
        super().__init__()
        self.mass_scanner_repo = mass_scanner_repo if mass_scanner_repo is not None else MassScannerRepository()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def run(self) -> None:
        """
        Fetch mass scanner IPs from Maltrail and store them.

        Extracts IP addresses from the Maltrail mass scanner list, validates them,
        and creates database entries. For each new mass scanner, also updates
        any existing IOC with the same IP address to mark it as a mass scanner.
        """
        # Simple regex to extract potential IPv4 addresses
        ip_candidate_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        # Regex to extract optional comment/reason after '#'
        comment_regex = re.compile(r"#\s*(.+)")

        try:
            with HttpClient() as client:
                r = client.get("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt")
        except requests.RequestException as e:
            self.log.error(f"Failed to fetch mass scanner list: {e}")
            raise

        for line_bytes in r.iter_lines():
            if line_bytes:
                line = line_bytes.decode("utf-8")
                if not line or line.startswith("#"):
                    continue

                # Try to extract IP candidate from the line
                ip_match = ip_candidate_regex.search(line)
                if not ip_match:
                    # No IP-like pattern found, log at DEBUG level
                    self.log.debug(f"No IP pattern found in line: {line}")
                    continue

                # Validate the extracted candidate
                is_valid, ip_address = is_valid_ipv4(ip_match.group(1))
                if not is_valid:
                    # Not a valid IPv4, log at DEBUG level
                    self.log.debug(f"Invalid IPv4 address in line: {line}")
                    continue

                # Extract optional comment/reason
                reason = ""
                comment_match = comment_regex.search(line)
                if comment_match:
                    reason = comment_match.group(1)

                # Add or update mass scanner entry
                _, created = self.mass_scanner_repo.get_or_create(ip_address, reason)
                if created:
                    self.log.info(f"added new mass scanner {ip_address}")
                    self.ioc_repo.update_ioc_reputation(ip_address, IpReputation.MASS_SCANNER)
