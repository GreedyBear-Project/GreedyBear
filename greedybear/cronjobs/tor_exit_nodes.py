import re

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import IocRepository
from greedybear.cronjobs.repositories.tor import TorRepository
from greedybear.enums import IpReputation
from greedybear.utils import is_valid_ipv4


class TorExitNodesCron(Cronjob):
    """Fetch and store Tor exit node IP addresses from Tor Project."""

    def __init__(self, tor_repo=None, ioc_repo=None):
        super().__init__()
        self.tor_repo = tor_repo if tor_repo is not None else TorRepository()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def run(self) -> None:
        """Fetch Tor exit node IPs from torproject.org and store them."""
        ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

        try:
            self.log.info("Starting download of Tor exit node list from torproject.org")

            r = requests.get(
                "https://check.torproject.org/exit-addresses",
                timeout=10,
            )
            r.raise_for_status()

            findings = ip_regex.findall(r.text)

            for ip_candidate in findings:
                is_valid, ip_address = is_valid_ipv4(ip_candidate)
                if not is_valid:
                    self.log.debug(f"Invalid IPv4 address: {ip_candidate}")
                    continue

                _, created = self.tor_repo.get_or_create(ip_address)
                if created:
                    self.log.info(f"Added new Tor exit node {ip_address}")
                    self.ioc_repo.update_ioc_reputation(ip_address, IpReputation.TOR_EXIT_NODE)

            self.log.info("Completed download of Tor exit node list")

        except requests.RequestException:
            self.log.exception("Failed to fetch Tor exit nodes")
            raise
