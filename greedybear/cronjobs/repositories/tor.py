import logging

from greedybear.enums import IpReputation
from greedybear.models import TorExitNode


class TorRepository:
    """Repository for data access to Tor exit node entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, reason: str = IpReputation.TOR_EXIT_NODE) -> tuple[TorExitNode, bool]:
        """
        Get an existing Tor exit node entry or create a new one.

        Args:
            ip_address: IP address of the Tor exit node.
            reason: Reason/description (default: "tor exit").

        Returns:
            Tuple of (TorExitNode object, created_flag) where created_flag is True if new.
        """
        node, created = TorExitNode.objects.get_or_create(ip_address=ip_address, defaults={"reason": reason})
        return node, created
