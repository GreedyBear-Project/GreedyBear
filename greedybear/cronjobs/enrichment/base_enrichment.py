from abc import ABC, abstractmethod

from greedybear.cache import invalidate_ioc_cache
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC


class BaseEnrichmentJob(Cronjob, ABC):
    """
    Shared base for enrichment cronjobs that write Tag records.
    """

    WRITE_METHOD = "replace"  # default, matches majority of sources

    @property
    @abstractmethod
    def SOURCE_NAME(self) -> str:  # noqa: N802
        """The source name used when writing/matching Tag records."""

    def __init__(self, tag_repo=None):
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()

    def _match_iocs(self, ip_dict):
        """
        Find the IOCs whose name matches one of the given IP addresses.

        Args:
            ip_dict: Dict keyed by IP address.

        Returns:
            QuerySet of (ioc_id, name) tuples.
        """
        return IOC.objects.filter(name__in=ip_dict.keys()).values_list("id", "name")

    def _write_tags(self, tag_entries):
        if self.WRITE_METHOD == "replace":
            count = self.tag_repo.replace_tags_for_source(self.SOURCE_NAME, tag_entries)
        elif self.WRITE_METHOD == "add":
            count = self.tag_repo.add_tags(self.SOURCE_NAME, tag_entries)
        else:
            raise ValueError(f"Unknown WRITE_METHOD: {self.WRITE_METHOD!r}")
        invalidate_ioc_cache()
        return count
