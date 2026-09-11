from abc import ABC

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository


class BaseEnrichmentJob(Cronjob, ABC):
    """
    Shared base for enrichment cronjobs that write Tag records.
    """

    WRITE_METHOD = "replace"  # default, matches majority of sources

    def __init__(self, tag_repo=None):
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()

    def _write_tags(self, tag_entries):
        if self.WRITE_METHOD == "replace":
            return self.tag_repo.replace_tags_for_source(self.SOURCE_NAME, tag_entries)
        return self.tag_repo.add_tags(self.SOURCE_NAME, tag_entries)

    def _should_skip(self) -> bool:
        return False
