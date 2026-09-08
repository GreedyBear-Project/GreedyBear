from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository


class BaseEnrichmentCron(Cronjob):
    """
    Shared base for enrichment cronjobs that write Tag records.

    Handles the common tag_repo initialization used by ThreatFox,
    AbuseIPDB, reverse DNS, and credential reuse jobs. Subclasses
    must still implement run(), inherited as abstract from Cronjob.
    This avoids repetitive code.
    """

    def __init__(self, tag_repo=None):
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()
