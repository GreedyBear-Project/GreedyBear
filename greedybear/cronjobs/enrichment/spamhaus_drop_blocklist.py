from greedybear.cronjobs.enrichment.base_enrichment import BaseEnrichmentJob
from greedybear.cronjobs.repositories import FireHolRepository


class SpamhausDropBlocklistCron(BaseEnrichmentJob):
    """
    Tag IOCs that appear on the stored Spamhaus DROP list.

    Reads only the Spamhaus DROP rows that SpamhausDropCron stores in the
    FireHolList table, so it makes no network calls. FireHol rows in the
    same table have their own job, FireHolBlocklistCron.
    """

    SOURCE_NAME = "spamhaus_drop"
    WRITE_METHOD = "replace"

    def __init__(self, firehol_repo=None, tag_repo=None):
        """
        Initialize the job with repository dependencies.

        Args:
            firehol_repo: Optional FireHolRepository instance for testing.
            tag_repo: Optional TagRepository instance for testing.
        """
        super().__init__(tag_repo=tag_repo)
        self.firehol_repo = firehol_repo if firehol_repo is not None else FireHolRepository()

    def run(self) -> None:
        """
        Match every stored Spamhaus DROP entry against known IOCs and write tags.

        Exact IPs are matched by name. CIDR ranges are matched in the
        database, since a membership test cannot use a name lookup.
        """

        # No Spamhaus rows means the download failed. Rewriting now would
        # delete all existing tags and put nothing back, so keep them.
        if not self.firehol_repo.has_entries(self.SOURCE_NAME):
            self.log.warning("No Spamhaus DROP entries stored, keeping existing tags")
            return

        entries_by_ip = self.firehol_repo.get_entries_by_ip(self.SOURCE_NAME)
        self.log.info(f"Matching {len(entries_by_ip)} exact Spamhaus DROP IPs against known IOCs")

        matching_iocs = self._match_iocs(entries_by_ip)
        tag_entries = [self._build_tag_entry(ioc_id) for ioc_id, _ in matching_iocs]

        cidr_matches = self.firehol_repo.get_cidr_matches(self.SOURCE_NAME)
        self.log.info(f"Found {len(cidr_matches)} IOCs inside stored Spamhaus DROP ranges")
        tag_entries += [self._build_tag_entry(ioc_id) for ioc_id, _ in cidr_matches]

        created_count = self._write_tags(tag_entries)
        self.log.info(f"{self.SOURCE_NAME} enrichment completed, created {created_count} tags.")

    def _build_tag_entry(self, ioc_id) -> dict:
        """
        Build the tag entry for one IOC on the Spamhaus DROP list.

        Args:
            ioc_id: ID of the matched IOC.

        Returns:
            Dict with keys: ioc_id, key, value.
        """
        return {"ioc_id": ioc_id, "key": "blocklist", "value": self.SOURCE_NAME}
