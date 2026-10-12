from greedybear.cronjobs.enrichment.base_enrichment import BaseEnrichmentJob
from greedybear.cronjobs.repositories import FireHolRepository


class FireHolBlocklistCron(BaseEnrichmentJob):
    """
    Tag IOCs that appear on a stored blocklist.

    Reads the FireHolList table that FireHolCron fills, so it makes no
    network calls. It runs on its own, more frequent schedule, so an IOC
    first seen after a download still gets tagged the same day.
    """

    SOURCE_NAME = "firehol"
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
        Match every stored blocklist entry against known IOCs and write tags.

        Exact IPs are matched by name. CIDR ranges are matched in the
        database, since a membership test cannot use a name lookup.
        """

        # An empty table means every download failed. Rewriting now would
        # delete all existing tags and put nothing back, so keep them.
        if not self.firehol_repo.has_entries():
            self.log.warning("No FireHol entries stored, keeping existing tags")
            return

        entries_by_ip = self.firehol_repo.get_entries_by_ip()
        self.log.info(f"Matching {len(entries_by_ip)} exact blocklist IPs against known IOCs")

        matching_iocs = self._match_iocs(entries_by_ip)
        tag_entries = self._build_tag_entries(matching_iocs, entries_by_ip)

        cidr_matches = self.firehol_repo.get_cidr_matches()
        self.log.info(f"Found {len(cidr_matches)} IOCs inside stored CIDR ranges")
        tag_entries += [{"ioc_id": ioc_id, "key": "blocklist", "value": source} for ioc_id, source in cidr_matches]

        created_count = self._write_tags(tag_entries)
        self.log.info(f"{self.SOURCE_NAME} enrichment completed, created {created_count} tags.")

    def _build_tag_entries(self, matching_iocs, entries_by_ip) -> list[dict]:
        """
        Turn matched IOCs into tag entries.

        Each blocklist an IOC appears on becomes one tag.

        Args:
            matching_iocs: List of (ioc_id, ip_address) tuples from _match_iocs.
            entries_by_ip: Dict mapping IP address to its list of sources.

        Returns:
            List of dicts with keys: ioc_id, key, value.
        """
        tag_entries = []
        for ioc_id, ioc_name in matching_iocs:
            tag_entries.extend({"ioc_id": ioc_id, "key": "blocklist", "value": source} for source in entries_by_ip[ioc_name])
        return tag_entries
