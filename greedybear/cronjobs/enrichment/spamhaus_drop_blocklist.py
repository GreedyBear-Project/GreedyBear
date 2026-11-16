from greedybear.cronjobs.enrichment.blocklist_enrichment import BlocklistEnrichmentJob
from greedybear.cronjobs.spamhaus_drop import SOURCE_NAME as SPAMHAUS_DROP_SOURCE


class SpamhausDropBlocklistCron(BlocklistEnrichmentJob):
    """
    Tag IOCs that appear on the stored Spamhaus DROP list.

    Reads only the Spamhaus DROP rows that SpamhausDropCron stores in the
    FireHolList table.
    """

    SOURCE_NAME = SPAMHAUS_DROP_SOURCE
    BLOCKLIST_SOURCES = SPAMHAUS_DROP_SOURCE
