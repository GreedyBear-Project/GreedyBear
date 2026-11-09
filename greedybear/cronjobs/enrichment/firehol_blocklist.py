from greedybear.cronjobs.enrichment.blocklist_enrichment import BlocklistEnrichmentJob
from greedybear.cronjobs.firehol import SOURCES


class FireHolBlocklistCron(BlocklistEnrichmentJob):
    """
    Tag IOCs that appear on a stored Firehol blocklist.

    Reads only the FireHol rows of the FireHolList table that FireHolCron
    fills. It runs on its own, more frequent schedule, so an IOC
    first seen after a download still gets tagged the same day.
    """

    SOURCE_NAME = "firehol"
    BLOCKLIST_SOURCES = SOURCES
