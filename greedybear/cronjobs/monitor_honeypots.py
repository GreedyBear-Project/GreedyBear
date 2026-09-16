# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import ElasticRepository, IocRepository


class MonitorHoneypots(Cronjob):
    """Monitor active honeypots for recent log activity."""

    def __init__(
        self,
        ioc_repo: IocRepository | None = None,
        elastic_repo: ElasticRepository | None = None,
        minutes_back: int = 60,
    ):
        """Initialize the monitoring.

        Args:
            ioc_repo: Repository for accessing known honeypots.
            elastic_repo: Repository for querying Elasticsearch logs.
            minutes_back: Time window in minutes to check for activity.
        """
        super().__init__()
        self.ioc_repo = ioc_repo or IocRepository()
        self.elastic_repo = elastic_repo or ElasticRepository()
        self.minutes_back = minutes_back

    def run(self):
        """Check all active honeypots for recent log activity."""
        for honeypot in self.ioc_repo.get_active_honeypots():
            honeypot_name = honeypot.name
            self.log.info(f"checking if logs from the honeypot {honeypot} are available")
            if self.elastic_repo.has_honeypot_been_hit(self.minutes_back, honeypot_name):
                self.log.info(f"logs available for {honeypot}")
                continue
            self.log.warning(f"no logs available for {honeypot} - something could be wrong with T-Pot")
