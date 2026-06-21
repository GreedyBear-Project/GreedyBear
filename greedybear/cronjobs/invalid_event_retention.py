from greedybear.cronjobs.base import Cronjob
from greedybear.models import APISource


class InvalidEventRetentionCron(Cronjob):
    """
    Reset APISource.invalid_event_count daily so temporary bursts of
    invalid requests do not permanently accumulate toward the lock threshold.
    """

    def run(self) -> None:
        updated = APISource.objects.filter(invalid_event_count__gt=0).update(invalid_event_count=0)

        self.log.info(f"Reset invalid_event_count to 0 for {updated} APISources")
