import logging

from greedybear.models import APISource


class APISourceRepository:
    """Repository to handle APISource data modifications."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def reset_invalid_counts(self) -> int:
        """
        Resets invalid_event_count to 0 for all records where it is greater than 0.
        Returns the number of updated records.
        """
        return APISource.objects.filter(invalid_event_count__gt=0).update(invalid_event_count=0)
