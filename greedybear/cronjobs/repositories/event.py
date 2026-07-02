import logging

from greedybear.models import EventStatus, RawEvent


class EventRepository:
    """
    Repository for data access to RawEvent and EventStatus entries.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def delete_old_raw_events(self, expiration_date) -> int:
        """
        Delete RawEvent entries older than the specified date.
        """
        deleted_count, _ = RawEvent.objects.filter(created_at__lt=expiration_date).delete()
        return deleted_count

    def delete_old_event_statuses(self, expiration_date) -> int:
        """
        Delete EventStatus entries older than the specified date.
        """
        deleted_count, _ = EventStatus.objects.filter(created_at__lt=expiration_date).delete()
        return deleted_count
