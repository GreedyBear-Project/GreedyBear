import logging

from greedybear.models import Statistics


class StatisticsRepository:
    """
    Repository for data access to Statistics records.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def delete_old_statistics(self, cutoff_date) -> int:
        """
        Delete Statistics records older than the specified cutoff date.

        Args:
            cutoff_date: DateTime threshold - statistics with request_date before this will be deleted.

        Returns:
            Number of Statistics objects deleted.
        """
        deleted_count, _ = Statistics.objects.filter(request_date__lte=cutoff_date).delete()
        return deleted_count
