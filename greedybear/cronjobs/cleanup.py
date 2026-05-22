from datetime import datetime, timedelta

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import (
    CowrieSessionRepository,
    IocRepository,
    StatisticsRepository,
)
from greedybear.settings import (
    COMMAND_SEQUENCE_RETENTION,
    COWRIE_SESSION_RETENTION,
    IOC_RETENTION,
    STATISTICS_RETENTION,
)


class CleanUp(Cronjob):
    """
    A scheduled job that performs database cleanup operations by removing outdated records.

    This job handles deletion of old IOCs, CowrieSessions, CommandSequences, and Statistics
    based on retention periods defined in the application settings. All deletion operations
    are logged with counts of removed objects.
    """

    def __init__(self, ioc_repo=None, cowrie_repo=None, stats_repo=None):
        """
        Initialize the cleanup job with repository dependencies.

        Args:
            ioc_repo: Optional IocRepository instance for testing.
            cowrie_repo: Optional CowrieSessionRepository instance for testing.
            stats_repo: Optional StatisticsRepository instance for testing.
        """
        super().__init__()
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()
        self.cowrie_repo = cowrie_repo if cowrie_repo is not None else CowrieSessionRepository()
        self.stats_repo = stats_repo if stats_repo is not None else StatisticsRepository()

    def run(self) -> None:
        """
        Execute the database cleanup process.

        This method:
        1. Calculates expiration dates for different record types
        2. Deletes IOCs older than IOC_RETENTION days
        3. Deletes incomplete Cowrie sessions (those without start time)
        4. Deletes Cowrie sessions without login attempts older than 30 days
        5. Deletes all Cowrie sessions older than COWRIE_SESSION_RETENTION days
        6. Deletes all command sequences older than COMMAND_SEQUENCE_RETENTION days
        7. Deletes Statistics records older than STATISTICS_RETENTION days

        Each deletion operation is logged with the number of affected records.
        """
        ioc_expiration_date = datetime.now() - timedelta(days=IOC_RETENTION)
        command_expiration_date = datetime.now() - timedelta(days=COMMAND_SEQUENCE_RETENTION)
        session_expiration_date = datetime.now() - timedelta(days=30)
        session_with_login_expiration_date = datetime.now() - timedelta(days=COWRIE_SESSION_RETENTION)
        statistics_expiration_date = datetime.now() - timedelta(days=STATISTICS_RETENTION)

        self.log.info(f"deleting all IOC older then {IOC_RETENTION} days")
        n = self.ioc_repo.delete_old_iocs(ioc_expiration_date)
        self.log.info(f"{n} objects deleted")

        self.log.info(f"deleting all command sequences older then {COMMAND_SEQUENCE_RETENTION} days")
        n = self.cowrie_repo.delete_old_command_sequences(command_expiration_date)
        self.log.info(f"{n} objects deleted")

        self.log.info("deleting all Cowrie sessions without start time (incomplete extractions)")
        n = self.cowrie_repo.delete_incomplete_sessions()
        self.log.info(f"{n} objects deleted")

        self.log.info("deleting all Cowrie sessions without login attempts older then 30 days")
        n = self.cowrie_repo.delete_sessions_without_login(session_expiration_date)
        self.log.info(f"{n} objects deleted")

        self.log.info(f"deleting all Cowrie sessions without associated commands older then {COWRIE_SESSION_RETENTION} days")
        n = self.cowrie_repo.delete_sessions_without_commands(session_with_login_expiration_date)
        self.log.info(f"{n} objects deleted")

        self.log.info(f"deleting all Statistics older then {STATISTICS_RETENTION} days")
        n = self.stats_repo.delete_old_statistics(statistics_expiration_date)
        self.log.info(f"{n} objects deleted")
