from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from greedybear.cronjobs.cleanup import CleanUp
from greedybear.cronjobs.repositories import (
    CowrieSessionRepository,
    IocRepository,
    StatisticsRepository,
)
from tests import CustomTestCase


class TestCleanUp(CustomTestCase):
    def test_init_uses_default_repos(self):
        """Test that the CleanUp job initializes with default repositories if none are provided."""
        cleanup_job = CleanUp()
        self.assertIsNotNone(cleanup_job.ioc_repo)
        self.assertIsNotNone(cleanup_job.cowrie_repo)
        self.assertIsNotNone(cleanup_job.stats_repo)
        self.assertIsInstance(cleanup_job.ioc_repo, IocRepository)
        self.assertIsInstance(cleanup_job.cowrie_repo, CowrieSessionRepository)
        self.assertIsInstance(cleanup_job.stats_repo, StatisticsRepository)

    @patch("greedybear.cronjobs.cleanup.IOC_RETENTION", 100)
    @patch("greedybear.cronjobs.cleanup.COMMAND_SEQUENCE_RETENTION", 90)
    @patch("greedybear.cronjobs.cleanup.COWRIE_SESSION_RETENTION", 80)
    @patch("greedybear.cronjobs.cleanup.STATISTICS_RETENTION", 700)
    def test_run_calls_repository_methods_with_correct_dates(self):
        """Test that run method calls repository deletion methods with correct retention dates."""
        # Create mock repositories
        ioc_repo = MagicMock()
        cowrie_repo = MagicMock()
        stats_repo = MagicMock()

        # Setup return values for logging purposes
        ioc_repo.delete_old_iocs.return_value = 10
        cowrie_repo.delete_old_command_sequences.return_value = 20
        cowrie_repo.delete_incomplete_sessions.return_value = 5
        cowrie_repo.delete_sessions_without_login.return_value = 15
        cowrie_repo.delete_sessions_without_commands.return_value = 8
        stats_repo.delete_old_statistics.return_value = 3

        # Initialize CleanUp with mocks
        cleanup_job = CleanUp(ioc_repo=ioc_repo, cowrie_repo=cowrie_repo, stats_repo=stats_repo)

        # Mock the logger to verify logging calls
        cleanup_job.log = MagicMock()

        # Execute the run method
        cleanup_job.run()

        # Verify interactions with IocRepository
        ioc_repo.delete_old_iocs.assert_called_once()
        expected_ioc_date = datetime.now() - timedelta(days=100)
        # Check that the date passed is approximately correct (within 1 second)
        args, _ = ioc_repo.delete_old_iocs.call_args
        actual_date = args[0]
        time_diff = abs((actual_date - expected_ioc_date).total_seconds())
        self.assertLess(time_diff, 1, f"Date difference ({time_diff}s) exceeds 1 second tolerance")

        # Verify interactions with CowrieSessionRepository

        # 1. delete_old_command_sequences
        cowrie_repo.delete_old_command_sequences.assert_called_once()
        expected_cmd_date = datetime.now() - timedelta(days=90)
        args, _ = cowrie_repo.delete_old_command_sequences.call_args
        actual_date = args[0]
        time_diff = abs((actual_date - expected_cmd_date).total_seconds())
        self.assertLess(time_diff, 1, f"Date difference ({time_diff}s) exceeds 1 second tolerance")

        # 2. delete_incomplete_sessions
        cowrie_repo.delete_incomplete_sessions.assert_called_once()

        # 3. delete_sessions_without_login
        cowrie_repo.delete_sessions_without_login.assert_called_once()
        expected_session_login_date = datetime.now() - timedelta(days=30)
        args, _ = cowrie_repo.delete_sessions_without_login.call_args
        actual_date = args[0]
        time_diff = abs((actual_date - expected_session_login_date).total_seconds())
        self.assertLess(time_diff, 1, f"Date difference ({time_diff}s) exceeds 1 second tolerance")

        # 4. delete_sessions_without_commands
        cowrie_repo.delete_sessions_without_commands.assert_called_once()
        expected_session_cmd_date = datetime.now() - timedelta(days=80)
        args, _ = cowrie_repo.delete_sessions_without_commands.call_args
        actual_date = args[0]
        time_diff = abs((actual_date - expected_session_cmd_date).total_seconds())
        self.assertLess(time_diff, 1, f"Date difference ({time_diff}s) exceeds 1 second tolerance")

        # Verify interactions with StatisticsRepository
        stats_repo.delete_old_statistics.assert_called_once()
        expected_stats_date = datetime.now() - timedelta(days=700)
        args, _ = stats_repo.delete_old_statistics.call_args
        actual_date = args[0]
        time_diff = abs((actual_date - expected_stats_date).total_seconds())
        self.assertLess(time_diff, 1, f"Date difference ({time_diff}s) exceeds 1 second tolerance")

        # Verify logging messages
        # We expect 6 pairs of logs (start + result)
        # 12 calls to info level
        self.assertEqual(cleanup_job.log.info.call_count, 12)

        # Check specific log messages to ensure counts are logged
        cleanup_job.log.info.assert_any_call("10 objects deleted")
        cleanup_job.log.info.assert_any_call("20 objects deleted")
        cleanup_job.log.info.assert_any_call("5 objects deleted")
        cleanup_job.log.info.assert_any_call("15 objects deleted")
        cleanup_job.log.info.assert_any_call("8 objects deleted")
        cleanup_job.log.info.assert_any_call("3 objects deleted")

    def test_run_handles_zero_deletions(self):
        """Test that run method handles cases where no objects are deleted."""
        ioc_repo = MagicMock()
        cowrie_repo = MagicMock()
        stats_repo = MagicMock()

        # Setup return values as 0
        ioc_repo.delete_old_iocs.return_value = 0
        cowrie_repo.delete_old_command_sequences.return_value = 0
        cowrie_repo.delete_incomplete_sessions.return_value = 0
        cowrie_repo.delete_sessions_without_login.return_value = 0
        cowrie_repo.delete_sessions_without_commands.return_value = 0
        stats_repo.delete_old_statistics.return_value = 0

        cleanup_job = CleanUp(ioc_repo=ioc_repo, cowrie_repo=cowrie_repo, stats_repo=stats_repo)
        cleanup_job.log = MagicMock()

        cleanup_job.run()

        # Verify invocations still happen
        ioc_repo.delete_old_iocs.assert_called_once()
        cowrie_repo.delete_old_command_sequences.assert_called_once()
        cowrie_repo.delete_incomplete_sessions.assert_called_once()
        cowrie_repo.delete_sessions_without_login.assert_called_once()
        cowrie_repo.delete_sessions_without_commands.assert_called_once()
        stats_repo.delete_old_statistics.assert_called_once()

        # Verify zero counts are logged
        cleanup_job.log.info.assert_any_call("0 objects deleted")
