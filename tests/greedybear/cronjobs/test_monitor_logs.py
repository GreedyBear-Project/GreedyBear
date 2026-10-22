from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.conf import settings

from greedybear.cronjobs.monitor_logs import MonitorLogs
from tests import CustomTestCase


class MonitorLogsTestCase(CustomTestCase):
    @patch("greedybear.cronjobs.monitor_logs.send_ntfy_message")
    @patch("greedybear.cronjobs.monitor_logs.send_slack_message")
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    def test_run_all_recent_logs(self, mock_stat, mock_exists, mock_slack, mock_ntfy):
        # Setup mock responses
        mock_exists.return_value = True

        # Simulate all recent activity
        recent_time = datetime.now().timestamp()
        mock_stat.return_value = MagicMock(st_mtime=recent_time)

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        self.assertEqual(mock_slack.call_count, 4)
        self.assertEqual(mock_ntfy.call_count, 4)

    @patch("greedybear.cronjobs.monitor_logs.send_ntfy_message")
    @patch("greedybear.cronjobs.monitor_logs.send_slack_message")
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    def test_run_some_recent_logs(self, mock_stat, mock_exists, mock_slack, mock_ntfy):
        # Setup mock responses
        mock_exists.return_value = True

        # Simulate all recent activity
        recent_time = datetime.now().timestamp()
        old_time = (datetime.now() - timedelta(hours=2)).timestamp()

        mock_stat.side_effect = [
            MagicMock(st_mtime=recent_time),  # greedybear
            MagicMock(st_mtime=old_time),  # api
            MagicMock(st_mtime=old_time),  # django
            MagicMock(st_mtime=old_time),  # django_q
        ]

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_slack.assert_called_once_with("found errors in log file greedybear_errors.log")
        self.assertEqual(mock_ntfy.call_count, 1)

    @patch("greedybear.cronjobs.monitor_logs.send_ntfy_message")
    @patch("greedybear.cronjobs.monitor_logs.send_slack_message")
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    @patch("greedybear.cronjobs.monitor_logs.Path.stat")
    def test_run_no_recent_logs(self, mock_stat, mock_exists, mock_slack, mock_ntfy):
        # Setup mock responses
        mock_exists.return_value = True

        # Simulate all recent activity
        old_time = (datetime.now() - timedelta(hours=3)).timestamp()
        mock_stat.return_value = MagicMock(st_mtime=old_time)

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_slack.assert_not_called()
        mock_ntfy.assert_not_called()

    @patch("greedybear.cronjobs.monitor_logs.send_ntfy_message")
    @patch("greedybear.cronjobs.monitor_logs.send_slack_message")
    @patch("greedybear.cronjobs.monitor_logs.Path.exists")
    def test_run_no_file(self, mock_exists, mock_slack, mock_ntfy):
        # Setup mock responses
        mock_exists.return_value = False

        # Run the cronjob
        cronjob = MonitorLogs()
        cronjob.execute()

        mock_slack.assert_not_called()
        mock_ntfy.assert_not_called()

    def test_init_default_log_directory(self):
        cronjob = MonitorLogs()
        self.assertEqual(cronjob.log_directory, Path(settings.DJANGO_LOG_DIRECTORY))
