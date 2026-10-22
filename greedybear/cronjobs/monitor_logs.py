# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from datetime import datetime, timedelta
from pathlib import Path

from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.ntfy import send_ntfy_message
from greedybear.slack import send_slack_message


class MonitorLogs(Cronjob):
    """Monitor error log files for recent activity indicating errors."""

    def __init__(
        self,
        log_directory: str | None = None,
        check_window_minutes: int = 60,
    ):
        """Initialize the log monitoring.

        Args:
            log_directory: Directory containing error log files. Defaults to settings.DJANGO_LOG_DIRECTORY.
            check_window_minutes: Time window in minutes to check for log modifications.
        """
        super().__init__()
        if log_directory is None:
            log_directory = getattr(settings, "DJANGO_LOG_DIRECTORY", "/var/log/greedybear/django/")
        self.log_directory = Path(log_directory)
        self.check_window_minutes = check_window_minutes
        self.logs_to_monitor = ["greedybear", "api", "django", "django_q"]

    def run(self):
        """Check error logs for recent modifications and alert via Slack and ntfy."""
        cutoff_time = datetime.now() - timedelta(minutes=self.check_window_minutes)
        self.log.info(f"checking {len(self.logs_to_monitor)} error logs for activity since {cutoff_time}")

        for log_name in self.logs_to_monitor:
            log_file = f"{log_name}_errors.log"
            log_path = self.log_directory / log_file

            if not log_path.exists():
                self.log.warning(f"log file not found: {log_path}")
                continue

            self.log.info(f"checking if the log {log_file} was populated in the last hour")
            last_modified = datetime.fromtimestamp(log_path.stat().st_mtime)
            self.log.info(f"file {log_file} was modified at {last_modified}")

            if last_modified > cutoff_time:
                message = f"found errors in log file {log_file}"
                self.log.warning(message)
                send_slack_message(message)
                message = f"**⚠️ GreedyBear Error**\n\nErrors detected in `{log_file}`"
                send_ntfy_message(message)
            else:
                self.log.debug(f"no recent activity in {log_file}")
