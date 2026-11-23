"""Tests for the setup_schedules management command."""

from datetime import timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule
from django_q.scheduler import scheduler


class TestSetupSchedules(TestCase):
    """Test setup_schedules command with various EXTRACTION_INTERVAL values."""

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=10)
    def test_extraction_interval_10(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=10."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        # Check extraction schedule uses CRON type with interval 10
        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["schedule_type"], Schedule.CRON)
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/10 * * * *")

        trending_cleanup_call = next(c for c in calls if c[1]["name"] == "clean_up_trending_buckets")
        self.assertEqual(trending_cleanup_call[1]["defaults"]["schedule_type"], Schedule.CRON)
        self.assertEqual(trending_cleanup_call[1]["defaults"]["cron"], "12 * * * *")

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=60)
    def test_extraction_interval_60_clamps_minute(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=60 (minute calculation: 60/3*2=40)."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        # Check extraction schedule
        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/60 * * * *")

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=5)
    def test_extraction_interval_5(self, mock_schedule):
        """Test schedules with EXTRACTION_INTERVAL=5."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        calls = mock_schedule.objects.update_or_create.call_args_list
        extract_call = next(c for c in calls if c[1]["name"] == "extract_all")
        self.assertEqual(extract_call[1]["defaults"]["cron"], "*/5 * * * *")

    @patch("greedybear.cronjobs.schedules.Schedule")
    @override_settings(EXTRACTION_INTERVAL=10, SECRET_KEY="test-secret")
    def test_external_weekly_jobs_cron_are_deterministic_and_outside_local_window(self, mock_schedule):
        """External weekly jobs run on Sunday at deterministic times outside 00:00-02:00."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")
        first_calls = mock_schedule.objects.update_or_create.call_args_list

        mock_schedule.objects.update_or_create.reset_mock()
        call_command("setup_schedules")
        second_calls = mock_schedule.objects.update_or_create.call_args_list

        def get_cron(calls, name):
            return next(c for c in calls if c[1]["name"] == name)[1]["defaults"]["cron"]

        for job_name in (
            "get_mass_scanners",
            "get_whatsmyip",
            "extract_firehol_lists",
            "get_tor_exit_nodes",
            "enrich_threatfox",
            "enrich_abuseipdb",
        ):
            first_cron = get_cron(first_calls, job_name)
            second_cron = get_cron(second_calls, job_name)

            self.assertEqual(first_cron, second_cron)

            minute_str, hour_str, day_of_month, month, day_of_week = first_cron.split()
            hour = int(hour_str)
            minute = int(minute_str)

            self.assertGreaterEqual(hour, 2)
            self.assertLessEqual(hour, 23)
            self.assertGreaterEqual(minute, 0)
            self.assertLessEqual(minute, 59)
            self.assertEqual(day_of_month, "*")
            self.assertEqual(month, "*")
            self.assertEqual(day_of_week, "0")

    @patch("greedybear.cronjobs.schedules.Schedule")
    def test_only_extraction_failures_are_acknowledged(self, mock_schedule):
        """Only extract_all carries ack_failure, all other schedules have no kwargs."""
        mock_schedule.CRON = Schedule.CRON
        mock_schedule.objects.update_or_create = MagicMock()
        mock_schedule.objects.exclude = MagicMock(return_value=MagicMock())

        call_command("setup_schedules")

        for call in mock_schedule.objects.update_or_create.call_args_list:
            kwargs = call[1]["defaults"]["kwargs"]
            if call[1]["name"] == "extract_all":
                self.assertEqual(kwargs, "{'q_options': {'ack_failure': True}}")
            else:
                self.assertIsNone(kwargs)

    @patch("django_q.scheduler.close_old_django_connections")
    @patch("django_q.scheduler.async_task")
    def test_scheduler_queues_extraction_with_ack_failure(self, mock_async_task, _mock_close_connections):
        """The Django Q scheduler queues extract_all with ack_failure and no extra function arguments."""
        mock_async_task.return_value = uuid4().hex
        call_command("setup_schedules")
        Schedule.objects.filter(name="extract_all").update(next_run=timezone.now() - timedelta(minutes=1))
        Schedule.objects.exclude(name="extract_all").update(next_run=timezone.now() + timedelta(days=1))

        scheduler(broker=MagicMock())

        mock_async_task.assert_called_once()
        args, kwargs = mock_async_task.call_args
        self.assertEqual(args, ("greedybear.tasks.extract_all",))
        self.assertEqual(set(kwargs), {"q_options"})
        self.assertTrue(kwargs["q_options"]["ack_failure"])

    def test_existing_extraction_schedule_gets_ack_failure(self):
        """Running setup_schedules again updates an extract_all schedule created without kwargs."""
        Schedule.objects.create(
            name="extract_all",
            func="greedybear.tasks.extract_all",
            schedule_type=Schedule.CRON,
            cron="*/10 * * * *",
        )

        call_command("setup_schedules")

        self.assertEqual(Schedule.objects.get(name="extract_all").kwargs, "{'q_options': {'ack_failure': True}}")
        self.assertIsNone(Schedule.objects.get(name="monitor_honeypots").kwargs)

    def test_orphan_schedules_are_deleted(self):
        """Test that orphaned schedules not in active_schedules list are deleted."""
        # Create an orphan schedule that's not in the active_schedules list
        Schedule.objects.create(
            name="old_deprecated_task",
            func="greedybear.tasks.deprecated_function",
            schedule_type=Schedule.CRON,
            cron="0 0 * * *",
        )

        # Create a valid schedule
        Schedule.objects.create(
            name="extract_all",
            func="greedybear.tasks.extract_all",
            schedule_type=Schedule.CRON,
            cron="*/10 * * * *",
        )

        # Run setup_schedules
        call_command("setup_schedules")

        # Orphan schedule should be deleted
        self.assertFalse(Schedule.objects.filter(name="old_deprecated_task").exists())

        # Valid schedule should still exist
        self.assertTrue(Schedule.objects.filter(name="extract_all").exists())
