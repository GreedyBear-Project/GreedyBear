from datetime import datetime, timedelta

from greedybear.cronjobs.repositories import ExtractionRunRepository
from greedybear.models import ExtractionJobName, ExtractionRun, ExtractionRunStatus

from . import CustomTestCase


class TestExtractionRunRepository(CustomTestCase):
    def setUp(self):
        self.repo = ExtractionRunRepository()

    def _create_run(self, window_end, job_name=ExtractionJobName.EXTRACTION, created_at=None):
        run = ExtractionRun.objects.create(job_name=job_name, window_start=window_end - timedelta(minutes=10), window_end=window_end)
        if created_at is not None:
            # created_at is auto_now_add, so it can only be set after creation
            ExtractionRun.objects.filter(pk=run.pk).update(created_at=created_at)
        return run

    def test_get_watermark_without_runs(self):
        self.assertIsNone(self.repo.get_watermark(ExtractionJobName.EXTRACTION))

    def test_get_watermark_returns_latest_window_end_of_job(self):
        self._create_run(datetime(2025, 1, 1, 10, 0))
        self._create_run(datetime(2025, 1, 1, 12, 0))
        self._create_run(datetime(2025, 1, 1, 11, 0))
        self._create_run(datetime(2025, 1, 1, 13, 0), job_name=ExtractionJobName.PAYLOAD_EXTRACTION)

        self.assertEqual(self.repo.get_watermark(ExtractionJobName.EXTRACTION), datetime(2025, 1, 1, 12, 0))
        self.assertEqual(self.repo.get_watermark(ExtractionJobName.PAYLOAD_EXTRACTION), datetime(2025, 1, 1, 13, 0))

    def test_start_run_covers_nothing_yet(self):
        run = self.repo.start_run(ExtractionJobName.EXTRACTION, datetime(2025, 1, 1, 10, 0))

        run.refresh_from_db()
        self.assertEqual(run.window_start, datetime(2025, 1, 1, 10, 0))
        self.assertEqual(run.window_end, datetime(2025, 1, 1, 10, 0))
        self.assertEqual(run.status, ExtractionRunStatus.RUNNING)
        self.assertEqual(self.repo.get_watermark(ExtractionJobName.EXTRACTION), datetime(2025, 1, 1, 10, 0))

    def test_advance_moves_window_end_and_counts_iocs(self):
        run = self.repo.start_run(ExtractionJobName.EXTRACTION, datetime(2025, 1, 1, 10, 0))

        self.repo.advance(run, datetime(2025, 1, 1, 10, 10), 3)
        self.repo.advance(run, datetime(2025, 1, 1, 10, 20), 4)

        run.refresh_from_db()
        self.assertEqual(run.window_end, datetime(2025, 1, 1, 10, 20))
        self.assertEqual(run.ioc_count, 7)

    def test_finish_without_error_marks_success(self):
        run = self.repo.start_run(ExtractionJobName.EXTRACTION, datetime(2025, 1, 1, 10, 0))

        self.repo.finish(run)

        run.refresh_from_db()
        self.assertEqual(run.status, ExtractionRunStatus.SUCCESS)
        self.assertIsNotNone(run.finished_at)

    def test_finish_with_retryable_error(self):
        run = self.repo.start_run(ExtractionJobName.EXTRACTION, datetime(2025, 1, 1, 10, 0))

        self.repo.finish(run, error="elastic is down", retryable=True)

        run.refresh_from_db()
        self.assertEqual(run.status, ExtractionRunStatus.FAILED_RETRYABLE)
        self.assertEqual(run.last_error, "elastic is down")

    def test_skipped_chunk_keeps_run_failed_after_finish(self):
        """A run that skipped a chunk must not look successful, even if all later chunks succeeded."""
        run = self.repo.start_run(ExtractionJobName.EXTRACTION, datetime(2025, 1, 1, 10, 0))

        self.repo.skip(run, datetime(2025, 1, 1, 10, 10), "corrupted data")
        self.repo.advance(run, datetime(2025, 1, 1, 10, 20), 2)
        self.repo.finish(run)

        run.refresh_from_db()
        self.assertEqual(run.status, ExtractionRunStatus.FAILED_PERMANENT)
        self.assertEqual(run.last_error, "corrupted data")
        self.assertEqual(run.window_end, datetime(2025, 1, 1, 10, 20))
        self.assertIsNotNone(run.finished_at)

    def test_delete_old_runs(self):
        now = datetime.now()
        old = self._create_run(datetime(2025, 1, 1, 10, 0), created_at=now - timedelta(days=40))
        recent = self._create_run(datetime(2025, 1, 1, 11, 0), created_at=now - timedelta(days=1))

        deleted = self.repo.delete_old_runs(now - timedelta(days=30))

        self.assertEqual(deleted, 1)
        self.assertFalse(ExtractionRun.objects.filter(pk=old.pk).exists())
        self.assertTrue(ExtractionRun.objects.filter(pk=recent.pk).exists())

    def test_delete_old_runs_keeps_watermark_of_every_job(self):
        """The latest run of a job holds its watermark and must survive, however old it is."""
        now = datetime.now()
        self._create_run(datetime(2025, 1, 1, 10, 0), created_at=now - timedelta(days=50))
        latest_extraction = self._create_run(datetime(2025, 1, 1, 11, 0), created_at=now - timedelta(days=40))
        latest_payloads = self._create_run(datetime(2025, 1, 1, 9, 0), job_name=ExtractionJobName.PAYLOAD_EXTRACTION, created_at=now - timedelta(days=40))

        deleted = self.repo.delete_old_runs(now - timedelta(days=30))

        self.assertEqual(deleted, 1)
        self.assertEqual(set(ExtractionRun.objects.values_list("pk", flat=True)), {latest_extraction.pk, latest_payloads.pk})
        self.assertEqual(self.repo.get_watermark(ExtractionJobName.EXTRACTION), datetime(2025, 1, 1, 11, 0))
        self.assertEqual(self.repo.get_watermark(ExtractionJobName.PAYLOAD_EXTRACTION), datetime(2025, 1, 1, 9, 0))

    def test_delete_old_runs_without_runs(self):
        self.assertEqual(self.repo.delete_old_runs(datetime.now()), 0)
