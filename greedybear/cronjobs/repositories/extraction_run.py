import logging
from datetime import datetime

from django.db.models import Max

from greedybear.models import ExtractionRun, ExtractionRunStatus


class ExtractionRunRepository:
    """
    Repository for the run history of windowed extraction jobs.

    The latest window_end of a job is its watermark, the point from which
    the next run of that job continues.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_watermark(self, job_name: str) -> datetime | None:
        """
        Return the point up to which a job has covered its data.

        Args:
            job_name: Name of the job.

        Returns:
            The latest window_end recorded for this job, or None if it never ran.
        """
        return ExtractionRun.objects.filter(job_name=job_name).aggregate(watermark=Max("window_end"))["watermark"]

    def start_run(self, job_name: str, window_start: datetime) -> ExtractionRun:
        """
        Record the start of a run that has not covered any data yet.

        Args:
            job_name: Name of the job.
            window_start: Start of the time window the run is about to process.

        Returns:
            The new ExtractionRun.
        """
        return ExtractionRun.objects.create(
            job_name=job_name,
            window_start=window_start,
            window_end=window_start,
        )

    def advance(self, run: ExtractionRun, window_end: datetime, ioc_count: int = 0) -> None:
        """
        Move the run's window_end past a processed chunk.

        Args:
            run: The run to update.
            window_end: End of the chunk that was processed.
            ioc_count: Number of IOC records the chunk produced.
        """
        run.window_end = window_end
        run.ioc_count += ioc_count
        run.save(update_fields=["window_end", "ioc_count"])

    def skip(self, run: ExtractionRun, window_end: datetime, error: str) -> None:
        """
        Move the run's window_end past a chunk that failed permanently.

        Args:
            run: The run to update.
            window_end: End of the chunk that failed.
            error: Description of the failure.
        """
        run.window_end = window_end
        run.status = ExtractionRunStatus.FAILED_PERMANENT
        run.last_error = error
        run.save(update_fields=["window_end", "status", "last_error"])

    def finish(self, run: ExtractionRun, error: str | None = None, retryable: bool = False) -> None:
        """
        Mark the run as finished.

        A run that skipped a chunk stays FAILED_PERMANENT even if every later
        chunk succeeded, so the skipped window remains visible.

        Args:
            run: The run to finish.
            error: Description of the failure that ended the run, if any.
            retryable: Whether that failure is worth retrying.
        """
        if error is not None:
            run.status = ExtractionRunStatus.FAILED_RETRYABLE if retryable else ExtractionRunStatus.FAILED_PERMANENT
            run.last_error = error
        elif run.status == ExtractionRunStatus.RUNNING:
            run.status = ExtractionRunStatus.SUCCESS
        run.finished_at = datetime.now()
        run.save(update_fields=["status", "last_error", "finished_at"])

    def delete_old_runs(self, expiration_date: datetime) -> int:
        """
        Delete runs created before the given date.

        The latest run of every job is always kept, since it holds that job's watermark.

        Args:
            expiration_date: Runs created before this date are deleted.

        Returns:
            Number of deleted runs.
        """
        # order_by() clears the default ordering, which would otherwise break distinct()
        job_names = ExtractionRun.objects.order_by().values_list("job_name", flat=True).distinct()
        latest_run_ids = [ExtractionRun.objects.filter(job_name=job_name).latest("window_end").pk for job_name in job_names]
        deleted_count, _ = ExtractionRun.objects.filter(created_at__lt=expiration_date).exclude(pk__in=latest_run_ids).delete()
        return deleted_count
