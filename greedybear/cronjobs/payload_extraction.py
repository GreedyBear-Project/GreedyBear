# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from datetime import datetime
from pathlib import Path

import requests
from django.conf import settings
from django.core.files.base import ContentFile

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.exceptions import PayloadServerError
from greedybear.cronjobs.http_client import HttpClient
from greedybear.cronjobs.repositories import ExtractionRunRepository, PayloadRepository
from greedybear.models import ExtractionJobName, HoneypotPayload
from greedybear.utils import get_catch_up_window, split_time_window


class PayloadExtractionJob(Cronjob):
    """
    Fetch new payloads from the tpot-payload-server, deduplicate them
    by SHA256 hash, and save them to the quarantine directory.

    This job:
    1. Queries the payload server's ``/api/v1/payloads/recent`` endpoint for
       metadata of files modified since the last run, one extraction interval
       at a time. If the server cannot be reached, the next run retries the
       same interval.
    2. Skips any payload whose SHA256 already has a downloaded file in the database.
    3. Checks quarantine disk usage against MAX_QUARANTINE_SIZE_GB before downloading.
    4. Downloads new payload files via ``/api/v1/payloads/download/{locator}``
       and saves them via QuarantineStorage.
    5. Records metadata-only rows for any payload left undownloaded once the
       quota is reached, so it is not lost with the extraction window.
    6. Links every payload it records, downloaded or not, to the Cowrie sessions
       and attacker IOCs that already transferred a file with the same SHA256.
    """

    # Timeout for the metadata listing request (seconds).
    METADATA_TIMEOUT = 30
    # Timeout for individual file download requests (seconds).
    DOWNLOAD_TIMEOUT = 120

    def __init__(self, payload_repo: PayloadRepository | None = None, run_repo: ExtractionRunRepository | None = None):
        super().__init__()
        self.payload_repo = payload_repo if payload_repo is not None else PayloadRepository()
        self.run_repo = run_repo if run_repo is not None else ExtractionRunRepository()

    def run(self) -> None:
        server_url = settings.TPOT_PAYLOAD_SERVER_URL
        if not server_url:
            self.log.info("TPOT_PAYLOAD_SERVER_URL not configured, skipping payload extraction.")
            return

        window_start, window_end = self._extraction_window()
        if window_start >= window_end:
            self.log.info(f"Nothing to extract, payloads up to {window_start} were already extracted.")
            return

        max_size_bytes = settings.MAX_QUARANTINE_SIZE_GB * (1024**3)
        run = self.run_repo.start_run(ExtractionJobName.PAYLOAD_EXTRACTION, window_start)
        downloaded = 0
        skipped_count = 0
        deferred_count = 0

        with HttpClient(default_timeout=self.METADATA_TIMEOUT) as client:
            for chunk_start, chunk_end in split_time_window(window_start, window_end, settings.EXTRACTION_INTERVAL):
                try:
                    payloads = self._fetch_metadata(client, server_url, chunk_start, chunk_end)
                    chunk_downloaded, chunk_skipped, chunk_deferred = self._store_payloads(client, server_url, payloads, max_size_bytes)
                except PayloadServerError as exc:
                    self.log.warning(f"Payloads of {chunk_start} - {chunk_end} could not be fetched, the next run will retry them.")
                    self.run_repo.finish(run, error=str(exc), retryable=True)
                    raise
                except Exception as exc:
                    self.log.exception(f"Payload extraction of {chunk_start} - {chunk_end} failed, skipping it.")
                    self.run_repo.skip(run, chunk_end, str(exc))
                    continue

                # Storing is idempotent per SHA256, so a chunk that stops halfway
                # can safely be processed again; no transaction is needed here.
                self.run_repo.advance(run, chunk_end, chunk_downloaded + chunk_deferred)
                downloaded += chunk_downloaded
                skipped_count += chunk_skipped
                deferred_count += chunk_deferred

        self.run_repo.finish(run)
        self.log.info(f"Payload extraction complete: {downloaded} downloaded, {skipped_count} skipped/failed, {deferred_count} stored as metadata only.")

    def _extraction_window(self) -> tuple[datetime, datetime]:
        """
        Calculate the time window for this run.

        The window continues from where the last run stopped, but reaches back
        at most INITIAL_EXTRACTION_TIMESPAN minutes. Without a previous run it
        covers the last extraction interval only, as before runs were recorded.

        Returns:
            The start and end of the time window. The window is empty if start >= end.
        """
        watermark = self.run_repo.get_watermark(ExtractionJobName.PAYLOAD_EXTRACTION)
        max_lookback = settings.INITIAL_EXTRACTION_TIMESPAN if watermark is not None else settings.EXTRACTION_INTERVAL
        return get_catch_up_window(
            reference_time=datetime.now(),
            watermark=watermark,
            max_lookback_minutes=max_lookback,
            extraction_interval=settings.EXTRACTION_INTERVAL,
        )

    def _store_payloads(self, client: HttpClient, server_url: str, payloads: list[dict], max_size_bytes: int) -> tuple[int, int, int]:
        """
        Download and store the new payloads of one time window.

        Args:
            client: HttpClient instance.
            server_url: Base URL of the payload server.
            payloads: Payload metadata dicts returned by the server.
            max_size_bytes: Quarantine size limit in bytes.

        Returns:
            tuple[int, int, int]: Number of downloaded, skipped/failed and metadata-only payloads.
        """
        if not payloads:
            self.log.info("No payloads returned from server.")
            return 0, 0, 0

        # Filter out already-known payloads by SHA256.
        new_payloads = self._deduplicate(payloads)
        if not new_payloads:
            self.log.info("All payloads already exist in the database.")
            return 0, 0, 0

        self.log.info(f"Found {len(new_payloads)} new payload(s) to download.")

        # Download and store each new payload.
        downloaded = 0
        skipped_count = 0
        deferred_count = 0
        for index, payload_meta in enumerate(new_payloads):
            # Check disk usage before each download.
            if self._quarantine_usage_bytes() >= max_size_bytes:
                self.log.error(f"Quarantine directory has reached the {settings.MAX_QUARANTINE_SIZE_GB} GB limit. Stopping downloads.")
                # Record what we did not get to. Every payload shows up in exactly
                # one /recent window, so dropping the rest of the batch here would
                # lose these files permanently.
                deferred_count = self._store_metadata_only(new_payloads[index:])
                break

            if self._download_and_store(client, server_url, payload_meta):
                downloaded += 1
            else:
                skipped_count += 1

        return downloaded, skipped_count, deferred_count

    def _build_auth_headers(self) -> dict:
        """
        Build the authentication headers for the payload server.

        Returns:
            dict: Headers dict with the API key, or empty dict if not configured.
        """
        api_key = settings.TPOT_PAYLOAD_SERVER_API_KEY
        if api_key:
            return {"X-API-Key": api_key}
        return {}

    def _fetch_metadata(self, client: HttpClient, server_url: str, window_start: datetime, window_end: datetime) -> list[dict]:
        """
        Fetch the list of payloads modified within a time window from the tpot-payload-server.

        Queries the ``/api/v1/payloads/recent`` endpoint.

        Args:
            client: HttpClient instance.
            server_url: Base URL of the payload server.
            window_start: Start of the time window.
            window_end: End of the time window.

        Returns:
            list[dict]: List of payload metadata dicts.

        Raises:
            PayloadServerError: If the server cannot be reached or answers with an error.
            ValueError: If the response is not valid JSON.
            TypeError: If the response is not a list of payloads.
        """
        url = f"{server_url.rstrip('/')}/api/v1/payloads/recent"
        params = {"start_ts": window_start.timestamp(), "end_ts": window_end.timestamp()}
        headers = self._build_auth_headers()

        try:
            response = client.get(url, params=params, headers=headers, verify=False)
        except requests.RequestException as exc:
            raise PayloadServerError(f"failed to fetch payload metadata from server: {exc}") from exc

        data = response.json()
        if not isinstance(data, list):
            raise TypeError("payload metadata response is not a list")
        return data

    def _deduplicate(self, payloads: list[dict]) -> list[dict]:
        """
        Filter out payloads whose SHA256 already has a downloaded file in the
        database, and remove duplicates within the response itself.

        A hash can already have a HoneypotPayload row without a file attached -
        a metadata-only stub created from a raw event before the file was
        available. Those hashes are treated as new so the file can still be
        downloaded.

        Args:
            payloads: List of payload metadata dicts (must contain 'sha256' key).

        Returns:
            list[dict]: Only the unique payloads not yet stored locally.
        """
        # HoneypotPayload is unique on Lower("sha256"), so compare case-insensitively
        # on both sides. Rows written before this normalization existed may still hold
        # a mixed-case hash; a case-sensitive lookup would miss them and let the insert
        # through to fail on the constraint instead.
        incoming_hashes = {p["sha256"].lower() for p in payloads if "sha256" in p}
        existing_hashes = self.payload_repo.get_downloaded_hashes(incoming_hashes)
        new_hashes = incoming_hashes - existing_hashes
        self.log.debug(f"Deduplication: {len(incoming_hashes)} incoming, {len(existing_hashes)} existing, {len(new_hashes)} new.")
        # Keep only the first occurrence of each sha256 to avoid IntegrityError.
        # Hashes are compared normalized, so entries differing only in case
        # collapse into one instead of colliding on the constraint.
        seen = set()
        unique = []
        for p in payloads:
            raw_sha = p.get("sha256")
            sha = raw_sha.lower() if raw_sha else None
            if sha in new_hashes and sha not in seen:
                seen.add(sha)
                unique.append(p)
        return unique

    def _quarantine_usage_bytes(self) -> int:
        """
        Return the total size of files in the quarantine directory in bytes.
        """
        quarantine_path = Path(settings.QUARANTINE_DIR)
        if not quarantine_path.is_dir():
            return 0
        return sum(f.stat().st_size for f in quarantine_path.iterdir() if f.is_file())

    def _store_metadata_only(self, payloads: list[dict]) -> int:
        """
        Persist metadata-only rows for payloads that were not downloaded.

        Called when the quarantine quota is exhausted mid-batch. The row keeps the
        locator, which is the only handle the file can be fetched with later, and
        leaves ``payload_file`` empty to mark the payload as not yet downloaded.

        Each row is linked to the Cowrie sessions and attacker IOCs that already
        transferred the same file, exactly as a downloaded payload would be. The
        hash is what the join runs on, so a row without a file still carries the
        attribution; the file only fills in later.

        Args:
            payloads: List of payload metadata dicts that were not downloaded.

        Returns:
            int: Number of payloads recorded.
        """
        stored = 0
        for payload_meta in payloads:
            # Lower-cased like in _deduplicate, so every writer agrees on the case.
            sha256 = payload_meta["sha256"].lower()
            locator = payload_meta.get("locator", "")

            if not locator:
                # Without a locator the file can never be fetched, so a row would
                # only shadow the hash without offering a way to recover it.
                self.log.warning(f"Payload {sha256[:12]}… has no locator, skipping.")
                continue

            payload = HoneypotPayload(
                sha256=sha256,
                md5=payload_meta.get("md5", ""),
                sha1=payload_meta.get("sha1", ""),
                mime_type=payload_meta.get("mime_type", ""),
                size=payload_meta.get("size"),
                locator=locator,
                mtime=payload_meta.get("mtime"),
            )
            payload_obj, _ = self.payload_repo.upsert_metadata_only_payload(payload)

            linked = self.payload_repo.link_sessions_to_payload(payload_obj)
            if linked:
                self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
            stored += 1

        if stored:
            self.log.info(f"Stored metadata for {stored} payload(s) that were not downloaded.")
        return stored

    def _download_and_store(self, client: HttpClient, server_url: str, payload_meta: dict) -> bool:
        """
        Download a single payload file, create its database record (or upgrade
        an existing hash-only stub with the real file), and link it to any
        Cowrie sessions that already transferred the same file.

        Args:
            client: HttpClient instance.
            server_url: Base URL of the payload server.
            payload_meta: Dict with at least 'sha256' and 'locator' keys.

        Returns:
            bool: True if download and storage succeeded, False otherwise.
        """
        # Lower-cased like in _deduplicate, so the stored row and the quarantine
        # filename always use the same case as every other writer.
        sha256 = payload_meta["sha256"].lower()
        locator = payload_meta.get("locator", "")

        if not locator:
            self.log.warning(f"Payload {sha256[:12]}… has no locator, skipping.")
            return False

        download_url = f"{server_url.rstrip('/')}/api/v1/payloads/download/{locator}"
        headers = self._build_auth_headers()

        try:
            response = client.get(download_url, timeout=self.DOWNLOAD_TIMEOUT, headers=headers, verify=False)
        except requests.RequestException:
            self.log.exception(f"Failed to download payload {sha256[:12]}…")
            return False

        file_content = response.content

        # Create the database record, or upgrade an existing hash-only stub with
        # the real file and fresh metadata.
        payload = HoneypotPayload(
            sha256=sha256,
            md5=payload_meta.get("md5", ""),
            sha1=payload_meta.get("sha1", ""),
            mime_type=payload_meta.get("mime_type", ""),
            size=len(file_content),
            locator=locator,
            mtime=payload_meta.get("mtime"),
        )
        payload_obj, created = self.payload_repo.upsert_downloaded_payload(payload)

        # Save the binary content via QuarantineStorage.
        filename = f"{sha256}.vir"
        payload_obj.payload_file.save(filename, ContentFile(file_content), save=False)
        payload_obj.save()

        if created:
            self.log.info(f"Stored new payload {sha256[:12]}… ({len(file_content)} bytes).")
        else:
            self.log.info(f"Upgraded hash-only stub {sha256[:12]}… with the downloaded file ({len(file_content)} bytes).")

        linked = self.payload_repo.link_sessions_to_payload(payload_obj)
        if linked:
            self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
        return True
