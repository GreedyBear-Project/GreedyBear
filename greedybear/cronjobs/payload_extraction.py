# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
from django.conf import settings
from django.core.files.base import ContentFile

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.http_client import HttpClient
from greedybear.cronjobs.repositories import PayloadRepository, SensorRepository
from greedybear.models import HoneypotPayload, PayloadObservation, Sensor
from greedybear.utils import get_time_window


@dataclass(frozen=True)
class PayloadSource:
    """
    A tpot-payload-server to fetch payloads from, and the sensor it runs on.

    The sensor is None for the legacy single-server configuration
    (TPOT_PAYLOAD_SERVER_URL), which does not say which sensor the server
    belongs to.
    """

    url: str
    api_key: str = field(default="", repr=False)
    sensor: Sensor | None = None

    def __str__(self) -> str:
        return f"{self.url} (sensor {self.sensor.address})" if self.sensor else self.url


class PayloadExtractionJob(Cronjob):
    """
    Fetch new payloads from one or more tpot-payload-servers, deduplicate them
    by SHA256 hash, and save them to the quarantine directory.

    For every configured payload server, this job:
    1. Queries the payload server's ``/api/v1/payloads/recent`` endpoint for
       metadata of files modified within the last extraction interval.
    2. Records an observation for every listed payload, which keeps the
       server's sensor and locator. A binary reported by several sensors is
       stored once but observed by each of them.
    3. Skips the download of any payload whose SHA256 already has a downloaded file.
    4. Checks quarantine disk usage against MAX_QUARANTINE_SIZE_GB before downloading.
    5. Downloads new payload files via ``/api/v1/payloads/download/{locator}``
       and saves them via QuarantineStorage.
    6. Records metadata-only rows for any payload left undownloaded once the
       quota is reached, so it is not lost with the extraction window.
    7. Links every payload it records, downloaded or not, to the Cowrie sessions
       and attacker IOCs that already transferred a file with the same SHA256.

    Payload servers are processed independently: one that is unreachable or
    fails is logged and skipped, without affecting the others.
    """

    # Timeout for the metadata listing request (seconds).
    METADATA_TIMEOUT = 30
    # Timeout for individual file download requests (seconds).
    DOWNLOAD_TIMEOUT = 120

    def __init__(self, payload_repo: PayloadRepository | None = None):
        super().__init__()
        self.payload_repo = payload_repo if payload_repo is not None else PayloadRepository()

    def run(self) -> None:
        sources = self._get_sources()
        if not sources:
            self.log.info("No payload server configured, skipping payload extraction.")
            return

        # Computed once, so every server is asked for the same window even if
        # the run crosses an interval boundary while working through them.
        window = self._extraction_window()

        failed = 0
        with HttpClient(default_timeout=self.METADATA_TIMEOUT) as client:
            for source in sources:
                # Every write is committed as it happens, so a failure here never
                # rolls back what was stored from this or any earlier server.
                try:
                    self._extract_from_source(client, source, window)
                except Exception:
                    self.log.exception(f"Payload extraction from {source} failed, continuing with the remaining payload servers.")
                    failed += 1
        # One broken server is already reported in the error log and must not fail
        # the run for the others. Only when none of them worked did the run fail.
        if failed == len(sources):
            raise RuntimeError(f"Payload extraction failed for all {failed} payload server(s).")

    def _get_sources(self) -> list[PayloadSource]:
        """
        Build the list of payload servers to fetch from.

        TPOT_PAYLOAD_SERVERS takes precedence. Without it, the legacy
        TPOT_PAYLOAD_SERVER_URL / TPOT_PAYLOAD_SERVER_API_KEY settings are used
        as a single server without a sensor.

        Returns:
            list[PayloadSource]: The payload servers, empty if none is configured.
        """
        if not settings.TPOT_PAYLOAD_SERVERS:
            if not settings.TPOT_PAYLOAD_SERVER_URL:
                return []
            return [PayloadSource(url=settings.TPOT_PAYLOAD_SERVER_URL, api_key=settings.TPOT_PAYLOAD_SERVER_API_KEY)]

        if settings.TPOT_PAYLOAD_SERVER_URL:
            self.log.warning("TPOT_PAYLOAD_SERVERS is set, ignoring TPOT_PAYLOAD_SERVER_URL.")

        sensor_repo = SensorRepository()
        sources = []
        for server in settings.TPOT_PAYLOAD_SERVERS:
            # The configured address is a T-Pot of this GreedyBear, never an Event Collector user's sensor.
            sensor = sensor_repo.get_or_create_internal_sensor(server["sensor"])
            if sensor is None:
                self.log.error(f"Skipping payload server {server['url']}: {server['sensor']} is not a valid sensor IP address.")
                continue
            sources.append(PayloadSource(url=server["url"], api_key=server.get("api_key", ""), sensor=sensor))
        return sources

    def _extraction_window(self) -> tuple[datetime, datetime]:
        """
        Return the time window of the last completed extraction interval.
        """
        return get_time_window(
            reference_time=datetime.now(),
            lookback_minutes=settings.EXTRACTION_INTERVAL,
            extraction_interval=settings.EXTRACTION_INTERVAL,
        )

    def _extract_from_source(self, client: HttpClient, source: PayloadSource, window: tuple[datetime, datetime]) -> None:
        """
        Fetch, record and download the payloads one payload server listed in the window.

        Args:
            client: HttpClient instance.
            source: Payload server to fetch from.
            window: Start and end of the extraction window.
        """
        max_size_bytes = settings.MAX_QUARANTINE_SIZE_GB * (1024**3)

        # Step 1: Fetch payload metadata from the server.
        payloads = self._fetch_metadata(client, source, window)
        if not payloads:
            self.log.info(f"No payloads returned from {source}.")
            return

        # Step 2: Separate payloads whose file is already stored, possibly
        # downloaded from another server, from new ones by SHA256. A row without
        # a file, like a hash-only stub, counts as new so its file is still downloaded.
        payloads = self._deduplicate(payloads)
        downloaded_payloads = self.payload_repo.get_downloaded_payloads({p["sha256"].lower() for p in payloads})
        new_payloads = [p for p in payloads if p["sha256"].lower() not in downloaded_payloads]

        # Step 3: Already stored payloads are not downloaded again, only
        # recorded as also observed on this server.
        self.payload_repo.record_observations(
            [
                self._observation(downloaded_payloads[p["sha256"].lower()], source, p)
                for p in payloads
                if p["sha256"].lower() in downloaded_payloads and p.get("locator")
            ]
        )

        if not new_payloads:
            self.log.info(f"All payloads from {source} already exist in the database.")
            return

        self.log.info(f"Found {len(new_payloads)} new payload(s) to download from {source}.")

        # Step 4: Download and store each new payload.
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
                deferred_count = self._store_metadata_only(new_payloads[index:], source)
                break

            if self._download_and_store(client, source, payload_meta):
                downloaded += 1
            else:
                skipped_count += 1

        self.log.info(
            f"Payload extraction from {source} complete: {downloaded} downloaded, {skipped_count} skipped/failed, "
            f"{deferred_count} stored as metadata only, {len(payloads) - len(new_payloads)} already stored."
        )

    def _build_auth_headers(self, source: PayloadSource) -> dict:
        """
        Build the authentication headers for a payload server.

        Args:
            source: Payload server the request goes to.

        Returns:
            dict: Headers dict with the API key, or empty dict if not configured.
        """
        if source.api_key:
            return {"X-API-Key": source.api_key}
        return {}

    def _fetch_metadata(self, client: HttpClient, source: PayloadSource, window: tuple[datetime, datetime]) -> list[dict]:
        """
        Fetch the list of recently modified payloads from a tpot-payload-server.

        Queries the ``/api/v1/payloads/recent`` endpoint for the given time window.

        Args:
            client: HttpClient instance.
            source: Payload server to fetch from.
            window: Start and end of the extraction window.

        Returns:
            list[dict]: List of payload metadata dicts, or empty list on error.
        """
        window_start, window_end = window
        url = f"{source.url.rstrip('/')}/api/v1/payloads/recent"
        params = {"start_ts": window_start.timestamp(), "end_ts": window_end.timestamp()}
        headers = self._build_auth_headers(source)

        try:
            response = client.get(url, params=params, headers=headers, verify=False)
            data = response.json()
        except requests.RequestException:
            self.log.exception(f"Failed to fetch payload metadata from {source}.")
            return []
        except (ValueError, KeyError):
            self.log.exception(f"Failed to parse payload metadata response from {source}.")
            return []

        if not isinstance(data, list):
            self.log.error(f"Payload metadata response from {source} is not a list, skipping.")
            return []
        return data

    def _deduplicate(self, payloads: list[dict]) -> list[dict]:
        """
        Remove duplicates within the response itself.

        Args:
            payloads: List of payload metadata dicts.

        Returns:
            list[dict]: The first payload for each SHA256, without the ones lacking a SHA256.
        """
        # Keep only the first occurrence of each sha256 to avoid IntegrityError.
        # Hashes are compared normalized, so entries differing only in case
        # collapse into one instead of colliding on the constraint.
        seen = set()
        unique = []
        for p in payloads:
            raw_sha = p.get("sha256")
            sha = raw_sha.lower() if raw_sha else None
            if sha and sha not in seen:
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

    def _observation(self, payload_obj: HoneypotPayload, source: PayloadSource, payload_meta: dict) -> PayloadObservation:
        """
        Build the observation of a payload on a payload server, holding the server's sensor and locator.
        """
        return PayloadObservation(payload=payload_obj, sensor=source.sensor, locator=payload_meta["locator"], mtime=payload_meta.get("mtime"))

    def _store_metadata_only(self, payloads: list[dict], source: PayloadSource) -> int:
        """
        Persist metadata-only rows for payloads that were not downloaded.

        Called when the quarantine quota is exhausted mid-batch. The row leaves
        ``payload_file`` empty to mark the payload as not yet downloaded, and its
        observation keeps the locator, which is the only handle the file can be
        fetched with later.

        Each row is linked to the Cowrie sessions and attacker IOCs that already
        transferred the same file, exactly as a downloaded payload would be. The
        hash is what the join runs on, so a row without a file still carries the
        attribution; the file only fills in later.

        Args:
            payloads: List of payload metadata dicts that were not downloaded.
            source: Payload server that listed the payloads.

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
            )
            payload_obj, _ = self.payload_repo.upsert_metadata_only_payload(payload)
            self.payload_repo.record_observations([self._observation(payload_obj, source, payload_meta)])

            linked = self.payload_repo.link_sessions_to_payload(payload_obj)
            if linked:
                self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
            stored += 1

        if stored:
            self.log.info(f"Stored metadata for {stored} payload(s) from {source} that were not downloaded.")
        return stored

    def _download_and_store(self, client: HttpClient, source: PayloadSource, payload_meta: dict) -> bool:
        """
        Download a single payload file, create its database record (or upgrade
        an existing hash-only stub with the real file), record the payload
        server's observation of it, and link it to any Cowrie sessions that
        already transferred the same file.

        Args:
            client: HttpClient instance.
            source: Payload server to download from.
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

        download_url = f"{source.url.rstrip('/')}/api/v1/payloads/download/{locator}"
        headers = self._build_auth_headers(source)

        try:
            response = client.get(download_url, timeout=self.DOWNLOAD_TIMEOUT, headers=headers, verify=False)
        except requests.RequestException:
            self.log.exception(f"Failed to download payload {sha256[:12]}… from {source}")
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
        )
        payload_obj, created = self.payload_repo.upsert_downloaded_payload(payload)

        # Save the binary content via QuarantineStorage.
        filename = f"{sha256}.vir"
        payload_obj.payload_file.save(filename, ContentFile(file_content), save=False)
        payload_obj.save()

        if created:
            self.log.info(f"Stored new payload {sha256[:12]}… ({len(file_content)} bytes) from {source}.")
        else:
            self.log.info(f"Upgraded hash-only stub {sha256[:12]}… with the file downloaded from {source} ({len(file_content)} bytes).")

        self.payload_repo.record_observations([self._observation(payload_obj, source, payload_meta)])

        linked = self.payload_repo.link_sessions_to_payload(payload_obj)
        if linked:
            self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
        return True
