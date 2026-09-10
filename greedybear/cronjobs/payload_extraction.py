# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from datetime import datetime
from pathlib import Path

import requests
from django.conf import settings
from django.core.files.base import ContentFile
from django.db.models.functions import Lower

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import get_time_window
from greedybear.cronjobs.http_client import HttpClient
from greedybear.cronjobs.repositories import PayloadRepository
from greedybear.models import HoneypotPayload


class PayloadExtractionJob(Cronjob):
    """
    Fetch new payloads from the tpot-payload-server, deduplicate them
    by SHA256 hash, and save them to the quarantine directory.

    This job:
    1. Queries the payload server's ``/api/v1/payloads/recent`` endpoint for
       metadata of files modified within the last extraction interval.
    2. Skips any payload whose SHA256 already exists in the database.
    3. Checks quarantine disk usage against MAX_QUARANTINE_SIZE_GB before downloading.
    4. Downloads new payload files via ``/api/v1/payloads/download/{locator}``
       and saves them via QuarantineStorage.
    5. Links each downloaded payload to any Cowrie sessions that already
       transferred a file with the same SHA256.
    """

    # Timeout for the metadata listing request (seconds).
    METADATA_TIMEOUT = 30
    # Timeout for individual file download requests (seconds).
    DOWNLOAD_TIMEOUT = 120

    def __init__(self, payload_repo: PayloadRepository = None):
        super().__init__()
        self.payload_repo = payload_repo if payload_repo is not None else PayloadRepository()

    def run(self) -> None:
        server_url = settings.TPOT_PAYLOAD_SERVER_URL
        if not server_url:
            self.log.info("TPOT_PAYLOAD_SERVER_URL not configured, skipping payload extraction.")
            return

        max_size_bytes = settings.MAX_QUARANTINE_SIZE_GB * (1024**3)

        with HttpClient(default_timeout=self.METADATA_TIMEOUT) as client:
            # Step 1: Fetch payload metadata from the server.
            payloads = self._fetch_metadata(client, server_url)
            if not payloads:
                self.log.info("No payloads returned from server.")
                return

            # Step 2: Filter out already-known payloads by SHA256.
            new_payloads = self._deduplicate(payloads)
            if not new_payloads:
                self.log.info("All payloads already exist in the database.")
                return

            self.log.info(f"Found {len(new_payloads)} new payload(s) to download.")

            # Step 3: Download and store each new payload.
            downloaded = 0
            skipped_count = 0
            for payload_meta in new_payloads:
                # Check disk usage before each download.
                if self._quarantine_usage_bytes() >= max_size_bytes:
                    self.log.error(f"Quarantine directory has reached the {settings.MAX_QUARANTINE_SIZE_GB} GB limit. Stopping downloads.")
                    break

                if self._download_and_store(client, server_url, payload_meta):
                    downloaded += 1
                else:
                    skipped_count += 1

        self.log.info(f"Payload extraction complete: {downloaded} downloaded, {skipped_count} skipped/failed.")

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

    def _fetch_metadata(self, client: HttpClient, server_url: str) -> list[dict]:
        """
        Fetch the list of recently modified payloads from the tpot-payload-server.

        Queries the ``/api/v1/payloads/recent`` endpoint with a time window
        spanning the last ``EXTRACTION_INTERVAL`` minutes.

        Returns:
            list[dict]: List of payload metadata dicts, or empty list on error.
        """
        window_start, window_end = get_time_window(
            datetime.now(),
            settings.EXTRACTION_INTERVAL,
            settings.EXTRACTION_INTERVAL,
        )

        url = f"{server_url.rstrip('/')}/api/v1/payloads/recent"
        params = {"start_ts": window_start.timestamp(), "end_ts": window_end.timestamp()}
        headers = self._build_auth_headers()

        try:
            response = client.get(url, params=params, headers=headers, verify=False)
            data = response.json()
        except requests.RequestException:
            self.log.exception("Failed to fetch payload metadata from server.")
            return []
        except (ValueError, KeyError):
            self.log.exception("Failed to parse payload metadata response.")
            return []

        if not isinstance(data, list):
            self.log.error("Payload metadata response is not a list, skipping.")
            return []
        return data

    def _deduplicate(self, payloads: list[dict]) -> list[dict]:
        """
        Filter out payloads whose SHA256 already exists in the database
        and remove duplicates within the response itself.

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
        existing_hashes = set(
            HoneypotPayload.objects.annotate(sha256_lower=Lower("sha256")).filter(sha256_lower__in=incoming_hashes).values_list("sha256_lower", flat=True)
        )
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

    def _download_and_store(self, client: HttpClient, server_url: str, payload_meta: dict) -> bool:
        """
        Download a single payload file, create its database record, and link
        it to any Cowrie sessions that already transferred the same file.

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

        # Create the database record with metadata.
        payload_obj = HoneypotPayload(
            sha256=sha256,
            md5=payload_meta.get("md5", ""),
            sha1=payload_meta.get("sha1", ""),
            mime_type=payload_meta.get("mime_type", ""),
            size=len(file_content),
            locator=locator,
            mtime=payload_meta.get("mtime"),
        )

        # Save the binary content via QuarantineStorage.
        filename = f"{sha256}.vir"
        payload_obj.payload_file.save(filename, ContentFile(file_content), save=False)
        payload_obj.save()

        self.log.info(f"Stored new payload {sha256[:12]}… ({len(file_content)} bytes).")

        linked = self.payload_repo.link_sessions_to_payload(payload_obj)
        if linked:
            self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
        return True
