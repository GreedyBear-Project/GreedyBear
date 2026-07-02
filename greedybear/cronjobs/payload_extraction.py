# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

import time
from pathlib import Path

import requests
from django.conf import settings
from django.core.files.base import ContentFile

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.http_client import HttpClient
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
    """

    # Timeout for the metadata listing request (seconds).
    METADATA_TIMEOUT = 30
    # Timeout for individual file download requests (seconds).
    DOWNLOAD_TIMEOUT = 120

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
                    self.log.warning(f"Quarantine directory has reached the {settings.MAX_QUARANTINE_SIZE_GB} GB limit. Stopping downloads.")
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
        end_ts = time.time()
        start_ts = end_ts - (settings.EXTRACTION_INTERVAL * 60)

        url = f"{server_url.rstrip('/')}/api/v1/payloads/recent"
        params = {"start_ts": start_ts, "end_ts": end_ts}
        headers = self._build_auth_headers()

        try:
            response = client.get(url, params=params, headers=headers)
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
        incoming_hashes = {p["sha256"] for p in payloads if "sha256" in p}
        existing_hashes = set(HoneypotPayload.objects.filter(sha256__in=incoming_hashes).values_list("sha256", flat=True))
        new_hashes = incoming_hashes - existing_hashes
        self.log.debug(f"Deduplication: {len(incoming_hashes)} incoming, {len(existing_hashes)} existing, {len(new_hashes)} new.")
        # Keep only the first occurrence of each sha256 to avoid IntegrityError.
        seen = set()
        unique = []
        for p in payloads:
            sha = p.get("sha256")
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
        Download a single payload file and create its database record.

        Args:
            client: HttpClient instance.
            server_url: Base URL of the payload server.
            payload_meta: Dict with at least 'sha256' and 'locator' keys.

        Returns:
            bool: True if download and storage succeeded, False otherwise.
        """
        sha256 = payload_meta["sha256"]
        locator = payload_meta.get("locator", "")

        if not locator:
            self.log.warning(f"Payload {sha256[:12]}… has no locator, skipping.")
            return False

        download_url = f"{server_url.rstrip('/')}/api/v1/payloads/download/{locator}"
        headers = self._build_auth_headers()

        try:
            response = client.get(download_url, timeout=self.DOWNLOAD_TIMEOUT, headers=headers)
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
        return True
