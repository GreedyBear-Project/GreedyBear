# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

import time
from pathlib import Path

import requests
from django.conf import settings
from django.core.files.base import ContentFile
from django.db.models.functions import Lower

from greedybear.cronjobs.base import Cronjob
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
    5. Records metadata-only rows for any payload left undownloaded once the
       quota is reached, so it is not lost with the extraction window.
    6. Links every payload it records, downloaded or not, to the Cowrie sessions
       and attacker IOCs that already transferred a file with the same SHA256.
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

        self.log.info(f"Payload extraction complete: {downloaded} downloaded, {skipped_count} skipped/failed, {deferred_count} stored as metadata only.")

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

            payload_obj, created = HoneypotPayload.objects.get_or_create(
                sha256=sha256,
                defaults={
                    # NULL rather than "", to match the hash-only stubs written by
                    # _process_payload_hashes. The field still expresses "no file"
                    # two ways across the codebase; unifying that is a follow-up.
                    "payload_file": None,
                    "md5": payload_meta.get("md5", ""),
                    "sha1": payload_meta.get("sha1", ""),
                    "mime_type": payload_meta.get("mime_type", ""),
                    "size": payload_meta.get("size"),
                    "locator": locator,
                    "mtime": payload_meta.get("mtime"),
                },
            )
            if not created and not payload_obj.locator:
                # A hash-only stub written by _process_payload_hashes carries no
                # locator. Fill it in so the payload stays recoverable.
                payload_obj.locator = locator
                payload_obj.save(update_fields=["locator"])

            linked = self.payload_repo.link_sessions_to_payload(payload_obj)
            if linked:
                self.log.info(f"Linked payload {sha256[:12]}… to {linked} cowrie session(s).")
            stored += 1

        if stored:
            self.log.info(f"Stored metadata for {stored} payload(s) that were not downloaded.")
        return stored

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
