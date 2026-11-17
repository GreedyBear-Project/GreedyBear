import logging

from django.contrib.postgres.expressions import ArraySubquery
from django.db.models import OuterRef, Q, QuerySet

from greedybear.models import IOC, Honeypot, HoneypotPayload
from greedybear.utils import normalize_sha256


class PayloadRepository:
    """
    Repository for creating, updating, and querying HoneypotPayload records.

    Each payload is identified by a lowercase SHA256. Event processing links
    payloads to the related IOCs and honeypots. PayloadExtractionJob adds file
    metadata and downloaded files to the same records.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create_payload_from_event(
        self,
        sha256: str,
        ioc: IOC,
        honeypot_names: list[str] | None = None,
    ) -> tuple[HoneypotPayload, bool]:
        """
        Get or create a payload reported by an event.

        The payload is linked to the attacker IOC and the honeypots that
        reported the event. File metadata and payload_file are added later by
        PayloadExtractionJob.

        Args:
            sha256: SHA256 reported by the event.
            ioc: Attacker IOC associated with the event.
            honeypot_names: Names of the honeypots that reported the event.

        Returns:
            The payload and whether it was created.
        """
        payload, created = HoneypotPayload.objects.get_or_create(
            sha256=normalize_sha256(sha256),
            defaults={"payload_file": None},
        )
        payload.iocs.add(ioc)

        if honeypot_names:
            honeypots = Honeypot.objects.filter(name__in=honeypot_names)
            payload.source_honeypots.add(*honeypots)

        return payload, created

    def upsert_downloaded_payload(self, payload: HoneypotPayload) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a file that was just downloaded, or
        upgrade the existing row for that hash with it.

        A new row gets every metadata field of `payload`. An existing row
        always has size and locator overwritten; every other field is
        overwritten only if its incoming value is truthy, so a blank one
        never erases existing data. The row is saved in both cases.

        Args:
            payload: Unsaved HoneypotPayload holding the lower-cased SHA256 and the download's metadata.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload_record, created = HoneypotPayload.objects.get_or_create(
            sha256=normalize_sha256(payload.sha256),
            defaults={
                "md5": payload.md5,
                "sha1": payload.sha1,
                "mime_type": payload.mime_type,
                "size": payload.size,
                "locator": payload.locator,
                "mtime": payload.mtime,
            },
        )
        if not created:
            # Always overwrite size and locator, but only overwrite other fields if the new value is not empty
            payload_record.size = payload.size
            payload_record.locator = payload.locator
            payload_record.md5 = payload.md5 or payload_record.md5
            payload_record.sha1 = payload.sha1 or payload_record.sha1
            payload_record.mime_type = payload.mime_type or payload_record.mime_type
            payload_record.mtime = payload.mtime or payload_record.mtime
            payload_record.save()
        return payload_record, created

    def upsert_metadata_only_payload(self, payload: HoneypotPayload) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a payload the server listed but
        this run did not download, or backfill an existing stub's locator.

        A new row gets every metadata field of `payload`, with payload_file
        left unset. An existing row's locator is filled in only if it doesn't
        already have one; no other metadata is updated here since an actual
        download has not occurred.

        Args:
            payload: Unsaved HoneypotPayload holding the lower-cased SHA256 and the listed metadata.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload_record, created = HoneypotPayload.objects.get_or_create(
            sha256=normalize_sha256(payload.sha256),
            defaults={
                # None rather than "", to match the hash-only stubs written by
                # _process_payload_hashes. The field still expresses "no file"
                # two ways across the codebase; unifying that is a follow-up.
                "payload_file": None,
                "md5": payload.md5,
                "sha1": payload.sha1,
                "mime_type": payload.mime_type,
                "size": payload.size,
                "locator": payload.locator,
                "mtime": payload.mtime,
            },
        )
        if not created and not payload_record.locator:
            # A hash-only stub written by _process_payload_hashes carries no
            # locator. Fill it in so the payload stays recoverable.
            payload_record.locator = payload.locator
            payload_record.save(update_fields=["locator"])
        return payload_record, created

    def get_downloaded_hashes(self, hashes: set[str]) -> set[str]:
        """
        Given SHA256 hashes in any case, return the subset that already have
        a downloaded file.

        Args:
            hashes: Set of SHA256 hashes to check, in any case.

        Returns:
            The subset of hashes (lower-cased) that already have a file attached.
        """
        hashes_lower = {h.strip().lower() for h in hashes}
        return set(
            HoneypotPayload.objects.filter(sha256__in=hashes_lower)
            # Django stores an unset FileField as an empty string, but exclude NULL as well.
            .exclude(Q(payload_file="") | Q(payload_file__isnull=True))
            .values_list("sha256", flat=True)
        )

    def get_pending_malwarebazaar_submissions(self, max_size_bytes: int, limit: int) -> list[HoneypotPayload]:
        """
        Return payloads not yet submitted to MalwareBazaar, excluding
        zero-byte or size-unknown payloads, with a downloaded file and
        within the given size limit.

        Args:
            max_size_bytes: Largest file size to include, in bytes.
            limit: Maximum number of payloads to return.

        Returns:
            Up to `limit` HoneypotPayload rows, with source_honeypots prefetched.
        """
        # Exclude zero-byte files (size=0 or NULL) and payloads without a
        # quarantine file on disk.  Evaluate into a list so we avoid the
        # double SQL hit of count() + iterate on a sliced queryset.
        return list(
            HoneypotPayload.objects.filter(is_uploaded_mb=False, size__lte=max_size_bytes)
            .exclude(payload_file="")
            .exclude(payload_file__isnull=True)
            .exclude(size__isnull=True)
            .exclude(size=0)
            .prefetch_related("source_honeypots")[:limit]
        )

    def list_payloads(self) -> QuerySet:
        """
        Return the base queryset for listing/retrieving payloads, with
        related honeypots, IOCs, and transfers prefetched, most recent first.

        Left unevaluated so the API view can paginate or filter further on
        top of it.

        Returns:
            QuerySet of HoneypotPayload.
        """
        return HoneypotPayload.objects.prefetch_related("source_honeypots", "iocs", "cowrie_file_transfers").order_by("-id")

    def payload_hashes_for_ioc(self) -> ArraySubquery:
        """
        Return an expression yielding an array of payload SHA256 values linked
        to each IOC, ready to pass to annotate() on an IOC queryset.

        Correlates via OuterRef("pk"), so it only works there - it depends
        on that outer query to run.

        Returns:
            An ArraySubquery expression.
        """
        payloads = HoneypotPayload.objects.filter(iocs=OuterRef("pk")).order_by("sha256").values("sha256")
        return ArraySubquery(payloads)
