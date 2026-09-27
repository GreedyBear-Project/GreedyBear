import logging
from typing import TypedDict

from django.contrib.postgres.expressions import ArraySubquery
from django.db.models import OuterRef, Q
from django.db.models.functions import Lower

from greedybear.models import CowrieSession, HoneypotPayload


class PayloadFields(TypedDict):
    """Known metadata fields for a HoneypotPayload, used to create or upgrade one."""

    md5: str
    sha1: str
    mime_type: str
    size: int | None
    locator: str
    mtime: float | None


class PayloadRepository:
    """
    Repository joining HoneypotPayload records with the CowrieSession(s) that
    transferred the same file, matched by SHA256 hash.

    ExtractionJob (Cowrie) and PayloadExtractionJob run independently and can
    complete in either order within the same tick, so this repository is used
    from both directions: once a payload is downloaded, and once a Cowrie file
    transfer is recorded, each side looks for a match already stored by the
    other.
    """

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def link_sessions_to_payload(self, payload: HoneypotPayload) -> int:
        """
        Find Cowrie sessions that transferred a file matching this payload's
        SHA256, and link them (and their source IOCs) to the payload.

        Args:
            payload: HoneypotPayload instance to link, already saved.

        Returns:
            Number of sessions linked.
        """
        # assumption: Cowrie always emits lowercase hex for shasum (hashlib.hexdigest()), and payload.sha256 is
        # always stored in lowercase too, hence this plain comparison works with CowrieFileTransfer's shasum index.
        sessions = CowrieSession.objects.filter(file_transfers__shasum=payload.sha256.lower()).select_related("source")
        linked = 0
        for session in sessions:
            payload.cowrie_sessions.add(session)
            payload.iocs.add(session.source)
            linked += 1
        return linked

    def link_payload_to_session(self, session: CowrieSession, shasum: str) -> bool:
        """
        Find a HoneypotPayload matching this file transfer's SHA256, and link
        it (and the session's source IOC) to the session.

        Args:
            session: CowrieSession instance that transferred the file.
            shasum: SHA256 checksum of the transferred file.

        Returns:
            True if a matching payload was found and linked.
        """
        payload = HoneypotPayload.objects.annotate(sha256_lower=Lower("sha256")).filter(sha256_lower=shasum.lower()).first()
        if payload is None:
            return False
        payload.cowrie_sessions.add(session)
        payload.iocs.add(session.source)
        return True

    def get_or_create_stub(self, sha256: str) -> tuple[HoneypotPayload, bool]:
        """
        Get an existing HoneypotPayload row for this hash, or create a
        hash-only stub if none exists yet.

        Args:
            sha256: SHA256 hash, expected already lower-cased by the caller.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload, created = HoneypotPayload.objects.get_or_create(
            sha256=sha256,
            defaults={"payload_file": None, "md5": "", "sha1": ""},
        )
        return payload, created

    def upsert_downloaded_payload(self, sha256: str, fields: PayloadFields) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a file that was just downloaded, or
        upgrade an existing hash-only stub with it.

        A new row gets every field in `fields`. An existing row always has
        size and locator overwritten; every other field is overwritten only
        if its incoming value is truthy, so a blank one never erases
        existing data.

        Args:
            sha256: Lower-cased SHA256 hash.
            fields: Metadata for this download. See PayloadFields.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload, created = HoneypotPayload.objects.get_or_create(sha256=sha256, defaults=fields)
        if not created:
            for field, value in fields.items():
                if field in ("size", "locator") or value:
                    setattr(payload, field, value)
        return payload, created

    def upsert_metadata_only_payload(self, sha256: str, fields: PayloadFields) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a payload the server listed but
        this run did not download, or backfill an existing stub's locator.

        A new row gets every field in `fields`, with payload_file left
        unset. A stub written by _process_payload_hashes always has an empty
        locator, so an existing row's locator is filled in whenever it's
        missing, keeping the payload recoverable; no other metadata is
        updated here since an actual download has not occurred.

        Args:
            sha256: Lower-cased SHA256 hash.
            fields: Metadata for this payload. See PayloadFields.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload, created = HoneypotPayload.objects.get_or_create(
            sha256=sha256,
            defaults={"payload_file": None, **fields},
        )
        if not created and not payload.locator:
            payload.locator = fields["locator"]
            payload.save(update_fields=["locator"])
        return payload, created

    def get_downloaded_hashes(self, hashes: set[str]) -> set[str]:
        """
        Given SHA256 hashes in any case, return the subset that already have
        a downloaded file - i.e. rows that are not hash-only stubs.

        Args:
            hashes: Set of SHA256 hashes to check, in any case.

        Returns:
            The subset of hashes (lower-cased) that already have a file attached.
        """
        hashes_lower = {h.lower() for h in hashes}
        return set(
            HoneypotPayload.objects.annotate(sha256_lower=Lower("sha256"))
            .filter(sha256_lower__in=hashes_lower)
            # Django stores an unset FileField as an empty string, not NULL - exclude both.
            .exclude(Q(payload_file="") | Q(payload_file__isnull=True))
            .values_list("sha256_lower", flat=True)
        )

    def get_pending_malwarebazaar_submissions(self, max_size_bytes: int, limit: int) -> list[HoneypotPayload]:
        """
        Return payloads not yet submitted to MalwareBazaar, excluding
        zero-byte or size-unknown payloads, with a downloaded file and
        within the given size limit.

        Args:
            max_size_bytes: Largest file size MalwareBazaar's API accepts.
            limit: Maximum number of payloads to return.

        Returns:
            Up to `limit` HoneypotPayload rows, with source_honeypots prefetched.
        """
        # Evaluated into a list here, not left as a queryset, so the caller's
        # truthiness check and iteration don't each trigger their own SQL query.
        return list(
            HoneypotPayload.objects.filter(is_uploaded_mb=False, size__lte=max_size_bytes)
            .exclude(payload_file="")
            .exclude(payload_file__isnull=True)
            .exclude(size__isnull=True)
            .exclude(size=0)
            .prefetch_related("source_honeypots")[:limit]
        )

    def list_payloads(self):
        """
        Return the base queryset for listing/retrieving payloads, with
        related honeypots/IOCs/sessions prefetched, most recent first.

        Left unevaluated so the API view can paginate or filter further on
        top of it.

        Returns:
            QuerySet of HoneypotPayload.
        """
        return HoneypotPayload.objects.prefetch_related("source_honeypots", "iocs", "cowrie_sessions").order_by("-id")

    def annotate_lower_sha256(self, queryset):
        """
        Annotate a HoneypotPayload queryset with sha256_lower, so it can be
        filtered by SHA256 case-insensitively.

        Args:
            queryset: A HoneypotPayload queryset.

        Returns:
            The same queryset, annotated with sha256_lower.
        """
        return queryset.annotate(sha256_lower=Lower("sha256"))

    def payload_hashes_for_ioc(self):
        """
        Return an array of lower-cased SHA256 hashes for the HoneypotPayloads
        linked to each IOC, ready to pass to annotate() on an IOC queryset.

        Correlates via OuterRef("pk"), so it only works there - it depends
        on that outer query to run.

        Returns:
            An ArraySubquery expression.
        """
        payloads = HoneypotPayload.objects.filter(iocs=OuterRef("pk")).annotate(sha256_lower=Lower("sha256")).order_by("sha256_lower").values("sha256_lower")
        return ArraySubquery(payloads)
