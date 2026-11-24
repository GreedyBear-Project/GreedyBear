import logging

from django.contrib.postgres.expressions import ArraySubquery
from django.db.models import OuterRef, Q, QuerySet
from django.db.models.functions import Lower

from greedybear.models import CowrieSession, HoneypotPayload, PayloadObservation


class PayloadRepository:
    """
    Repository for data access to HoneypotPayload records.

    It also links payloads to the CowrieSession(s) that transferred the same
    file, matched by SHA256 hash. ExtractionJob (Cowrie) and
    PayloadExtractionJob run independently and can complete in either order
    within the same tick, so the linking is done from both directions: once a
    payload is downloaded, and once a Cowrie file transfer is recorded, each
    side looks for a match already stored by the other. Stubs created by the
    event collector link pre-existing sessions at creation time.
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

    def upsert_downloaded_payload(self, payload: HoneypotPayload) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a file that was just downloaded, or
        upgrade the existing row for that hash with it.

        A new row gets every metadata field of `payload`. An existing row
        always has size overwritten; every other field is overwritten only
        if its incoming value is truthy, so a blank one never erases
        existing data. The row is saved in both cases. Where the file was
        found is recorded separately, see record_observations.

        Args:
            payload: Unsaved HoneypotPayload holding the lower-cased SHA256 and the download's metadata.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload_record, created = HoneypotPayload.objects.get_or_create(
            sha256=payload.sha256,
            defaults={
                "md5": payload.md5,
                "sha1": payload.sha1,
                "mime_type": payload.mime_type,
                "size": payload.size,
            },
        )
        if not created:
            # Always overwrite size, but only overwrite other fields if the new value is not empty
            payload_record.size = payload.size
            payload_record.md5 = payload.md5 or payload_record.md5
            payload_record.sha1 = payload.sha1 or payload_record.sha1
            payload_record.mime_type = payload.mime_type or payload_record.mime_type
            payload_record.save()
        return payload_record, created

    def upsert_metadata_only_payload(self, payload: HoneypotPayload) -> tuple[HoneypotPayload, bool]:
        """
        Create a HoneypotPayload row for a payload the server listed but
        this run did not download, or return the existing row for its hash.

        A new row gets every metadata field of `payload`, with payload_file
        left unset. An existing row is left untouched since an actual
        download has not occurred. The locator that makes the payload
        recoverable is recorded separately, see record_observations.

        Args:
            payload: Unsaved HoneypotPayload holding the lower-cased SHA256 and the listed metadata.

        Returns:
            Tuple of (HoneypotPayload object, created_flag) where created_flag is True if new.
        """
        payload_record, created = HoneypotPayload.objects.get_or_create(
            sha256=payload.sha256,
            defaults={
                # None rather than "", to match the hash-only stubs written by
                # _process_payload_hashes. The field still expresses "no file"
                # two ways across the codebase; unifying that is a follow-up.
                "payload_file": None,
                "md5": payload.md5,
                "sha1": payload.sha1,
                "mime_type": payload.mime_type,
                "size": payload.size,
            },
        )
        return payload_record, created

    def record_observations(self, observations: list[PayloadObservation]) -> None:
        """
        Record that a payload server listed these payloads, or refresh the
        locator and mtime of that server's earlier observations of them.

        Each sensor keeps its own observation, so a binary reported by several
        sensors is stored once while every sensor's locator is kept.

        Args:
            observations: Unsaved PayloadObservations of saved payloads, at most one per payload and sensor.
        """
        PayloadObservation.objects.bulk_create(
            observations,
            update_conflicts=True,
            unique_fields=["payload", "sensor"],
            update_fields=["locator", "mtime"],
        )

    def get_downloaded_payloads(self, hashes: set[str]) -> dict[str, HoneypotPayload]:
        """
        Given SHA256 hashes in any case, return the payloads among them that
        already have a downloaded file.

        Args:
            hashes: Set of SHA256 hashes to check, in any case.

        Returns:
            Dict mapping the lower-cased hash to its HoneypotPayload, for the hashes that already have a file attached.
        """
        hashes_lower = {h.lower() for h in hashes}
        payloads = (
            HoneypotPayload.objects.annotate(sha256_lower=Lower("sha256"))
            .filter(sha256_lower__in=hashes_lower)
            # Django stores an unset FileField as an empty string, but exclude NULL as well.
            .exclude(Q(payload_file="") | Q(payload_file__isnull=True))
        )
        return {payload.sha256.lower(): payload for payload in payloads}

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
        related honeypots/sensors/IOCs/sessions prefetched, most recent first.

        Left unevaluated so the API view can paginate or filter further on
        top of it.

        Returns:
            QuerySet of HoneypotPayload.
        """
        return HoneypotPayload.objects.prefetch_related("source_honeypots", "sensors", "iocs", "cowrie_sessions").order_by("-id")

    def annotate_lower_sha256(self, queryset: QuerySet) -> QuerySet:
        """
        Annotate a HoneypotPayload queryset with sha256_lower, so it can be
        filtered by SHA256 case-insensitively.

        Args:
            queryset: A HoneypotPayload queryset.

        Returns:
            The same queryset, annotated with sha256_lower.
        """
        return queryset.annotate(sha256_lower=Lower("sha256"))

    def payload_hashes_for_ioc(self) -> ArraySubquery:
        """
        Return an expression yielding an array of the lower-cased SHA256 hashes
        of the HoneypotPayloads linked to each IOC, ready to pass to annotate()
        on an IOC queryset.

        Correlates via OuterRef("pk"), so it only works there - it depends
        on that outer query to run.

        Returns:
            An ArraySubquery expression.
        """
        payloads = HoneypotPayload.objects.filter(iocs=OuterRef("pk")).annotate(sha256_lower=Lower("sha256")).order_by("sha256_lower").values("sha256_lower")
        return ArraySubquery(payloads)
