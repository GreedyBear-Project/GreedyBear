import logging

from django.db.models.functions import Lower

from greedybear.models import CowrieSession, HoneypotPayload


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
