from django.utils import timezone

from greedybear.cronjobs.repositories import PayloadRepository
from greedybear.models import IOC, CowrieFileTransfer, CowrieSession, HoneypotPayload

from . import CustomTestCase


class TestPayloadRepository(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.repo = PayloadRepository()

    def _make_transfer(self, session, shasum):
        return CowrieFileTransfer.objects.create(
            session=session,
            shasum=shasum,
            url="",
            outfile="",
            timestamp=timezone.now(),
        )

    def test_link_sessions_to_payload_no_match(self):
        payload = HoneypotPayload.objects.create(sha256="a" * 64)
        linked = self.repo.link_sessions_to_payload(payload)
        self.assertEqual(linked, 0)
        self.assertEqual(payload.cowrie_sessions.count(), 0)
        self.assertEqual(payload.iocs.count(), 0)

    def test_link_sessions_to_payload_single_match(self):
        self._make_transfer(self.cowrie_session, "a" * 64)
        payload = HoneypotPayload.objects.create(sha256="a" * 64)

        linked = self.repo.link_sessions_to_payload(payload)

        self.assertEqual(linked, 1)
        self.assertIn(self.cowrie_session, payload.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, payload.iocs.all())

    def test_link_sessions_to_payload_multiple_sessions(self):
        self._make_transfer(self.cowrie_session, "c" * 64)
        self._make_transfer(self.cowrie_session_2, "c" * 64)
        payload = HoneypotPayload.objects.create(sha256="c" * 64)

        linked = self.repo.link_sessions_to_payload(payload)

        self.assertEqual(linked, 2)
        self.assertIn(self.cowrie_session, payload.cowrie_sessions.all())
        self.assertIn(self.cowrie_session_2, payload.cowrie_sessions.all())

    def test_link_payload_to_session_no_match(self):
        linked = self.repo.link_payload_to_session(self.cowrie_session, "e" * 64)
        self.assertFalse(linked)

    def test_link_payload_to_session_match(self):
        payload = HoneypotPayload.objects.create(sha256="f" * 64)

        linked = self.repo.link_payload_to_session(self.cowrie_session, "f" * 64)

        self.assertTrue(linked)
        self.assertIn(self.cowrie_session, payload.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, payload.iocs.all())

    def test_link_payload_to_session_case_insensitive_match(self):
        payload = HoneypotPayload.objects.create(sha256=("11" * 32).lower())

        linked = self.repo.link_payload_to_session(self.cowrie_session, ("11" * 32).upper())

        self.assertTrue(linked)
        self.assertIn(self.cowrie_session, payload.cowrie_sessions.all())

    def test_link_payload_to_session_idempotent(self):
        payload = HoneypotPayload.objects.create(sha256="9" * 64)

        self.repo.link_payload_to_session(self.cowrie_session, "9" * 64)
        self.repo.link_payload_to_session(self.cowrie_session, "9" * 64)

        self.assertEqual(payload.cowrie_sessions.count(), 1)
        self.assertEqual(payload.iocs.count(), 1)

    def test_link_sessions_to_payload_only_matches_exact_hash(self):
        other_ioc = IOC.objects.create(name="203.0.113.9", type="ip")
        other_session = CowrieSession.objects.create(session_id=0x7777, source=other_ioc)
        self._make_transfer(other_session, "b" * 64)
        payload = HoneypotPayload.objects.create(sha256="a" * 64)

        linked = self.repo.link_sessions_to_payload(payload)

        self.assertEqual(linked, 0)
        self.assertNotIn(other_session, payload.cowrie_sessions.all())
