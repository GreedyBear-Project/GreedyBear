from datetime import datetime, timedelta

from django.db import IntegrityError

from greedybear.cronjobs.repositories import CowrieSessionRepository
from greedybear.models import IOC, CommandSequence, CowrieFileTransfer, CowrieSession, Credential

from . import CustomTestCase


class TestCowrieSessionRepository(CustomTestCase):
    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_get_or_create_session_creates_new(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id="123456", source=source_ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result.session_id, int("123456", 16))
        self.assertEqual(result.source, source_ioc)

    def test_get_or_create_session_returns_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        result = self.repo.get_or_create_session(existing_session_id, source=source)
        self.assertEqual(result.pk, int(existing_session_id, 16))
        self.assertTrue(result.login_attempt)

    def test_get_or_create_raises_on_invalid_session_id(self):
        session_id = "gggggggggggg"
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        with self.assertRaises(ValueError):
            self.repo.get_or_create_session(session_id, source=source)

    def test_save_session_persists_to_database(self):
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession(session_id=12345, source=source_ioc)
        result = self.repo.save_session(session)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CowrieSession.objects.filter(session_id=12345).exists())

    def test_save_session_updates_existing(self):
        existing_session_id = "ffffffffffff"
        source = self.cowrie_session.source
        session = self.repo.get_or_create_session(existing_session_id, source=source)

        original_interaction_count = session.interaction_count
        session.interaction_count = 10
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, 10)
        self.assertEqual(
            CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count,
            10,
        )

        session.interaction_count = original_interaction_count
        result = self.repo.save_session(session)
        self.assertEqual(result.interaction_count, original_interaction_count)
        self.assertEqual(
            CowrieSession.objects.get(session_id=int(existing_session_id, 16)).interaction_count,
            original_interaction_count,
        )

    def test_get_command_sequence_by_hash_returns_existing(self):
        existing = self.command_sequence
        result = self.repo.get_command_sequence_by_hash(existing.commands_hash)
        self.assertIsNotNone(result)
        self.assertEqual(result.pk, existing.pk)
        self.assertEqual(result.commands_hash, existing.commands_hash)

    def test_get_command_sequence_by_hash_returns_none_for_missing(self):
        result = self.repo.get_command_sequence_by_hash("nonexistent")
        self.assertIsNone(result)

    def test_save_command_sequence_persists_to_database(self):
        cmd_seq = CommandSequence(
            commands=["ls", "pwd", "whoami"],
            commands_hash="def456",
        )
        result = self.repo.save_command_sequence(cmd_seq)
        self.assertIsNotNone(result.pk)
        self.assertTrue(CommandSequence.objects.filter(commands_hash="def456").exists())

    def test_save_command_sequence_updates_existing(self):
        existing = self.command_sequence
        existing.last_seen = datetime(2025, 1, 2)
        self.repo.save_command_sequence(existing)
        updated = CommandSequence.objects.get(commands_hash=existing.commands_hash)
        self.assertEqual(updated.last_seen.date(), datetime(2025, 1, 2).date())

    def test_get_or_create_session_with_hex_session_id(self):
        session_id = "abc123"
        source_ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        result = self.repo.get_or_create_session(session_id=session_id, source=source_ioc)
        self.assertEqual(result.session_id, int(session_id, 16))

    def test_command_sequence_unique_hash_constraint(self):
        existing = self.command_sequence
        with self.assertRaises(IntegrityError):
            CommandSequence.objects.create(
                commands=["different", "commands"],
                commands_hash=existing.commands_hash,
            )

    def test_get_or_create_file_transfer_creates_new(self):
        session = self.cowrie_session

        transfer = self.repo.get_or_create_file_transfer(
            session=session,
            shasum="abc123def456",
            url="http://malware.com/bad.exe",
            outfile="/data/cowrie/downloads/bad.exe",
            timestamp=datetime(2023, 1, 1, 10, 0, 4),
        )

        self.assertIsNotNone(transfer.pk)
        self.assertEqual(transfer.session, session)
        self.assertEqual(transfer.shasum, "abc123def456")
        self.assertEqual(transfer.url, "http://malware.com/bad.exe")
        self.assertEqual(transfer.outfile, "/data/cowrie/downloads/bad.exe")
        self.assertEqual(transfer.timestamp, datetime(2023, 1, 1, 10, 0, 4))

    def test_get_or_create_file_transfer_updates_timestamp(self):
        session = self.cowrie_session

        existing = CowrieFileTransfer.objects.create(
            session=session,
            shasum="abc123def456",
            url="http://malware.com/bad.exe",
            outfile="/data/cowrie/downloads/bad.exe",
            timestamp=datetime(2023, 1, 1, 10, 0, 4),
        )

        transfer = self.repo.get_or_create_file_transfer(
            session=session,
            shasum="abc123def456",
            url="http://malware.com/ignored.exe",
            outfile="/data/cowrie/downloads/ignored.exe",
            timestamp=datetime(2023, 1, 2, 10, 0, 4),
        )

        self.assertEqual(transfer.pk, existing.pk)
        self.assertEqual(transfer.timestamp, datetime(2023, 1, 2, 10, 0, 4))
        self.assertEqual(
            CowrieFileTransfer.objects.filter(session=session, shasum="abc123def456").count(),
            1,
        )

    def test_add_credential_uses_default_protocol_variant(self):
        session = self.cowrie_session

        self.repo.add_credential(session, username="root", password="root")

        credential = Credential.objects.get(username="root", password="root", protocol="")
        self.assertTrue(session.credentials.filter(pk=credential.pk).exists())

    def test_add_credential_protocol_none_maps_to_default_protocol(self):
        session = self.cowrie_session

        self.repo.add_credential(session, username="admin", password="admin", protocol=None)

        self.assertTrue(Credential.objects.filter(username="admin", password="admin", protocol="").exists())

    def test_add_credential_does_not_raise_with_protocol_variants_present(self):
        session = self.cowrie_session
        Credential.objects.get_or_create(username="root", password="root", protocol="ssh")

        self.repo.add_credential(session, username="root", password="root")

        default_credential = Credential.objects.get(username="root", password="root", protocol="")
        self.assertTrue(session.credentials.filter(pk=default_credential.pk).exists())


class TestCowrieSessionRepositoryCleanup(CustomTestCase):
    """Tests for cleanup-related methods in CowrieSessionRepository."""

    def setUp(self):
        self.repo = CowrieSessionRepository()

    def test_delete_old_command_sequences(self):
        old_date = datetime.now() - timedelta(days=40)
        recent_date = datetime.now() - timedelta(days=5)

        CommandSequence.objects.create(commands=["ls"], commands_hash="old_hash", last_seen=old_date)
        CommandSequence.objects.create(commands=["pwd"], commands_hash="recent_hash", last_seen=recent_date)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_old_command_sequences(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CommandSequence.objects.filter(commands_hash="old_hash").exists())
        self.assertTrue(CommandSequence.objects.filter(commands_hash="recent_hash").exists())

    def test_delete_incomplete_sessions(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")

        CowrieSession.objects.create(session_id=123, source=source, start_time=None)
        CowrieSession.objects.create(session_id=456, source=source, start_time=datetime.now())

        deleted_count = self.repo.delete_incomplete_sessions()

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=123).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=456).exists())

    def test_delete_sessions_without_login(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        old_date = datetime.now() - timedelta(days=40)
        recent_date = datetime.now() - timedelta(days=5)

        # Old session without login
        CowrieSession.objects.create(session_id=111, source=source, start_time=old_date, login_attempt=False)
        # Recent session without login
        CowrieSession.objects.create(session_id=222, source=source, start_time=recent_date, login_attempt=False)
        # Old session with login
        CowrieSession.objects.create(session_id=333, source=source, start_time=old_date, login_attempt=True)

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_sessions_without_login(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=111).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=222).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=333).exists())

    def test_delete_sessions_without_commands(self):
        source = IOC.objects.create(name="1.2.3.4", type="ip")
        old_date = datetime.now() - timedelta(days=40)

        # Session without commands
        CowrieSession.objects.create(session_id=777, source=source, start_time=old_date)
        # Session with commands
        session_with_cmd = CowrieSession.objects.create(session_id=888, source=source, start_time=old_date)
        cmd_seq = CommandSequence.objects.create(commands=["ls"], commands_hash="hash1")
        session_with_cmd.commands = cmd_seq
        session_with_cmd.save()

        cutoff = datetime.now() - timedelta(days=30)
        deleted_count = self.repo.delete_sessions_without_commands(cutoff)

        self.assertEqual(deleted_count, 1)
        self.assertFalse(CowrieSession.objects.filter(session_id=777).exists())
        self.assertTrue(CowrieSession.objects.filter(session_id=888).exists())


class CredentialReuseTestCase(CustomTestCase):
    def setUp(self):
        self.repo = CowrieSessionRepository()
        # counter for generating unique session_ids
        self._session_counter = 1000

    def create_cowrie_session(self, source_ip: str, session_id=None):
        """Helper to create a CowrieSession with a unique session_id."""
        source_ioc, _ = IOC.objects.get_or_create(name=source_ip, defaults={"type": "ip"})
        if session_id is None:
            session_id = self._session_counter
            self._session_counter += 1
        return CowrieSession.objects.create(
            session_id=session_id,
            source=source_ioc,
        )

    def test_same_ip_not_counted_twice(self):
        session = self.create_cowrie_session(source_ip="1.2.3.4", session_id=111)

        self.repo.add_credential(session, "admin", "123")
        self.repo.add_credential(session, "admin", "123")

        credential = Credential.objects.get(username="admin", password="123")
        self.assertEqual(credential.sources.count(), 1)

    def test_different_ips_counted(self):
        session1 = self.create_cowrie_session(source_ip="1.2.3.4", session_id=111)
        session2 = self.create_cowrie_session(source_ip="5.6.7.8", session_id=222)

        self.repo.add_credential(session1, "admin", "123")
        self.repo.add_credential(session2, "admin", "123")

        credential = Credential.objects.get(username="admin", password="123")
        self.assertEqual(credential.sources.count(), 2)

    def test_same_source_ip_different_sessions_not_counted_twice(self):
        """
        Same credential added from two different sessions
        but the same source IP should only be linked once.
        """
        # two DIFFERENT sessions, but SAME source IP
        session1 = self.create_cowrie_session(source_ip="1.2.3.4", session_id=333)
        session2 = self.create_cowrie_session(source_ip="1.2.3.4", session_id=444)

        self.repo.add_credential(session1, "admin", "123")
        self.repo.add_credential(session2, "admin", "123")

        credential = Credential.objects.get(username="admin", password="123")

        # despite two different sessions, same IP = count only 1
        self.assertEqual(credential.sources.count(), 1)
