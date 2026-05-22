"""
Tests for Cowrie extraction helper functions and strategy.
"""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

from django.test import override_settings

from greedybear.cronjobs.extraction.strategies.cowrie import (
    CowrieExtractionStrategy,
    normalize_command,
    normalize_credential_field,
    parse_url_hostname,
)
from greedybear.models import CommandSequence
from tests import ExtractionTestCase


class TestHelperFunctions(ExtractionTestCase):
    """Test standalone helper functions."""

    def test_parse_url_hostname_valid_http(self):
        """Test URL parsing with valid HTTP URL."""
        result = parse_url_hostname("http://example.com/path")
        self.assertEqual(result, "example.com")

    def test_parse_url_hostname_valid_https(self):
        """Test URL parsing with valid HTTPS URL."""
        result = parse_url_hostname("https://malware.site/payload.exe")
        self.assertEqual(result, "malware.site")

    def test_parse_url_hostname_with_port(self):
        """Test URL parsing with port number."""
        result = parse_url_hostname("http://evil.com:8080/download")
        self.assertEqual(result, "evil.com")

    def test_parse_url_hostname_invalid_url(self):
        """Test URL parsing with invalid URL."""
        result = parse_url_hostname("not_a_url")
        self.assertIsNone(result)

    def test_parse_url_hostname_empty_string(self):
        """Test URL parsing with empty string."""
        result = parse_url_hostname("")
        self.assertIsNone(result)

    def test_normalize_command_with_prefix(self):
        """Test command normalization with CMD prefix."""
        result = normalize_command("CMD: ls -la")
        self.assertEqual(result, "ls -la")

    def test_normalize_command_without_prefix(self):
        """Test command normalization without prefix."""
        result = normalize_command("pwd")
        self.assertEqual(result, "pwd")

    def test_normalize_command_with_null_chars(self):
        """Test command normalization with null characters."""
        result = normalize_command("CMD: echo\x00test")
        self.assertEqual(result, "echo[NUL]test")

    def test_normalize_command_truncation(self):
        """Test command truncation to 1024 characters."""
        long_command = "CMD: " + "A" * 2000
        result = normalize_command(long_command)
        self.assertEqual(len(result), 1024)
        self.assertTrue(result.startswith("A"))

    def test_normalize_credential_field_with_null(self):
        """Test credential normalization with null characters."""
        result = normalize_credential_field("user\x00name")
        self.assertEqual(result, "user[NUL]name")

    def test_normalize_credential_field_clean(self):
        """Test credential normalization with clean string."""
        result = normalize_credential_field("admin")
        self.assertEqual(result, "admin")

    def test_normalize_credential_field_truncation(self):
        """Test credential field truncation to 256 characters."""
        long_field = "A" * 300
        result = normalize_credential_field(long_field)
        self.assertEqual(len(result), 256)
        self.assertTrue(result.startswith("A"))

    def test_normalize_credential_field_short_not_truncated(self):
        """Test that short strings are not truncated."""
        short_field = "password123"
        result = normalize_credential_field(short_field)
        self.assertEqual(result, short_field)


@override_settings(THREATFOX_API_KEY="")
class TestCowrieExtractionStrategy(ExtractionTestCase):
    """Test CowrieExtractionStrategy class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()
        self.mock_session_repo = Mock()

        self.strategy = CowrieExtractionStrategy(
            "Cowrie",
            self.mock_ioc_repo,
            self.mock_sensor_repo,
            self.mock_session_repo,
        )
        self.strategy.ioc_processor = Mock()

    def test_extract_payload_in_messages_with_url(self):
        """Test extraction of URLs from login failure messages."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.login.failed",
                "message": "Failed login with http://evil.com/malware.exe",
                "@timestamp": "2025-01-01T00:00:00",
            }
        ]

        scanner_mock = Mock()
        scanner_mock.related_ioc.all.return_value = []
        payload_mock = Mock()
        payload_mock.related_ioc.all.return_value = []

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should have called add_ioc for the payload
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 1)
        call_args = self.strategy.ioc_processor.add_ioc.call_args
        ioc_arg = call_args[0][0]

        self.assertEqual(ioc_arg.name, "evil.com")
        self.assertIn("http://evil.com/malware.exe", ioc_arg.related_urls)
        # Verify honeypot is set via honeypot_name argument
        self.assertEqual(call_args.kwargs.get("honeypot_name"), "Cowrie")

    def test_extract_payload_in_messages_no_url(self):
        """Test extraction when message has no URL."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.login.failed",
                "message": "Failed login attempt",
            }
        ]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should not add any IOC
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_extract_payload_different_ips(self):
        """Test that payloads from different IPs are all processed."""
        hits = [
            {
                "src_ip": "5.6.7.8",
                "eventid": "cowrie.login.failed",
                "message": "http://evil.com/malware",
                "@timestamp": "2025-01-01T00:00:00",
            }
        ]

        scanner_mock = Mock()
        payload_mock = Mock()
        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should process the payload from any IP
        self.strategy.ioc_processor.add_ioc.assert_called_once()

    def test_extract_payload_in_messages_empty_hits(self):
        """Test extraction with empty hits list."""
        hits = []

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should not call add_ioc when there are no hits
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_get_url_downloads(self):
        """Test extraction of file download attempts."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.session.file_download",
                "url": "http://malware.com/bad.exe",
                "@timestamp": "2025-01-01T00:00:00",
            }
        ]

        scanner_mock = Mock()
        payload_mock = Mock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]
        mock_payload_record = Mock(spec=["honeypots", "payload_request"])
        mock_payload_record.payload_request = False
        mock_payload_record.honeypots.all.return_value = []
        self.strategy.ioc_processor.add_ioc.return_value = mock_payload_record

        self.strategy._get_url_downloads(hits)

        # Should only create 1 IOC: payload hostname (scanner already added in _get_scanners)
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 1)
        self.assertEqual(self.strategy.added_url_downloads, 1)

    def test_get_url_downloads_invalid_url(self):
        """Test download extraction with invalid URL."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.session.file_download",
                "url": "not_a_valid_url",
            }
        ]

        self.strategy.ioc_processor.add_ioc.return_value = Mock()

        self.strategy._get_url_downloads(hits)

        # Should not create any IOC (invalid URL, and scanner already added in _get_scanners)
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_process_session_hit_connect(self):
        """Test processing of session connect event."""
        session_record = Mock()
        session_record.interaction_count = 0
        hit = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2023-01-01T10:00:00",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertEqual(session_record.start_time, datetime(2023, 1, 1, 10, 0, 0))
        self.assertIsNone(session_record.start_time.tzinfo)
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_login_failed(self):
        """Test processing of login failure event."""
        session_record = Mock()
        session_record.credentials = Mock()
        session_record.source = Mock(login_attempts=0)
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2023-01-01T10:00:01",
            "username": "root",
            "password": "password123",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertTrue(session_record.login_attempt)
        self.mock_session_repo.add_credential.assert_called_once_with(session_record, "root", "password123")

    def test_process_session_hit_command_input(self):
        """Test processing of command input event."""
        session_record = Mock()
        session_record.commands = None
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.command.input",
            "timestamp": "2023-01-01T10:00:05",
            "message": "CMD: ls -la",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertTrue(session_record.command_execution)
        self.assertIsInstance(session_record.commands, CommandSequence)
        self.assertEqual(session_record.commands.first_seen, datetime(2023, 1, 1, 10, 0, 5))
        self.assertIsNone(session_record.commands.first_seen.tzinfo)
        self.assertEqual(session_record.commands.last_seen, datetime(2023, 1, 1, 10, 0, 5))
        self.assertIsNone(session_record.commands.last_seen.tzinfo)
        self.assertIn("ls -la", session_record.commands.commands)

    def test_process_session_hit_session_closed(self):
        """Test processing of session closed event."""
        session_record = Mock()
        session_record.interaction_count = 0
        hit = {
            "eventid": "cowrie.session.closed",
            "timestamp": "2023-01-01T10:00:10",
            "duration": 10.5,
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertEqual(session_record.duration, 10.5)

    def test_process_session_hit_file_download_creates_transfer(self):
        """Test processing of file download event creates file transfer."""
        session_record = Mock()
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.session.file_download",
            "timestamp": "2023-01-01T10:00:04",
            "shasum": "abc123def456",
            "url": "http://malware.com/bad.exe",
            "outfile": "/data/cowrie/downloads/bad.exe",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.mock_session_repo.get_or_create_file_transfer.assert_called_once_with(
            session=session_record,
            shasum="abc123def456",
            url="http://malware.com/bad.exe",
            outfile="/data/cowrie/downloads/bad.exe",
            timestamp=datetime(2023, 1, 1, 10, 0, 4),
        )
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_file_upload_creates_transfer(self):
        """Test processing of file upload event creates file transfer."""
        session_record = Mock()
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.session.file_upload",
            "timestamp": "2023-01-01T10:00:04",
            "shasum": "deadbeef123456",
            "filename": "malware.sh",
            "outfile": "/var/lib/cowrie/downloads/deadbeef123456",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.mock_session_repo.get_or_create_file_transfer.assert_called_once_with(
            session=session_record,
            shasum="deadbeef123456",
            url="",  # upload events do not contain URL
            outfile="/var/lib/cowrie/downloads/deadbeef123456",
            timestamp=datetime(2023, 1, 1, 10, 0, 4),
        )
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_file_upload_without_shasum(self):
        """Test file transfer is skipped when shasum is missing."""
        session_record = Mock()
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.session.file_upload",
            "timestamp": "2023-01-01T10:00:04",
            # no shasum
            "url": "http://attacker.com/upload.bin",
            "outfile": "/data/cowrie/uploads/upload.bin",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.mock_session_repo.get_or_create_file_transfer.assert_not_called()
        self.assertEqual(session_record.interaction_count, 1)

    def test_add_fks_both_exist(self):
        """Test linking IOCs when both exist."""
        scanner_mock = MagicMock()
        hostname_mock = MagicMock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, hostname_mock]

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner_mock.related_ioc.add.assert_called_once_with(hostname_mock)
        hostname_mock.related_ioc.add.assert_called_once_with(scanner_mock)
        self.assertEqual(self.mock_ioc_repo.save.call_count, 0)

    def test_add_fks_scanner_none(self):
        """Test linking when scanner IOC doesn't exist."""
        hostname_mock = MagicMock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [None, hostname_mock]

        self.strategy._add_fks("1.2.3.4", "evil.com")

        # Should not save anything (early return when either is None)
        self.mock_ioc_repo.save.assert_not_called()

    def test_deduplicate_command_sequence_new(self):
        """Test command sequence deduplication for new sequence."""
        session = Mock()
        session.commands = Mock()
        session.commands.commands = ["ls", "pwd", "whoami"]

        self.mock_session_repo.get_command_sequence_by_hash.return_value = None

        result = self.strategy._deduplicate_command_sequence(session)

        self.assertFalse(result)
        self.assertIsNotNone(session.commands.commands_hash)

    def test_deduplicate_command_sequence_existing(self):
        """Test command sequence deduplication for existing sequence."""
        session = Mock()
        session.commands = Mock()
        session.commands.commands = ["ls", "pwd", "whoami"]
        session.commands.last_seen = datetime(2023, 1, 1, 10, 0, 10)

        existing_cmd_seq = Mock()
        self.mock_session_repo.get_command_sequence_by_hash.return_value = existing_cmd_seq

        result = self.strategy._deduplicate_command_sequence(session)

        self.assertTrue(result)
        self.assertEqual(session.commands, existing_cmd_seq)
        self.assertIsInstance(session.commands.last_seen, datetime)
        self.assertIsNone(session.commands.last_seen.tzinfo)

    def test_start_time_is_naive_datetime_not_string(self):
        """Regression: parse_timestamp() must be called so that timezone-aware
        Elasticsearch strings are stripped to naive datetimes before .save().
        Without the fix, USE_TZ=False causes a ValueError on PostgreSQL."""
        session_record = Mock()
        session_record.interaction_count = 0
        hit = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2025-06-01T12:00:00.000000+00:00",
        }

        self.strategy._process_session_hit(session_record, hit, Mock())

        self.assertIsInstance(session_record.start_time, datetime)
        self.assertIsNone(session_record.start_time.tzinfo)

    @patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits")
    def test_extract_from_hits_integration(self, mock_iocs_from_hits):
        """Test the main extract_from_hits coordination."""
        mock_ioc = Mock(name="1.2.3.4")
        mock_ioc.related_urls = []
        # Return list of IOCs as expected by the new format
        mock_iocs_from_hits.return_value = [mock_ioc]

        mock_ioc_record = Mock()
        mock_ioc_record.payload_request = False
        self.strategy.ioc_processor.add_ioc.return_value = mock_ioc_record

        hits = [{"src_ip": "1.2.3.4", "session": "s1", "eventid": "cowrie.session.connect"}]

        with patch.object(self.strategy, "_get_sessions"), patch.object(self.strategy, "_extract_possible_payload_in_messages"):
            self.strategy.extract_from_hits(hits)

        # Verify scanner was processed with Cowrie as honeypot
        self.strategy.ioc_processor.add_ioc.assert_called()
        call_args = self.strategy.ioc_processor.add_ioc.call_args
        self.assertEqual(call_args.kwargs.get("honeypot_name"), "Cowrie")

    @patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits")
    def test_get_scanners_and_sessions(self, mock_iocs_from_hits):
        """Test _get_scanners and _get_sessions correctly group and route hits."""
        ioc1 = Mock()
        ioc1.name = "1.1.1.1"
        ioc1.related_urls = []
        ioc2 = Mock()
        ioc2.name = "2.2.2.2"
        ioc2.related_urls = []

        mock_iocs_from_hits.return_value = [ioc1, ioc2]

        hits = [
            {"src_ip": "1.1.1.1", "session": "s1", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:00:00"},
            {"src_ip": "1.1.1.1", "session": "s1", "eventid": "cowrie.session.closed", "timestamp": "2023-01-01T10:00:05"},
            {"src_ip": "2.2.2.2", "session": "s2", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:00:00"},
        ]

        mock_ioc_record1 = Mock()
        mock_ioc_record1.name = "1.1.1.1"
        mock_ioc_record2 = Mock()
        mock_ioc_record2.name = "2.2.2.2"
        self.strategy.ioc_processor.add_ioc.side_effect = [mock_ioc_record1, mock_ioc_record2]

        with patch.object(self.strategy, "_get_sessions") as mock_get_sessions:
            self.strategy._get_scanners(hits)

            mock_iocs_from_hits.assert_called_once_with(hits)
            self.assertEqual(mock_get_sessions.call_count, 2)
            # Verify the hits passed to _get_sessions are only those containing the matching src_ip
            calls = mock_get_sessions.call_args_list
            args_ioc1, args_ioc2 = calls[0][0], calls[1][0]

            self.assertEqual(args_ioc1[0], mock_ioc_record1)
            self.assertEqual(len(args_ioc1[1]), 2)
            self.assertTrue(all(h["src_ip"] == "1.1.1.1" for h in args_ioc1[1]))

            self.assertEqual(args_ioc2[0], mock_ioc_record2)
            self.assertEqual(len(args_ioc2[1]), 1)
            self.assertTrue(all(h["src_ip"] == "2.2.2.2" for h in args_ioc2[1]))

    def test_get_sessions_processes_hits(self):
        """Test _get_sessions iterates and processes session hits."""
        ioc = Mock()
        ioc.name = "1.1.1.1"

        hits = [
            {"src_ip": "1.1.1.1", "session": "s1", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:00:00"},
            {"src_ip": "1.1.1.1", "session": "s1", "eventid": "cowrie.session.closed", "timestamp": "2023-01-01T10:00:05"},
            {"src_ip": "1.1.1.1", "session": "s2", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:00:02"},
        ]

        session_s1 = Mock()
        session_s1.commands = None
        session_s2 = Mock()
        session_s2.commands = None
        self.mock_session_repo.get_or_create_session.side_effect = [session_s1, session_s2]

        with patch.object(self.strategy, "_process_session_hit") as mock_process_hit:
            self.strategy._get_sessions(ioc, hits)

            self.assertEqual(self.mock_session_repo.get_or_create_session.call_count, 2)
            self.assertEqual(mock_process_hit.call_count, 3)
