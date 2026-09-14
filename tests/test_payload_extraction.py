from unittest.mock import MagicMock, Mock, patch

import requests
from django.test import override_settings
from django.utils import timezone

from greedybear.cronjobs.payload_extraction import PayloadExtractionJob
from greedybear.models import CowrieFileTransfer, HoneypotPayload

from . import CustomTestCase


class TestPayloadExtractionJob(CustomTestCase):
    """Tests for the PayloadExtractionJob cronjob."""

    def setUp(self):
        super().setUp()
        self.job = PayloadExtractionJob()

    @override_settings(TPOT_PAYLOAD_SERVER_URL="")
    def test_skips_when_url_not_configured(self):
        """Job should be a no-op when TPOT_PAYLOAD_SERVER_URL is empty."""
        self.job.run()
        # No exception, no payloads created.
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
    )
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_skips_when_no_payloads_returned(self, mock_http_class):
        """Job should exit cleanly when the server returns an empty list."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_response = Mock()
        mock_response.json.return_value = []
        mock_client.get.return_value = mock_response

        self.job.run()
        self.assertEqual(HoneypotPayload.objects.count(), 0)

        # Verify it hit the /recent endpoint with timestamps.
        call_args = mock_client.get.call_args
        self.assertIn("/api/v1/payloads/recent", call_args[0][0])
        self.assertIn("start_ts", call_args[1]["params"])
        self.assertIn("end_ts", call_args[1]["params"])

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_downloads_new_payload(self, mock_http_class, mock_usage):
        """Job should download and store a payload not yet in the database."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        # Payload metadata response
        payload_meta = {
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "sha1": "c" * 40,
            "mime_type": "application/octet-stream",
            "locator": "cowrie/aaa",
            "mtime": 1719000000.0,
        }
        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [payload_meta]

        # Download response
        mock_download_resp = Mock()
        mock_download_resp.content = b"\x00" * 256

        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0  # Under the limit.

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 1)
        obj = HoneypotPayload.objects.first()
        self.assertEqual(obj.sha256, "a" * 64)
        self.assertEqual(obj.md5, "b" * 32)
        self.assertEqual(obj.sha1, "c" * 40)
        self.assertEqual(obj.mime_type, "application/octet-stream")
        self.assertEqual(obj.size, 256)
        self.assertEqual(obj.locator, "cowrie/aaa")

        # Verify download hit the /download/ endpoint.
        download_call = mock_client.get.call_args_list[1]
        self.assertIn("/api/v1/payloads/download/cowrie/aaa", download_call[0][0])

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_download_without_matching_session(self, mock_http_class, mock_usage):
        """Job should not link a downloaded payload to any session when no matching transfer exists."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [{"sha256": "a" * 64, "locator": "cowrie/aaa"}]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\x00" * 256
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        # No CowrieFileTransfer was ever created for this hash, so nothing should link.
        obj = HoneypotPayload.objects.get(sha256="a" * 64)
        self.assertEqual(obj.cowrie_sessions.count(), 0)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_download_links_cowrie_session(self, mock_http_class, mock_usage):
        """Job should link a downloaded payload to a Cowrie session that already transferred the same file."""
        # Same hash as the payload metadata below - simulates Cowrie's extraction already
        # having recorded this transfer before the payload download runs.
        CowrieFileTransfer.objects.create(
            session=self.cowrie_session,
            shasum="a" * 64,
            url="",
            outfile="",
            timestamp=timezone.now(),
        )

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [{"sha256": "a" * 64, "locator": "cowrie/aaa"}]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\x00" * 256
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        obj = HoneypotPayload.objects.get(sha256="a" * 64)
        self.assertIn(self.cowrie_session, obj.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, obj.iocs.all())

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_deduplicates_existing_payloads(self, mock_http_class, mock_usage):
        """Job should skip payloads that already exist in the database."""
        # Pre-create a payload record.
        HoneypotPayload.objects.create(sha256="a" * 64)

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "a" * 64, "locator": "cowrie/aaa"},
        ]
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        # Only the one we pre-created, nothing new downloaded.
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        # get() was called only once (metadata request), no download request.
        self.assertEqual(mock_client.get.call_count, 1)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=0.001,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_stops_when_quarantine_limit_reached(self, mock_http_class, mock_usage):
        """Job should stop downloading when quarantine size limit is exceeded."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "d" * 64, "locator": "cowrie/ddd"},
        ]
        mock_client.get.return_value = mock_metadata_resp

        # Report disk usage above the limit (0.001 GB ~ 1,073,741 bytes).
        mock_usage.return_value = 2_000_000

        with patch.object(self.job.log, "error") as mock_error:
            self.job.run()

        mock_error.assert_called_once_with("Quarantine directory has reached the 0.001 GB limit. Stopping downloads.")
        # Only the metadata request was made, no download was attempted.
        self.assertEqual(mock_client.get.call_count, 1)
        # The payload is kept as metadata only so it is not lost with the window.
        obj = HoneypotPayload.objects.get(sha256="d" * 64)
        self.assertFalse(obj.payload_file)
        self.assertEqual(obj.locator, "cowrie/ddd")

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=0.001,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_stores_metadata_for_whole_remaining_batch(self, mock_http_class, mock_usage):
        """Every payload left undownloaded when the quota trips should be recorded."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "d" * 64, "locator": "cowrie/ddd", "md5": "d" * 32, "sha1": "d" * 40, "mime_type": "application/x-executable", "mtime": 1234.5},
            {"sha256": "e" * 64, "locator": "cowrie/eee"},
            {"sha256": "f" * 64, "locator": "cowrie/fff"},
        ]
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 2_000_000

        self.job.run()

        # All three are recorded, none downloaded. payload_file expresses "no file"
        # as both "" and NULL today, so check falsiness rather than one of the two.
        self.assertEqual(HoneypotPayload.objects.count(), 3)
        self.assertTrue(all(not p.payload_file for p in HoneypotPayload.objects.all()))
        # Metadata from the listing is carried over to the stub.
        obj = HoneypotPayload.objects.get(sha256="d" * 64)
        self.assertEqual(obj.md5, "d" * 32)
        self.assertEqual(obj.sha1, "d" * 40)
        self.assertEqual(obj.mime_type, "application/x-executable")
        self.assertEqual(obj.mtime, 1234.5)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=0.001,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_downloads_until_quota_then_stores_metadata(self, mock_http_class, mock_usage):
        """Payloads downloaded before the quota trips keep their file, the rest do not."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "a" * 64, "locator": "cowrie/aaa"},
            {"sha256": "b" * 64, "locator": "cowrie/bbb"},
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\x00" * 128
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]

        # Under the limit for the first payload, over it for the second.
        mock_usage.side_effect = [0, 2_000_000]

        self.job.run()

        downloaded = HoneypotPayload.objects.get(sha256="a" * 64)
        self.assertTrue(downloaded.payload_file)
        self.assertEqual(downloaded.size, 128)

        deferred = HoneypotPayload.objects.get(sha256="b" * 64)
        self.assertFalse(deferred.payload_file)
        self.assertEqual(deferred.locator, "cowrie/bbb")

    def test_metadata_only_skips_payload_without_locator(self):
        """A payload with no locator can never be fetched, so no row is written."""
        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": ""}])

        self.assertEqual(stored, 0)
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    def test_metadata_only_links_cowrie_session(self):
        """A payload recorded without its file still gets its session and IOC links."""
        CowrieFileTransfer.objects.create(
            session=self.cowrie_session,
            shasum="c" * 64,
            url="",
            outfile="",
            timestamp=timezone.now(),
        )

        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": "cowrie/ccc"}])

        self.assertEqual(stored, 1)
        obj = HoneypotPayload.objects.get(sha256="c" * 64)
        self.assertFalse(obj.payload_file)
        self.assertIn(self.cowrie_session, obj.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, obj.iocs.all())

    def test_metadata_only_links_existing_stub_to_session(self):
        """An existing hash-only stub picked up here is linked as well, not just new rows."""
        HoneypotPayload.objects.create(sha256="c" * 64)
        CowrieFileTransfer.objects.create(
            session=self.cowrie_session,
            shasum="c" * 64,
            url="",
            outfile="",
            timestamp=timezone.now(),
        )

        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": "cowrie/ccc"}])

        self.assertEqual(stored, 1)
        obj = HoneypotPayload.objects.get(sha256="c" * 64)
        self.assertIn(self.cowrie_session, obj.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, obj.iocs.all())

    def test_metadata_only_is_idempotent(self):
        """Recording the same payload twice should not create a duplicate row."""
        payloads = [{"sha256": "c" * 64, "locator": "cowrie/ccc"}]

        self.assertEqual(self.job._store_metadata_only(payloads), 1)
        self.assertEqual(self.job._store_metadata_only(payloads), 1)
        self.assertEqual(HoneypotPayload.objects.filter(sha256="c" * 64).count(), 1)

    def test_metadata_only_fills_locator_on_existing_stub(self):
        """A hash-only stub gets its locator filled in so it stays recoverable."""
        HoneypotPayload.objects.create(sha256="c" * 64)

        stored = self.job._store_metadata_only([{"sha256": "C" * 64, "locator": "cowrie/ccc"}])

        self.assertEqual(stored, 1)
        obj = HoneypotPayload.objects.get(sha256="c" * 64)
        self.assertEqual(obj.locator, "cowrie/ccc")

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_skips_payload_without_locator(self, mock_http_class, mock_usage):
        """Job should skip payloads that have no locator field."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "e" * 64, "locator": ""},
        ]
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="test-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_mixed_new_and_existing_payloads(self, mock_http_class, mock_usage):
        """Job should only download payloads not already in the database."""
        # Pre-create one payload.
        HoneypotPayload.objects.create(sha256="a" * 64)

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "a" * 64, "locator": "cowrie/aaa"},  # existing
            {"sha256": "f" * 64, "locator": "cowrie/fff", "md5": "1" * 32},  # new
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\xde\xad"

        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 2)
        new_obj = HoneypotPayload.objects.get(sha256="f" * 64)
        self.assertEqual(new_obj.size, 2)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="my-secret-key",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_sends_api_key_header(self, mock_http_class, mock_usage):
        """Job should send X-API-Key header when TPOT_PAYLOAD_SERVER_API_KEY is set."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = []
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        call_args = mock_client.get.call_args
        self.assertEqual(call_args[1]["headers"]["X-API-Key"], "my-secret-key")

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_no_api_key_sends_empty_headers(self, mock_http_class, mock_usage):
        """Job should not send X-API-Key when the key is not configured."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = []
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        call_args = mock_client.get.call_args
        self.assertNotIn("X-API-Key", call_args[1]["headers"])

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
    )
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_handles_network_error_on_metadata_fetch(self, mock_http_class):
        """Job should handle network errors when fetching metadata gracefully."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_client.get.side_effect = requests.ConnectionError("connection refused")

        self.job.run()

        # No crash, no payloads created.
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
    )
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_handles_invalid_json_response(self, mock_http_class):
        """Job should handle malformed JSON from the server gracefully."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_response = Mock()
        mock_response.json.side_effect = ValueError("No JSON object could be decoded")
        mock_client.get.return_value = mock_response

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_handles_download_failure(self, mock_http_class, mock_usage):
        """Job should handle download errors for individual payloads gracefully."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "a" * 64, "locator": "cowrie/aaa"},
        ]

        # First call returns metadata, second call (download) raises error.
        mock_client.get.side_effect = [
            mock_metadata_resp,
            requests.ConnectionError("download failed"),
        ]
        mock_usage.return_value = 0

        self.job.run()

        # Download failed, so no payload record should exist.
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(QUARANTINE_DIR="/tmp/test_quarantine_nonexistent_path")
    def test_quarantine_usage_returns_zero_for_missing_dir(self):
        """_quarantine_usage_bytes should return 0 if quarantine dir doesn't exist."""
        result = self.job._quarantine_usage_bytes()
        self.assertEqual(result, 0)

    # SHA256 case normalization (see issue #1556).
    # HoneypotPayload is unique on Lower("sha256"), so a hash that differs only
    # in case must be treated as a duplicate. Before the fix, the case-sensitive
    # lookup missed it, the insert went ahead and the unique constraint aborted
    # the whole run.

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_uppercase_hash_matches_existing_lowercase_row(self, mock_http_class, mock_usage):
        """An uppercase hash from the server must not re-insert a known payload."""
        HoneypotPayload.objects.create(sha256="a" * 64)

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "A" * 64, "locator": "cowrie/aaa"},
        ]
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        # Recognised as a duplicate: nothing inserted, no download attempted.
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        self.assertEqual(mock_client.get.call_count, 1)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_lowercase_hash_matches_existing_uppercase_row(self, mock_http_class, mock_usage):
        """Rows stored in upper case before the fix must still be matched."""
        HoneypotPayload.objects.create(sha256="B" * 64)

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "b" * 64, "locator": "cowrie/bbb"},
        ]
        mock_client.get.return_value = mock_metadata_resp
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 1)
        self.assertEqual(mock_client.get.call_count, 1)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_new_payload_is_stored_lower_cased(self, mock_http_class, mock_usage):
        """A new uppercase hash should be persisted in lower case."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "C" * 64, "locator": "cowrie/ccc"},
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\xde\xad"
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 1)
        payload = HoneypotPayload.objects.get()
        self.assertEqual(payload.sha256, "c" * 64)
        self.assertIn("c" * 64, payload.payload_file.name)

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_same_hash_in_different_cases_within_one_batch(self, mock_http_class, mock_usage):
        """Two entries differing only in case must collapse into a single insert."""
        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "d" * 64, "locator": "cowrie/ddd"},
            {"sha256": "D" * 64, "locator": "cowrie/DDD"},
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\xbe\xef"
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 1)
        self.assertEqual(HoneypotPayload.objects.get().sha256, "d" * 64)
        # One metadata request plus exactly one download.
        self.assertEqual(mock_client.get.call_count, 2)


class TestExtractAllPayloadIntegration(CustomTestCase):
    """Test that extract_all calls extract_honeypot_payloads."""

    @patch("greedybear.tasks.extract_honeypot_payloads")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    def test_extract_all_calls_payload_extraction(self, mock_datetime, mock_job, mock_payload_extract):
        """extract_all should always call extract_honeypot_payloads."""
        from datetime import datetime as real_datetime

        mock_datetime.now.return_value = real_datetime(2026, 1, 1, 10, 30)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_payload_extract.assert_called_once()

    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.tasks.extract_honeypot_payloads")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    @patch("greedybear.tasks.datetime")
    def test_extract_all_calls_both_at_midnight(self, mock_datetime, mock_job, mock_payload, mock_train):
        """At midnight, extract_all should call both train_and_update and extract_honeypot_payloads."""
        from datetime import datetime as real_datetime

        mock_datetime.now.return_value = real_datetime(2026, 1, 1, 0, 0)

        from greedybear.tasks import extract_all

        extract_all()

        mock_job().execute.assert_called_once()
        mock_train.assert_called_once()
        mock_payload.assert_called_once()


class TestExtractHoneypotPayloadsTask(CustomTestCase):
    """Test the extract_honeypot_payloads task wrapper."""

    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob.execute")
    def test_task_calls_execute(self, mock_execute):
        from greedybear.tasks import extract_honeypot_payloads

        extract_honeypot_payloads()
        mock_execute.assert_called_once()
