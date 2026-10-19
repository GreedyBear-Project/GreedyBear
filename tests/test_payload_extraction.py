import hashlib
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import urlsplit

import requests
from django.test import override_settings
from django.utils import timezone

from greedybear.cronjobs.payload_extraction import PayloadExtractionJob, PayloadSource
from greedybear.cronjobs.repositories import PayloadRepository
from greedybear.models import CowrieFileTransfer, HoneypotPayload, PayloadObservation, Sensor

from . import CustomTestCase, make_api_source, make_sensor


class TestPayloadExtractionJob(CustomTestCase):
    """Tests for the PayloadExtractionJob cronjob."""

    def setUp(self):
        super().setUp()
        self.job = PayloadExtractionJob()
        # The server configured through the legacy TPOT_PAYLOAD_SERVER_URL setting.
        self.legacy_source = PayloadSource(url="http://payload-server:8000")

    def _locator(self, sha256):
        """Return the locator the legacy payload server reported for this hash."""
        return PayloadObservation.objects.get(payload__sha256=sha256, sensor=None).locator

    @override_settings(TPOT_PAYLOAD_SERVER_URL="")
    def test_skips_when_url_not_configured(self):
        """Job should be a no-op when TPOT_PAYLOAD_SERVER_URL is empty."""
        self.job.run()
        # No exception, no payloads created.
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    @override_settings(EXTRACTION_INTERVAL=10)
    @patch("greedybear.cronjobs.payload_extraction.datetime")
    def test_fetch_metadata_uses_aligned_time_window(self, mock_datetime):
        """Metadata lookup should use the last completed extraction interval."""
        reference_time = datetime(2026, 1, 1, 8, 12, 37)
        mock_datetime.now.return_value = reference_time
        client = MagicMock()
        client.get.return_value.json.return_value = []

        self.job._fetch_metadata(client, self.legacy_source, self.job._extraction_window())

        params = client.get.call_args.kwargs["params"]
        self.assertEqual(params["start_ts"], datetime(2026, 1, 1, 8, 0).timestamp())
        self.assertEqual(params["end_ts"], datetime(2026, 1, 1, 8, 10).timestamp())

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
        observation = PayloadObservation.objects.get(payload=obj)
        self.assertIsNone(observation.sensor)
        self.assertEqual(observation.locator, "cowrie/aaa")
        self.assertEqual(observation.mtime, 1719000000.0)

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
        # payload_file must be set for a HoneypotPayload to be considered "existing".
        HoneypotPayload.objects.create(sha256="a" * 64, payload_file="existing.vir")

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
        self.assertEqual(self._locator("d" * 64), "cowrie/ddd")

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
        self.assertEqual(PayloadObservation.objects.get(payload=obj).mtime, 1234.5)

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
        self.assertEqual(self._locator("b" * 64), "cowrie/bbb")

    def test_metadata_only_skips_payload_without_locator(self):
        """A payload with no locator can never be fetched, so no row is written."""
        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": ""}], self.legacy_source)

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

        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": "cowrie/ccc"}], self.legacy_source)

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

        stored = self.job._store_metadata_only([{"sha256": "c" * 64, "locator": "cowrie/ccc"}], self.legacy_source)

        self.assertEqual(stored, 1)
        obj = HoneypotPayload.objects.get(sha256="c" * 64)
        self.assertIn(self.cowrie_session, obj.cowrie_sessions.all())
        self.assertIn(self.cowrie_session.source, obj.iocs.all())

    def test_metadata_only_is_idempotent(self):
        """Recording the same payload twice should not create a duplicate row."""
        payloads = [{"sha256": "c" * 64, "locator": "cowrie/ccc"}]

        self.assertEqual(self.job._store_metadata_only(payloads, self.legacy_source), 1)
        self.assertEqual(self.job._store_metadata_only(payloads, self.legacy_source), 1)
        self.assertEqual(HoneypotPayload.objects.filter(sha256="c" * 64).count(), 1)
        self.assertEqual(PayloadObservation.objects.filter(payload__sha256="c" * 64).count(), 1)

    def test_metadata_only_fills_locator_on_existing_stub(self):
        """A hash-only stub gets its locator filled in so it stays recoverable."""
        HoneypotPayload.objects.create(sha256="c" * 64)

        stored = self.job._store_metadata_only([{"sha256": "C" * 64, "locator": "cowrie/ccc"}], self.legacy_source)

        self.assertEqual(stored, 1)
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        self.assertEqual(self._locator("c" * 64), "cowrie/ccc")

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
        # payload_file must be set for a HoneypotPayload to be considered "existing".
        HoneypotPayload.objects.create(sha256="a" * 64, payload_file="existing.vir")

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
        HoneypotPayload.objects.create(sha256="a" * 64, payload_file="existing.vir")

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
        HoneypotPayload.objects.create(sha256="B" * 64, payload_file="existing.vir")

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

    # Stub-aware deduplication (see issue #1530).
    # A HoneypotPayload row can exist without a file - a metadata-only stub
    # created from a raw event before the file itself was ever downloaded.
    # Such a row must not block the real download, and downloading it must
    # upgrade the existing row rather than fail on the unique sha256 constraint.

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_hash_only_stub_is_not_treated_as_duplicate(self, mock_http_class, mock_usage):
        """A stub row with no payload_file must still be downloaded, not skipped."""
        stub = HoneypotPayload.objects.create(sha256="e" * 64)
        stub.refresh_from_db()
        self.assertEqual(stub.payload_file.name, "")

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "e" * 64, "locator": "cowrie/eee"},
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\xca\xfe"
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        # Metadata fetch plus a real download attempt, not skipped as a duplicate.
        self.assertEqual(mock_client.get.call_count, 2)
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        payload = HoneypotPayload.objects.get()
        self.assertNotEqual(payload.payload_file, "")

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_downloading_a_stub_upgrades_the_same_row(self, mock_http_class, mock_usage):
        """Downloading a known stub must update its row, not raise IntegrityError."""
        stub = HoneypotPayload.objects.create(sha256="f" * 64, md5="", mime_type="")

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "f" * 64, "locator": "cowrie/fff", "md5": "1" * 32, "mime_type": "application/x-elf"},
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\xfe\xed\xfa\xce"
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        # No IntegrityError, and the existing row was upgraded rather than duplicated.
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        stub.refresh_from_db()
        self.assertEqual(stub.md5, "1" * 32)
        self.assertEqual(stub.mime_type, "application/x-elf")
        self.assertEqual(stub.size, len(b"\xfe\xed\xfa\xce"))
        self.assertNotEqual(stub.payload_file, "")

    @override_settings(
        TPOT_PAYLOAD_SERVER_URL="http://payload-server:8000",
        TPOT_PAYLOAD_SERVER_API_KEY="",
        MAX_QUARANTINE_SIZE_GB=5,
    )
    @patch("greedybear.cronjobs.payload_extraction.PayloadExtractionJob._quarantine_usage_bytes")
    @patch("greedybear.cronjobs.payload_extraction.HttpClient")
    def test_upgrading_a_stub_keeps_fields_missing_from_the_response(self, mock_http_class, mock_usage):
        """A field already on the stub must survive an upgrade where the response omits it."""
        stub = HoneypotPayload.objects.create(sha256="h" * 64, md5="c" * 32)

        mock_client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)

        mock_metadata_resp = Mock()
        mock_metadata_resp.json.return_value = [
            {"sha256": "h" * 64, "locator": "cowrie/hhh"},  # no md5 this time
        ]
        mock_download_resp = Mock()
        mock_download_resp.content = b"\x01\x02\x03"
        mock_client.get.side_effect = [mock_metadata_resp, mock_download_resp]
        mock_usage.return_value = 0

        self.job.run()

        self.assertEqual(HoneypotPayload.objects.count(), 1)
        stub.refresh_from_db()
        # md5 wasn't in the response, so the existing value must be kept, not blanked.
        self.assertEqual(stub.md5, "c" * 32)
        # size/locator are always known from this download, so they still update.
        self.assertEqual(stub.size, len(b"\x01\x02\x03"))
        self.assertEqual(self._locator("h" * 64), "cowrie/hhh")


SENSOR_A = "198.51.100.10"
SENSOR_B = "198.51.100.20"
SERVER_A = "https://tpot-a.example:64445"
SERVER_B = "https://tpot-b.example:64445"
# Benign stand-ins for captured binaries.
ONLY_A = b"captured only by sensor A"
ONLY_B = b"captured only by sensor B"
SHARED = b"captured by both sensors"


def sha256_of(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class FakePayloadServer:
    """
    In-memory tpot-payload-server, answering the GET requests the job sends.

    It lists every file it holds on /recent, serves them on /download and
    rejects requests without its API key, like the real server does.
    """

    def __init__(self, api_key: str, files: dict[str, bytes]):
        self.api_key = api_key
        self.files = files
        # Raised by /recent instead of answering, to simulate an unreachable server.
        self.recent_error = None
        # Returned by /recent instead of the listing, to simulate a malformed response.
        self.recent_body = None
        self.recent_params = []
        self.downloads = []

    def listing(self) -> list[dict]:
        return [
            {
                "locator": locator,
                "mime_type": "text/plain",
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "sha256": sha256_of(content),
                "mtime": 1719000000.0,
                "size": len(content),
                "source_honeypot": locator.split("/")[0],
            }
            for locator, content in self.files.items()
        ]

    def get(self, path: str, headers: dict, params: dict | None = None) -> Mock:
        if self.api_key and headers.get("X-API-Key") != self.api_key:
            raise requests.HTTPError("403 Client Error: Forbidden")
        response = Mock()
        if path == "/api/v1/payloads/recent":
            self.recent_params.append(params)
            if self.recent_error is not None:
                raise self.recent_error
            response.json.return_value = self.listing() if self.recent_body is None else self.recent_body
            return response
        locator = path.removeprefix("/api/v1/payloads/download/")
        self.downloads.append(locator)
        response.content = self.files[locator]
        return response


class TestMultiSourcePayloadExtraction(CustomTestCase):
    """Tests for fetching payloads from several payload servers, one per T-Pot sensor (issue #1511)."""

    def setUp(self):
        super().setUp()
        self.server_a = FakePayloadServer("key-a", {"cowrie/downloads/only-a": ONLY_A, "cowrie/downloads/shared": SHARED})
        self.server_b = FakePayloadServer("key-b", {"cowrie/downloads/only-b": ONLY_B, "dionaea/binaries/shared": SHARED})
        self.servers = {SERVER_A: self.server_a, SERVER_B: self.server_b}

        http_patcher = patch("greedybear.cronjobs.payload_extraction.HttpClient")
        mock_http_class = http_patcher.start()
        self.addCleanup(http_patcher.stop)
        self.client = MagicMock()
        mock_http_class.return_value.__enter__ = Mock(return_value=self.client)
        mock_http_class.return_value.__exit__ = Mock(return_value=False)
        self.client.get.side_effect = self._route

        usage_patcher = patch.object(PayloadExtractionJob, "_quarantine_usage_bytes", return_value=0)
        self.mock_usage = usage_patcher.start()
        self.addCleanup(usage_patcher.stop)

    def _route(self, url, headers=None, params=None, **kwargs):
        parts = urlsplit(url)
        server = self.servers.get(f"{parts.scheme}://{parts.netloc}")
        if server is None:
            raise requests.ConnectionError(f"no route to {url}")
        return server.get(parts.path, headers or {}, params)

    def _config(self, *servers: str) -> list[dict]:
        entries = {
            SERVER_A: {"url": SERVER_A, "api_key": "key-a", "sensor": SENSOR_A},
            SERVER_B: {"url": SERVER_B, "api_key": "key-b", "sensor": SENSOR_B},
        }
        return [entries[server] for server in servers or (SERVER_A, SERVER_B)]

    def _run(self, config: list | None = None, legacy_url: str = "") -> None:
        with override_settings(
            TPOT_PAYLOAD_SERVERS=self._config() if config is None else config,
            TPOT_PAYLOAD_SERVER_URL=legacy_url,
            TPOT_PAYLOAD_SERVER_API_KEY="",
            MAX_QUARANTINE_SIZE_GB=5,
        ):
            PayloadExtractionJob().run()

    def _sensors(self, content: bytes) -> list[str | None]:
        """Addresses of the sensors that observed this content, sorted."""
        return sorted(
            PayloadObservation.objects.filter(payload__sha256=sha256_of(content)).values_list("sensor__address", flat=True),
            key=str,
        )

    def _locator(self, content: bytes, sensor_address: str) -> str:
        return PayloadObservation.objects.get(payload__sha256=sha256_of(content), sensor__address=sensor_address).locator

    def _assert_fleet_extracted(self):
        """Both sensors' payloads are stored once, each with the sensors that reported it."""
        self.assertEqual(HoneypotPayload.objects.count(), 3)
        self.assertEqual(PayloadObservation.objects.count(), 4)
        self.assertEqual(self._sensors(ONLY_A), [SENSOR_A])
        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_A, SENSOR_B])
        self.assertTrue(all(payload.payload_file for payload in HoneypotPayload.objects.all()))

    def test_two_sources_both_succeed(self):
        self._run()

        self._assert_fleet_extracted()
        # The shared binary is stored once and downloaded only from the first server.
        self.assertEqual(HoneypotPayload.objects.filter(sha256=sha256_of(SHARED)).count(), 1)
        self.assertCountEqual(self.server_a.downloads, ["cowrie/downloads/only-a", "cowrie/downloads/shared"])
        self.assertEqual(self.server_b.downloads, ["cowrie/downloads/only-b"])
        shared = HoneypotPayload.objects.get(sha256=sha256_of(SHARED))
        self.assertEqual(shared.size, len(SHARED))
        self.assertEqual(shared.md5, hashlib.md5(SHARED).hexdigest())

    def test_unique_payloads_are_attributed_to_their_own_sensor(self):
        self._run()

        only_a = HoneypotPayload.objects.get(sha256=sha256_of(ONLY_A))
        only_b = HoneypotPayload.objects.get(sha256=sha256_of(ONLY_B))
        self.assertEqual([s.address for s in only_a.sensors.all()], [SENSOR_A])
        self.assertEqual([s.address for s in only_b.sensors.all()], [SENSOR_B])

    def test_shared_payload_keeps_each_sensors_locator(self):
        self._run()

        self.assertEqual(self._locator(SHARED, SENSOR_A), "cowrie/downloads/shared")
        self.assertEqual(self._locator(SHARED, SENSOR_B), "dionaea/binaries/shared")

    def test_source_order_does_not_matter(self):
        self._run(self._config(SERVER_B, SERVER_A))

        self._assert_fleet_extracted()
        self.assertEqual(self._locator(SHARED, SENSOR_A), "cowrie/downloads/shared")
        self.assertEqual(self._locator(SHARED, SENSOR_B), "dionaea/binaries/shared")
        # Now the shared binary is downloaded from B, which comes first, and only from it.
        self.assertCountEqual(self.server_b.downloads, ["cowrie/downloads/only-b", "dionaea/binaries/shared"])
        self.assertEqual(self.server_a.downloads, ["cowrie/downloads/only-a"])

    def test_repeated_runs_are_idempotent(self):
        for _ in range(3):
            self._run()

        self._assert_fleet_extracted()
        # Nothing is downloaded again after the first run.
        self.assertEqual(len(self.server_a.downloads) + len(self.server_b.downloads), 3)

    def test_each_source_uses_its_own_api_key(self):
        self._run()

        for call in self.client.get.call_args_list:
            url, headers = call.args[0], call.kwargs["headers"]
            expected_key = "key-a" if urlsplit(url).hostname == urlsplit(SERVER_A).hostname else "key-b"
            self.assertEqual(headers, {"X-API-Key": expected_key})

    def test_wrong_api_key_for_one_source_does_not_affect_the_other(self):
        # B's key was rotated on the server but not in GreedyBear yet.
        self.server_b.api_key = "rotated-key"

        self._run()

        self.assertEqual(self._sensors(ONLY_A), [SENSOR_A])
        self.assertEqual(self._sensors(SHARED), [SENSOR_A])
        self.assertFalse(HoneypotPayload.objects.filter(sha256=sha256_of(ONLY_B)).exists())

        # Once the key matches again, B's payloads come in as usual.
        self.server_b.api_key = "key-b"
        self._run()
        self._assert_fleet_extracted()

    def test_source_b_unavailable_then_recovers(self):
        self.server_b.recent_error = requests.ConnectionError("connection refused")

        self._run()

        self.assertEqual(HoneypotPayload.objects.count(), 2)
        self.assertEqual(self._sensors(ONLY_A), [SENSOR_A])
        self.assertEqual(self._sensors(SHARED), [SENSOR_A])

        self.server_b.recent_error = None
        self._run()

        self._assert_fleet_extracted()
        # The shared binary was already downloaded from A, so B only adds its observation.
        self.assertEqual(self.server_b.downloads, ["cowrie/downloads/only-b"])

    def test_source_a_unavailable_does_not_stop_source_b(self):
        self.server_a.recent_error = requests.Timeout("read timed out")

        self._run()

        self.assertEqual(HoneypotPayload.objects.count(), 2)
        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_B])
        self.assertFalse(HoneypotPayload.objects.filter(sha256=sha256_of(ONLY_A)).exists())

    def test_unreachable_host_does_not_stop_the_other_source(self):
        config = [{"url": "https://unreachable.example:64445", "api_key": "key-x", "sensor": "198.51.100.99"}, *self._config(SERVER_B)]

        self._run(config)

        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_B])

    def test_malformed_response_from_one_source_does_not_affect_the_other(self):
        self.server_a.recent_body = {"detail": "Internal Server Error"}

        self._run()

        self.assertFalse(HoneypotPayload.objects.filter(sha256=sha256_of(ONLY_A)).exists())
        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_B])

    def test_garbage_entries_from_one_source_do_not_affect_the_other(self):
        self.server_a.recent_body = [42, "x", None]

        with self.assertLogs("greedybear.cronjobs.base.PayloadExtractionJob", level="ERROR") as logs:
            self._run()

        # The broken server is reported in the error log, the run itself does not fail.
        self.assertIn(f"Payload extraction from {SERVER_A} (sensor {SENSOR_A}) failed", "\n".join(logs.output))
        self.assertFalse(HoneypotPayload.objects.filter(sha256=sha256_of(ONLY_A)).exists())
        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_B])

    def test_invalid_json_from_one_source_does_not_affect_the_other(self):
        self.servers[SERVER_A] = Mock(get=Mock(return_value=Mock(json=Mock(side_effect=ValueError("Expecting value")))))

        self._run()

        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])
        self.assertEqual(self._sensors(SHARED), [SENSOR_B])

    def test_entries_without_sha256_are_skipped(self):
        self.server_b.recent_body = [{"locator": "cowrie/downloads/z"}, *self.server_b.listing()]

        self._run()

        self._assert_fleet_extracted()

    def test_unexpected_error_in_one_source_does_not_stop_the_next(self):
        record_observations = PayloadRepository.record_observations

        def fail_for_sensor_b(repo, observations):
            if any(observation.sensor.address == SENSOR_B for observation in observations):
                raise RuntimeError("unexpected failure")
            return record_observations(repo, observations)

        with (
            patch.object(PayloadRepository, "record_observations", autospec=True, side_effect=fail_for_sensor_b),
            self.assertLogs("greedybear.cronjobs.base.PayloadExtractionJob", level="ERROR") as logs,
        ):
            # B comes first and fails, A must still be processed.
            self._run(self._config(SERVER_B, SERVER_A))

        self.assertEqual(self._sensors(ONLY_A), [SENSOR_A])
        self.assertEqual(self._sensors(SHARED), [SENSOR_A])
        self.assertIn(f"Payload extraction from {SERVER_B} (sensor {SENSOR_B}) failed, continuing", "\n".join(logs.output))

    def test_run_fails_when_every_source_fails(self):
        self.server_a.recent_body = [42]
        self.server_b.recent_body = [None]

        with self.assertRaisesMessage(RuntimeError, "Payload extraction failed for all 2 payload server(s)."):
            self._run()

        self.assertEqual(HoneypotPayload.objects.count(), 0)

    def test_legacy_source_failing_fails_the_run(self):
        # With a single server nothing worked, so the run fails like it always did.
        self.server_a.recent_body = [42]

        with (
            override_settings(TPOT_PAYLOAD_SERVERS=[], TPOT_PAYLOAD_SERVER_URL=SERVER_A, TPOT_PAYLOAD_SERVER_API_KEY="key-a", MAX_QUARANTINE_SIZE_GB=5),
            self.assertRaisesMessage(RuntimeError, "Payload extraction failed for all 1 payload server(s)."),
        ):
            PayloadExtractionJob().run()

    def test_unreachable_sources_do_not_fail_the_run(self):
        # Network errors are expected and handled per server, as for the single server before.
        self.server_a.recent_error = requests.ConnectionError("connection refused")
        self.server_b.recent_error = requests.Timeout("read timed out")

        self._run()

        self.assertEqual(HoneypotPayload.objects.count(), 0)

    def test_hash_case_differs_between_sources(self):
        self.server_a.recent_body = [{**entry, "sha256": entry["sha256"].upper()} for entry in self.server_a.listing()]

        self._run()

        self._assert_fleet_extracted()
        self.assertEqual(HoneypotPayload.objects.filter(sha256=sha256_of(SHARED)).count(), 1)
        self.assertEqual(self.server_b.downloads, ["cowrie/downloads/only-b"])

    def test_quota_reached_records_every_sensors_observation(self):
        self.mock_usage.return_value = 10 * 1024**3

        self._run()

        self.assertEqual(HoneypotPayload.objects.count(), 3)
        self.assertFalse(any(payload.payload_file for payload in HoneypotPayload.objects.all()))
        self.assertEqual(self.server_a.downloads + self.server_b.downloads, [])
        self.assertEqual(self._sensors(SHARED), [SENSOR_A, SENSOR_B])
        self.assertEqual(self._locator(SHARED, SENSOR_B), "dionaea/binaries/shared")

        # Once there is space again, every metadata-only row is upgraded in place.
        self.mock_usage.return_value = 0
        self._run()

        self._assert_fleet_extracted()
        self.assertEqual(len(self.server_a.downloads) + len(self.server_b.downloads), 3)

    def test_hash_only_stub_is_upgraded_and_observed(self):
        stub, _ = PayloadRepository().get_or_create_stub(sha256_of(SHARED))
        stub.iocs.add(self.ioc)

        self._run()

        self._assert_fleet_extracted()
        shared = HoneypotPayload.objects.get(sha256=sha256_of(SHARED))
        self.assertEqual(shared.pk, stub.pk)
        self.assertIn(self.ioc, shared.iocs.all())

    def test_shared_payload_is_linked_to_cowrie_session_and_ioc(self):
        CowrieFileTransfer.objects.create(session=self.cowrie_session, shasum=sha256_of(SHARED), url="", outfile="", timestamp=timezone.now())

        self._run()

        shared = HoneypotPayload.objects.get(sha256=sha256_of(SHARED))
        self.assertEqual(list(shared.cowrie_sessions.all()), [self.cowrie_session])
        self.assertEqual(list(shared.iocs.all()), [self.cowrie_session.source])
        self.assertEqual(HoneypotPayload.objects.get(sha256=sha256_of(ONLY_A)).cowrie_sessions.count(), 0)

    @override_settings(EXTRACTION_INTERVAL=10)
    @patch("greedybear.cronjobs.payload_extraction.datetime")
    def test_all_sources_are_queried_for_the_same_window(self, mock_datetime):
        # Should the clock be read again for the second server, it would already
        # be in the next interval and ask for a different window.
        mock_datetime.now.side_effect = [datetime(2026, 1, 1, 8, 9, 59), datetime(2026, 1, 1, 8, 10, 1)]

        self._run()

        expected = {"start_ts": datetime(2026, 1, 1, 7, 50).timestamp(), "end_ts": datetime(2026, 1, 1, 8, 0).timestamp()}
        self.assertEqual(self.server_a.recent_params, [expected])
        self.assertEqual(self.server_b.recent_params, [expected])

    def test_existing_sensor_is_reused(self):
        sensor = Sensor.objects.create(address=SENSOR_A, label="tpot-a")

        self._run()

        self.assertEqual(Sensor.objects.filter(address=SENSOR_A).count(), 1)
        shared = HoneypotPayload.objects.get(sha256=sha256_of(SHARED))
        self.assertIn(sensor, shared.sensors.all())

    def test_payloads_are_never_linked_to_an_event_collector_sensor(self):
        # An Event Collector user registered a sensor with the same address as T-Pot A.
        user_sensor = make_sensor(make_api_source(self.regular_user), address=SENSOR_A, label="user-sensor")

        self._run()

        observation = PayloadObservation.objects.get(payload__sha256=sha256_of(ONLY_A))
        self.assertIsNone(observation.sensor.api_source)
        self.assertNotEqual(observation.sensor.pk, user_sensor.pk)
        self.assertFalse(user_sensor.payload_observations.exists())

    def test_source_with_invalid_sensor_address_is_skipped(self):
        config = [{"url": SERVER_A, "api_key": "key-a", "sensor": "not-an-ip"}, *self._config(SERVER_B)]

        with self.assertLogs("greedybear.cronjobs.base.PayloadExtractionJob", level="ERROR") as logs:
            self._run(config)

        self.assertEqual(len(logs.output), 1)
        self.assertEqual(self.server_a.recent_params, [])
        self.assertEqual(self._sensors(ONLY_B), [SENSOR_B])

    def test_api_key_is_optional(self):
        self.server_a.api_key = ""

        self._run([{"url": SERVER_A, "sensor": SENSOR_A}])

        self.assertEqual(self._sensors(ONLY_A), [SENSOR_A])
        self.assertEqual(self.client.get.call_args_list[0].kwargs["headers"], {})

    def test_new_setting_takes_precedence_over_legacy_setting(self):
        with self.assertLogs("greedybear.cronjobs.base.PayloadExtractionJob", level="WARNING") as logs:
            self._run(legacy_url="https://legacy.example:64445")

        self._assert_fleet_extracted()
        called_hosts = {urlsplit(call.args[0]).hostname for call in self.client.get.call_args_list}
        self.assertNotIn("legacy.example", called_hosts)
        self.assertIn("ignoring TPOT_PAYLOAD_SERVER_URL", "\n".join(logs.output))

    def test_legacy_setting_records_observations_without_sensor(self):
        with override_settings(TPOT_PAYLOAD_SERVERS=[], TPOT_PAYLOAD_SERVER_URL=SERVER_A, TPOT_PAYLOAD_SERVER_API_KEY="key-a", MAX_QUARANTINE_SIZE_GB=5):
            PayloadExtractionJob().run()

        self.assertEqual(HoneypotPayload.objects.count(), 2)
        self.assertEqual(self._sensors(ONLY_A), [None])
        self.assertEqual(self._sensors(SHARED), [None])
        self.assertEqual(HoneypotPayload.objects.get(sha256=sha256_of(SHARED)).sensors.count(), 0)

    def test_api_keys_are_never_logged(self):
        self.server_a.recent_error = requests.ConnectionError("connection refused")
        self.server_b.api_key = "rotated-key"

        with self.assertLogs(level="DEBUG") as logs:
            self._run()

        output = "\n".join(logs.output)
        self.assertIn("tpot-a.example:64445", output)
        self.assertIn("tpot-b.example:64445", output)
        for secret in ("key-a", "key-b"):
            self.assertNotIn(secret, output)

    def test_payload_source_never_shows_its_api_key(self):
        source = PayloadSource(url=SERVER_A, api_key="key-a", sensor=Sensor(address=SENSOR_A))

        self.assertEqual(str(source), f"{SERVER_A} (sensor {SENSOR_A})")
        self.assertNotIn("key-a", repr(source))
        self.assertEqual(str(PayloadSource(url="http://payload-server:8000")), "http://payload-server:8000")


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
