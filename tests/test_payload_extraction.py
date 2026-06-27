from unittest.mock import MagicMock, Mock, patch

import requests
from django.test import override_settings

from greedybear.cronjobs.payload_extraction import PayloadExtractionJob
from greedybear.models import HoneypotPayload

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

        self.job.run()

        # No payload should have been downloaded.
        self.assertEqual(HoneypotPayload.objects.count(), 0)

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
