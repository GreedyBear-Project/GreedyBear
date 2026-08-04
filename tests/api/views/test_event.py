import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import EventStatus, EventStatusType, RawEvent
from tests import CustomTestCase, make_api_source, make_sensor, make_user

User = get_user_model()

EVENTS_URL = "/api/events/add/"
STATUS_URL = "/api/events/status/{task_id}/"


def auth_client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def valid_event(sensor_id, **overrides):
    base = {
        "src_ip": "1.2.3.4",
        "event_type": "login_attempt",
        "timestamp": (timezone.now() - timezone.timedelta(seconds=10)).isoformat(),
        "sensor_id": sensor_id,
    }
    base.update(overrides)
    return base


class BaseEventTestCase(CustomTestCase):
    def setUp(self):
        self.user = make_user()
        self.api_source = make_api_source(self.user)
        self.sensor = make_sensor(api_source=self.api_source)
        self.client = auth_client(self.user)


class TestEventsCreateAuth(BaseEventTestCase):
    def test_unauthenticated_returns_401(self):
        anon = APIClient()
        res = anon.post(EVENTS_URL, {"events": []}, format="json")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_api_source_returns_403(self):
        user2 = make_user(username="noapi")
        client2 = auth_client(user2)
        payload = {"events": [valid_event(self.sensor.id)]}
        res = client2.post(EVENTS_URL, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("APISource", res.data["error"])

    def test_locked_api_source_returns_403(self):
        self.api_source.is_active = False
        self.api_source.save()
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("locked", res.data["error"])


class TestEventsCreateValidation(BaseEventTestCase):
    def test_empty_events_list_returns_400(self):
        res = self.client.post(EVENTS_URL, {"events": []}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_events_key_returns_400(self):
        res = self.client.post(EVENTS_URL, {}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_required_src_ip_returns_400(self):
        event = valid_event(self.sensor.id)
        del event["src_ip"]
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("src_ip", str(res.data))

    def test_missing_required_event_type_returns_400(self):
        event = valid_event(self.sensor.id)
        del event["event_type"]
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_required_timestamp_returns_400(self):
        event = valid_event(self.sensor.id)
        del event["timestamp"]
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_required_sensor_id_returns_400(self):
        event = valid_event(self.sensor.id)
        del event["sensor_id"]
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_ip_returns_400(self):
        event = valid_event(self.sensor.id, src_ip="not-an-ip")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_future_timestamp_returns_400(self):
        future_ts = (timezone.now() + timezone.timedelta(hours=1)).isoformat()
        event = valid_event(self.sensor.id, timestamp=future_ts)
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("future", str(res.data).lower())

    def test_src_port_out_of_range_returns_400(self):
        event = valid_event(self.sensor.id, src_port=99999)
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dest_port_out_of_range_returns_400(self):
        event = valid_event(self.sensor.id, dest_port=0)
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_event_count_incremented_on_bad_payload(self):
        before = self.api_source.invalid_event_count
        event = valid_event(self.sensor.id, src_ip="bad-ip")
        self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.api_source.refresh_from_db()
        self.assertEqual(self.api_source.invalid_event_count, before + 1)

    def test_exceeding_max_batch_size_returns_400(self):
        # Sending 10 001 events should fail InjectionSerializer's max_length
        events = [valid_event(self.sensor.id) for _ in range(10_001)]
        res = self.client.post(EVENTS_URL, {"events": events}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_events_root_must_be_dict(self):
        res = self.client.post(EVENTS_URL, [], format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_timestamp_now_is_accepted(self):
        now_ts = timezone.now().isoformat()
        event = valid_event(self.sensor.id, timestamp=now_ts)

        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

    def test_sensor_from_other_api_source_is_rejected(self):
        other_user = make_user(username="other2")
        other_api = make_api_source(other_user, name="OtherUniqueSource")
        other_sensor = make_sensor(api_source=other_api)

        event = valid_event(other_sensor.id)

        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_payload_hash_uppercase_normalized_to_lowercase(self):
        event = valid_event(self.sensor.id, payload_hash="A" * 64)
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.payload_hash, "a" * 64)

    def test_payload_hash_wrong_length_returns_400(self):
        event = valid_event(self.sensor.id, payload_hash="tooshort")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_protocol_normalized_to_lowercase(self):
        event = valid_event(self.sensor.id, protocol="SSH")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.protocol, "ssh")

    def test_protocol_stripped_of_whitespace(self):
        event = valid_event(self.sensor.id, protocol="  ssh  ")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.protocol, "ssh")

    def test_cve_id_normalized_to_uppercase(self):
        event = valid_event(self.sensor.id, cve_id="cve-2021-44228")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.cve_id, "CVE-2021-44228")

    def test_cve_id_invalid_format_returns_400(self):
        event = valid_event(self.sensor.id, cve_id="INVALID-FORMAT")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cve_id_empty_string_accepted(self):
        """Empty cve_id is optional — must not be validated against the CVE regex."""
        event = valid_event(self.sensor.id, cve_id="")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)


class TestEventsCreateSuccess(BaseEventTestCase):
    @patch("api.views.event.async_task", return_value="task-abc-123")
    def test_single_valid_event_returns_202(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

    @patch("api.views.event.async_task", return_value="task-abc-123")
    def test_response_contains_required_fields(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")
        for key in ("message", "task_id", "status_url"):
            self.assertIn(key, res.data)

    @patch("api.views.event.async_task", return_value="task-uuid")
    def test_task_id_returned_verbatim_as_hex_string(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

        batch = EventStatus.objects.get()
        self.assertIsInstance(res.data["task_id"], str)
        self.assertEqual(res.data["task_id"], batch.task_id)
        self.assertRegex(res.data["task_id"], r"^[0-9a-f]{32}$")

    @patch("api.views.event.async_task", return_value="task-xyz")
    def test_status_url_contains_task_id(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")

        # Verify that the status_url contains the correct lookup identifier returned in the response
        expected_task_id = res.data["task_id"]
        self.assertIn(f"/api/events/status/{expected_task_id}/", res.data["status_url"])
        mock_task.assert_called_once()

    @patch("api.views.event.async_task", return_value="task-multi")
    def test_multiple_valid_events_accepted(self, mock_task):
        events = [valid_event(self.sensor.id) for _ in range(5)]
        res = self.client.post(EVENTS_URL, {"events": events}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn("5", res.data["message"])

    @patch("api.views.event.async_task", return_value="task-db")
    def test_raw_events_persisted_in_db(self, mock_task):
        events = [valid_event(self.sensor.id) for _ in range(3)]
        res = self.client.post(EVENTS_URL, {"events": events}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        task_id = res.data["task_id"]
        self.assertEqual(RawEvent.objects.filter(batch__task_id=task_id).count(), 3)

    @patch("api.views.event.async_task", return_value="task-batchstatus")
    def test_event_status_created_with_pending(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}
        res = self.client.post(EVENTS_URL, payload, format="json")

        batch = EventStatus.objects.get(task_id=res.data["task_id"])

        self.assertEqual(batch.task_id, res.data["task_id"])
        mock_task.assert_called_once()

    @patch("api.views.event.async_task", return_value="task-optional")
    def test_optional_fields_accepted(self, mock_task):
        event = valid_event(
            self.sensor.id,
            session_id="sess-1",
            token_id="tok-1",
            protocol="tcp",
            service_name="ssh",
            username="root",
            password="toor",
            cve_id="CVE-2024-0001",
            command="whoami",
            src_port=4444,
            dest_port=22,
            related_url="http://evil.example.com/malware",
            payload_hash="a" * 64,
            data={"extra": "info"},
        )
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

    @patch("api.views.event.async_task", return_value="task-ipv6")
    def test_ipv6_src_ip_accepted(self, mock_task):
        event = valid_event(self.sensor.id, src_ip="2001:db8::1")
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

    @patch("api.views.event.async_task", return_value="task-dup")
    def test_duplicate_requests_create_separate_batches(self, mock_task):
        payload = {"events": [valid_event(self.sensor.id)]}

        res1 = self.client.post(EVENTS_URL, payload, format="json")
        res2 = self.client.post(EVENTS_URL, payload, format="json")

        self.assertEqual(res1.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(res2.status_code, status.HTTP_202_ACCEPTED)

        self.assertNotEqual(res1.data["task_id"], res2.data["task_id"])
        self.assertEqual(mock_task.call_count, 2)

    @patch("api.views.event.create_batch_and_events", side_effect=Exception("DB crash"))
    def test_batch_creation_failure_returns_500(self, mock_create):
        payload = {"events": [valid_event(self.sensor.id)]}

        res = self.client.post(EVENTS_URL, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    @patch("api.views.event.async_task")
    def test_events_create_all_invalid_sensors_locks_api_source_after_10_failures(self, mock_task):
        """
        Verifies that if an APISource reaches 10 failed batch insertion
        attempts due to invalid sensor data, it is automatically deactivated (locked).
        """
        # Set the current count to 9 (so the next failure hits the 10 threshold)
        self.api_source.invalid_event_count = 9
        self.api_source.save()

        # Send a payload containing a non-existent sensor ID
        bad_event = valid_event(sensor_id=999999)
        res = self.client.post(EVENTS_URL, {"events": [bad_event]}, format="json")

        # The 10th failure must return a 403 Forbidden instead of a 400 Bad Request
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("automatically locked", res.data["error"])

        # Reload from the database to confirm it is locked
        self.api_source.refresh_from_db()
        self.assertFalse(self.api_source.is_active)
        self.assertEqual(self.api_source.invalid_event_count, 10)

        # Ensure background execution was never triggered
        mock_task.assert_not_called()

    @patch("api.views.event.async_task", return_value="task-newfields")
    def test_new_fields_persisted_on_raw_event(self, mock_task):
        """
        Confirms protocol, cve_id, and payload_hash values submitted via the API
        are actually written to the RawEvent row, not just accepted by validation.
        """
        event = valid_event(
            self.sensor.id,
            protocol="ssh",
            cve_id="CVE-2024-0001",
            payload_hash="a" * 64,
        )
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.protocol, "ssh")
        self.assertEqual(raw.cve_id, "CVE-2024-0001")
        self.assertEqual(raw.payload_hash, "a" * 64)

    @patch("api.views.event.async_task", return_value="task-emptyfields")
    def test_omitted_new_fields_default_empty_on_raw_event(self, mock_task):
        """Protocol/cve_id/payload_hash are optional — must default to empty, not null/error."""
        event = valid_event(self.sensor.id)  # none of the new optional fields set
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)

        raw = RawEvent.objects.get(batch__task_id=res.data["task_id"])
        self.assertEqual(raw.protocol, "")
        self.assertEqual(raw.cve_id, "")
        self.assertEqual(raw.payload_hash, "")


class TestEventsCreateAllInvalidSensors(BaseEventTestCase):
    @patch("api.views.event.async_task")
    def test_nonexistent_sensor_ids_return_400(self, mock_task):
        """All events reference a sensor that does not exist → 0 rows created → 400."""
        event = valid_event(sensor_id=999999)
        res = self.client.post(EVENTS_URL, {"events": [event]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid or missing sensor_id", res.data["error"])
        # background task must NOT be dispatched
        mock_task.assert_not_called()

    @patch("api.views.event.async_task", return_value="task-partial")
    def test_mixed_valid_and_invalid_sensors_stores_none(self, mock_task):
        """One valid sensor + one ghost sensor → entire batch rejected with 400."""
        good = valid_event(self.sensor.id)
        bad = valid_event(sensor_id=999999)
        res = self.client.post(EVENTS_URL, {"events": [good, bad]}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid or missing sensor_id", res.data["error"])
        self.assertEqual(RawEvent.objects.count(), 0)
        mock_task.assert_not_called()


class TestEventStatusView(BaseEventTestCase):
    def _make_batch(self, task_id=None, batch_status="pending"):
        return EventStatus.objects.create(
            api_source=self.api_source,
            task_id=task_id or uuid.uuid4().hex,
            status=batch_status,
        )

    def test_unauthenticated_returns_401(self):
        anon = APIClient()
        res = anon.get(STATUS_URL.format(task_id=uuid.uuid4().hex))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_api_source_returns_403(self):
        user2 = make_user(username="noapi2")
        client2 = auth_client(user2)
        res = client2.get(STATUS_URL.format(task_id=uuid.uuid4().hex))
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_unknown_task_id_returns_404(self):
        res = self.client.get(STATUS_URL.format(task_id=uuid.uuid4().hex))
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_malformed_task_id_returns_400(self):
        """A task_id that cannot have been minted by the API is rejected before the lookup."""
        res = self.client.get(STATUS_URL.format(task_id="not-a-task-id"))
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("task_id", str(res.data))

    def test_batch_belonging_to_other_user_returns_404(self):
        """Users must not be able to see other users' batches."""
        user2 = make_user(username="other")
        api_source2 = make_api_source(user2, name="OtherSource")
        other_batch = EventStatus.objects.create(
            api_source=api_source2,
            task_id=uuid.uuid4().hex,
            status="pending",
        )
        res = self.client.get(STATUS_URL.format(task_id=other_batch.task_id))
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_valid_task_id_returns_200(self):
        batch = self._make_batch()
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_response_contains_required_fields(self):
        batch = self._make_batch()
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        for key in ("task_id", "batch_id", "status", "ioc_count", "last_error", "processed_at", "created_at"):
            self.assertIn(key, res.data)

    def test_status_pending_reflected(self):
        batch = self._make_batch(batch_status="pending")
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.data["status"], "pending")

    def test_status_completed_reflected(self):
        batch = self._make_batch(batch_status="completed")
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.data["status"], "completed")

    def test_status_failed_with_error_message(self):
        batch = self._make_batch(batch_status="failed")
        batch.last_error = "Something went wrong"
        batch.save(update_fields=["last_error"])
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.data["status"], "failed")
        self.assertEqual(res.data["last_error"], "Something went wrong")

    def test_null_last_error_returned_as_none(self):
        batch = self._make_batch()
        batch.last_error = ""
        batch.save()
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertIsNone(res.data["last_error"])

    def test_ioc_count_returned(self):
        batch = self._make_batch()
        batch.ioc_count = 42
        batch.save(update_fields=["ioc_count"])
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.data["ioc_count"], 42)

    def test_locked_api_source_returns_403_on_status(self):
        batch = self._make_batch()
        self.api_source.is_active = False
        self.api_source.save()
        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        # locked source should still return 403 to be consistent with create view
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_status_changes_over_time(self):
        batch = self._make_batch(batch_status="pending")

        batch.status = "processing"
        batch.save()

        res = self.client.get(STATUS_URL.format(task_id=batch.task_id))
        self.assertEqual(res.data["status"], "processing")

    @patch("api.views.event.async_task")
    def test_events_create_fails_when_background_queue_crashing(self, mock_async_task):
        """
        If the message broker or async_task dispatcher throws an exception,
        the API must catch it, transition the batch status to FAILED with the traceback,
        and return a 500 Internal Server Error instead of staying stuck in PENDING.
        """
        mock_async_task.side_effect = Exception("Connection refused by Redis broker")

        payload = {"events": [valid_event(self.sensor.id)]}

        res = self.client.post(EVENTS_URL, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn("An internal error occurred while queueing events", res.data["error"])

        batch = EventStatus.objects.get(api_source=self.api_source)
        self.assertEqual(batch.status, EventStatusType.FAILED)
        self.assertIn("Background task dispatch failed", batch.last_error)
        self.assertIn("Connection refused by Redis broker", batch.last_error)
