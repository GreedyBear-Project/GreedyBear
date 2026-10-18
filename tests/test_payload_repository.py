from django.db import IntegrityError, transaction
from django.utils import timezone

from greedybear.cronjobs.repositories import PayloadRepository
from greedybear.models import IOC, CowrieFileTransfer, CowrieSession, HoneypotPayload, PayloadObservation, Sensor

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

    def test_get_or_create_stub_creates_minimal_row(self):
        payload, created = self.repo.get_or_create_stub("d" * 64)

        self.assertTrue(created)
        self.assertEqual(payload.sha256, "d" * 64)
        self.assertFalse(payload.payload_file)
        self.assertEqual(payload.md5, "")
        self.assertEqual(payload.sha1, "")

    def test_get_or_create_stub_returns_existing_row(self):
        existing = HoneypotPayload.objects.create(sha256="e" * 64, md5="deadbeef")

        payload, created = self.repo.get_or_create_stub("e" * 64)

        self.assertFalse(created)
        self.assertEqual(payload.id, existing.id)
        self.assertEqual(payload.md5, "deadbeef")

    def test_get_downloaded_payloads_excludes_stub_without_file(self):
        HoneypotPayload.objects.create(sha256="1" * 64)

        downloaded = self.repo.get_downloaded_payloads({"1" * 64})

        self.assertEqual(downloaded, {})

    def test_get_downloaded_payloads_includes_row_with_file(self):
        payload = HoneypotPayload.objects.create(sha256="2" * 64, payload_file="sample.vir")

        downloaded = self.repo.get_downloaded_payloads({"2" * 64})

        self.assertEqual(downloaded, {"2" * 64: payload})

    def test_get_downloaded_payloads_excludes_real_null_payload_file(self):
        payload = HoneypotPayload.objects.create(sha256="3" * 64)
        # .update() bypasses FileField's own save-time coercion of None to "",
        # this is the one way to get a real NULL into the column via the ORM.
        HoneypotPayload.objects.filter(id=payload.id).update(payload_file=None)

        downloaded = self.repo.get_downloaded_payloads({"3" * 64})

        self.assertEqual(downloaded, {})

    def test_get_downloaded_payloads_normalizes_mixed_case_input(self):
        HoneypotPayload.objects.create(sha256=("ab" * 32).lower(), payload_file="sample.vir")

        downloaded = self.repo.get_downloaded_payloads({("ab" * 32).upper()})

        self.assertEqual(set(downloaded), {("ab" * 32).lower()})

    def test_get_downloaded_payloads_keys_uppercase_row_by_lower_cased_hash(self):
        payload = HoneypotPayload.objects.create(sha256=("cd" * 32).upper(), payload_file="sample.vir")

        downloaded = self.repo.get_downloaded_payloads({("cd" * 32).lower()})

        self.assertEqual(downloaded, {("cd" * 32).lower(): payload})

    def test_upsert_downloaded_payload_creates_new_row(self):
        incoming = HoneypotPayload(
            sha256="6" * 64,
            md5="m1",
            sha1="s1",
            mime_type="application/octet-stream",
            size=100,
        )
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertTrue(created)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "m1")
        self.assertEqual(payload.sha1, "s1")
        self.assertEqual(payload.mime_type, "application/octet-stream")
        self.assertEqual(payload.size, 100)

    def test_upsert_downloaded_payload_upgrades_existing_stub_with_truthy_fields(self):
        stub = HoneypotPayload.objects.create(sha256="7" * 64, md5="", sha1="")

        incoming = HoneypotPayload(
            sha256="7" * 64,
            md5="m2",
            sha1="s2",
            mime_type="application/x-elf",
            size=200,
        )
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        self.assertEqual(payload.id, stub.id)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "m2")
        self.assertEqual(payload.sha1, "s2")
        self.assertEqual(payload.mime_type, "application/x-elf")

    def test_upsert_downloaded_payload_keeps_existing_value_when_incoming_is_falsy(self):
        HoneypotPayload.objects.create(sha256="8" * 64, md5="keepme")

        incoming = HoneypotPayload(sha256="8" * 64, md5="", sha1="", mime_type="", size=50)
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "keepme")

    def test_upsert_downloaded_payload_always_overwrites_size(self):
        HoneypotPayload.objects.create(sha256="9" * 64, size=1)

        incoming = HoneypotPayload(sha256="9" * 64, md5="", sha1="", mime_type="", size=0)
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        self.assertEqual(payload.size, 0)

    def test_upsert_metadata_only_payload_creates_new_row(self):
        incoming = HoneypotPayload(sha256="0" * 64, md5="m1", sha1="s1", mime_type="text/plain", size=42)
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertTrue(created)
        payload.refresh_from_db()
        self.assertFalse(payload.payload_file)
        self.assertEqual(payload.md5, "m1")
        self.assertEqual(payload.sha1, "s1")
        self.assertEqual(payload.mime_type, "text/plain")
        self.assertEqual(payload.size, 42)

    def test_upsert_metadata_only_payload_returns_existing_stub(self):
        stub = HoneypotPayload.objects.create(sha256=("cd" * 32).lower())

        incoming = HoneypotPayload(sha256=("cd" * 32).lower(), md5="", sha1="", mime_type="", size=None)
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertFalse(created)
        self.assertEqual(payload.id, stub.id)

    def test_upsert_metadata_only_payload_does_not_update_existing_row(self):
        HoneypotPayload.objects.create(sha256=("01" * 32).lower(), md5="keepme", mime_type="keepme_mime")

        incoming = HoneypotPayload(
            sha256=("01" * 32).lower(),
            md5="different",
            sha1="different",
            mime_type="different",
            size=5,
        )
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        # Nothing was updated, despite the incoming payload carrying different values.
        self.assertEqual(payload.md5, "keepme")
        self.assertEqual(payload.mime_type, "keepme_mime")

    def test_record_observations_creates_observation(self):
        sensor = Sensor.objects.create(address="198.51.100.1")
        payload = HoneypotPayload.objects.create(sha256="a7" * 32)

        self.repo.record_observations([PayloadObservation(payload=payload, sensor=sensor, locator="cowrie/downloads/aaa", mtime=123.0)])

        observation = PayloadObservation.objects.get(payload=payload)
        self.assertEqual(observation.sensor, sensor)
        self.assertEqual(observation.locator, "cowrie/downloads/aaa")
        self.assertEqual(observation.mtime, 123.0)
        self.assertEqual(list(payload.sensors.all()), [sensor])

    def test_record_observations_keeps_each_sensors_locator(self):
        sensor_a = Sensor.objects.create(address="198.51.100.1")
        sensor_b = Sensor.objects.create(address="198.51.100.2")
        payload = HoneypotPayload.objects.create(sha256="a8" * 32)

        self.repo.record_observations([PayloadObservation(payload=payload, sensor=sensor_a, locator="cowrie/downloads/aaa", mtime=1.0)])
        self.repo.record_observations([PayloadObservation(payload=payload, sensor=sensor_b, locator="dionaea/binaries/bbb", mtime=2.0)])

        self.assertEqual(PayloadObservation.objects.get(payload=payload, sensor=sensor_a).locator, "cowrie/downloads/aaa")
        self.assertEqual(PayloadObservation.objects.get(payload=payload, sensor=sensor_b).locator, "dionaea/binaries/bbb")
        self.assertCountEqual(payload.sensors.all(), [sensor_a, sensor_b])

    def test_record_observations_refreshes_same_sensor(self):
        sensor = Sensor.objects.create(address="198.51.100.1")
        payload = HoneypotPayload.objects.create(sha256="a9" * 32)
        self.repo.record_observations([PayloadObservation(payload=payload, sensor=sensor, locator="cowrie/downloads/old", mtime=1.0)])

        self.repo.record_observations([PayloadObservation(payload=payload, sensor=sensor, locator="dionaea/binaries/new", mtime=2.0)])

        observation = PayloadObservation.objects.get(payload=payload)
        self.assertEqual(observation.locator, "dionaea/binaries/new")
        self.assertEqual(observation.mtime, 2.0)

    def test_record_observations_without_sensor_is_unique_per_payload(self):
        payload = HoneypotPayload.objects.create(sha256="aa" * 32)

        self.repo.record_observations([PayloadObservation(payload=payload, sensor=None, locator="cowrie/downloads/old")])
        self.repo.record_observations([PayloadObservation(payload=payload, sensor=None, locator="cowrie/downloads/new")])

        observation = PayloadObservation.objects.get(payload=payload)
        self.assertIsNone(observation.sensor)
        self.assertEqual(observation.locator, "cowrie/downloads/new")
        self.assertEqual(payload.sensors.count(), 0)

    def test_record_observations_uses_one_query_for_a_batch(self):
        sensor = Sensor.objects.create(address="198.51.100.1")
        payloads = [HoneypotPayload.objects.create(sha256=f"c{i}" * 32) for i in range(5)]
        observations = [PayloadObservation(payload=payload, sensor=sensor, locator=f"cowrie/downloads/c{i}") for i, payload in enumerate(payloads)]

        with self.assertNumQueries(1):
            self.repo.record_observations(observations)
        with self.assertNumQueries(0):
            self.repo.record_observations([])

        self.assertEqual(PayloadObservation.objects.filter(sensor=sensor).count(), 5)

    def test_payload_observation_is_unique_per_sensor(self):
        sensor = Sensor.objects.create(address="198.51.100.1")
        payload = HoneypotPayload.objects.create(sha256="ab" * 32)
        PayloadObservation.objects.create(payload=payload, sensor=sensor, locator="cowrie/downloads/aaa")

        with self.assertRaises(IntegrityError), transaction.atomic():
            PayloadObservation.objects.create(payload=payload, sensor=sensor, locator="cowrie/downloads/bbb")

    def test_payload_observation_without_sensor_is_unique_per_payload(self):
        payload = HoneypotPayload.objects.create(sha256="ac" * 32)
        PayloadObservation.objects.create(payload=payload, sensor=None, locator="cowrie/downloads/aaa")

        with self.assertRaises(IntegrityError), transaction.atomic():
            PayloadObservation.objects.create(payload=payload, sensor=None, locator="cowrie/downloads/bbb")

    def test_get_pending_malwarebazaar_submissions_includes_eligible_payload(self):
        HoneypotPayload.objects.create(sha256="2" * 64, payload_file="p.vir", size=100)

        pending = self.repo.get_pending_malwarebazaar_submissions(max_size_bytes=1000, limit=10)

        self.assertEqual([p.sha256 for p in pending], ["2" * 64])

    def test_get_pending_malwarebazaar_submissions_excludes_already_uploaded(self):
        HoneypotPayload.objects.create(sha256="4" * 64, payload_file="p.vir", size=100, is_uploaded_mb=True)

        pending = self.repo.get_pending_malwarebazaar_submissions(max_size_bytes=1000, limit=10)

        self.assertEqual(list(pending), [])

    def test_get_pending_malwarebazaar_submissions_excludes_ineligible_payloads(self):
        HoneypotPayload.objects.create(sha256="5" * 64, payload_file="", size=100)
        HoneypotPayload.objects.create(sha256="6" * 64, payload_file=None, size=100)
        HoneypotPayload.objects.create(sha256="7" * 64, payload_file="p.vir", size=0)
        HoneypotPayload.objects.create(sha256="8" * 64, payload_file="p.vir", size=None)
        HoneypotPayload.objects.create(sha256="9" * 64, payload_file="p.vir", size=2000)

        pending = self.repo.get_pending_malwarebazaar_submissions(max_size_bytes=1000, limit=10)

        self.assertEqual(list(pending), [])

    def test_get_pending_malwarebazaar_submissions_respects_limit(self):
        for i in range(3):
            HoneypotPayload.objects.create(sha256=str(i) * 64, payload_file="p.vir", size=100)

        pending = self.repo.get_pending_malwarebazaar_submissions(max_size_bytes=1000, limit=2)

        self.assertEqual(len(pending), 2)

    def test_list_payloads_orders_by_id_descending(self):
        first = HoneypotPayload.objects.create(sha256="a1" * 32)
        second = HoneypotPayload.objects.create(sha256="a2" * 32)

        payloads = list(self.repo.list_payloads())

        self.assertEqual([p.id for p in payloads], [second.id, first.id])

    def test_list_payloads_returns_unevaluated_queryset(self):
        HoneypotPayload.objects.create(sha256="a3" * 32, is_uploaded_mb=True)
        HoneypotPayload.objects.create(sha256="a4" * 32, is_uploaded_mb=False)

        filtered = self.repo.list_payloads().filter(is_uploaded_mb=True)

        self.assertEqual(filtered.count(), 1)

    def test_annotate_lower_sha256_matches_regardless_of_stored_case(self):
        HoneypotPayload.objects.create(sha256=("a6" * 32).upper())

        queryset = self.repo.annotate_lower_sha256(HoneypotPayload.objects.all())
        match = queryset.filter(sha256_lower=("a6" * 32).lower())

        self.assertEqual(match.count(), 1)

    def test_payload_hashes_for_ioc_returns_lower_cased_hashes_for_linked_payloads(self):
        ioc = IOC.objects.create(name="203.0.113.50", type="ip")
        payload = HoneypotPayload.objects.create(sha256=("bb" * 32).upper())
        payload.iocs.add(ioc)

        result = IOC.objects.filter(pk=ioc.pk).annotate(payload_hashes=self.repo.payload_hashes_for_ioc()).first()

        self.assertEqual(result.payload_hashes, [("bb" * 32).lower()])

    def test_payload_hashes_for_ioc_returns_empty_array_when_no_payloads(self):
        ioc = IOC.objects.create(name="203.0.113.51", type="ip")

        result = IOC.objects.filter(pk=ioc.pk).annotate(payload_hashes=self.repo.payload_hashes_for_ioc()).first()

        self.assertEqual(result.payload_hashes, [])
