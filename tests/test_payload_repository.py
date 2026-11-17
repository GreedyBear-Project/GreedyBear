from django.db import IntegrityError, transaction

from greedybear.cronjobs.repositories import PayloadRepository
from greedybear.models import IOC, Honeypot, HoneypotPayload

from . import CustomTestCase


class TestPayloadRepository(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.repo = PayloadRepository()
        self.cowrie_hp, _ = Honeypot.objects.get_or_create(name="Cowrie")

    def test_get_or_create_payload_from_event_creates_minimal_payload(self):
        payload, created = self.repo.get_or_create_payload_from_event(
            sha256="A" * 64,
            ioc=self.ioc,
            honeypot_names=["Cowrie"],
        )

        self.assertTrue(created)
        self.assertEqual(payload.sha256, "a" * 64)
        self.assertFalse(payload.payload_file)
        self.assertIn(self.ioc, payload.iocs.all())
        self.assertIn(self.cowrie_hp, payload.source_honeypots.all())

    def test_get_or_create_payload_from_event_returns_existing_payload(self):
        existing = HoneypotPayload.objects.create(sha256="e" * 64, md5="deadbeef")

        payload, created = self.repo.get_or_create_payload_from_event(
            sha256="E" * 64,
            ioc=self.ioc,
            honeypot_names=["Cowrie"],
        )

        self.assertFalse(created)
        self.assertEqual(payload.id, existing.id)
        self.assertEqual(payload.md5, "deadbeef")
        self.assertIn(self.ioc, payload.iocs.all())
        self.assertIn(self.cowrie_hp, payload.source_honeypots.all())

    def test_get_or_create_payload_from_event_is_idempotent(self):
        for _ in range(2):
            self.repo.get_or_create_payload_from_event(
                sha256="c" * 64,
                ioc=self.ioc,
                honeypot_names=["Cowrie"],
            )

        payload = HoneypotPayload.objects.get(sha256="c" * 64)
        self.assertEqual(HoneypotPayload.objects.count(), 1)
        self.assertEqual(payload.iocs.count(), 1)
        self.assertEqual(payload.source_honeypots.count(), 1)

    def test_get_or_create_payload_from_event_rejects_invalid_sha256(self):
        with self.assertRaises(ValueError):
            self.repo.get_or_create_payload_from_event(
                sha256="not-a-sha256",
                ioc=self.ioc,
            )

    def test_get_downloaded_hashes_excludes_stub_without_file(self):
        HoneypotPayload.objects.create(sha256="1" * 64)

        downloaded = self.repo.get_downloaded_hashes({"1" * 64})

        self.assertEqual(downloaded, set())

    def test_get_downloaded_hashes_includes_row_with_file(self):
        HoneypotPayload.objects.create(sha256="2" * 64, payload_file="sample.vir")

        downloaded = self.repo.get_downloaded_hashes({"2" * 64})

        self.assertEqual(downloaded, {"2" * 64})

    def test_get_downloaded_hashes_excludes_real_null_payload_file(self):
        payload = HoneypotPayload.objects.create(sha256="3" * 64)
        # .update() bypasses FileField's own save-time coercion of None to "",
        # this is the one way to get a real NULL into the column via the ORM.
        HoneypotPayload.objects.filter(id=payload.id).update(payload_file=None)

        downloaded = self.repo.get_downloaded_hashes({"3" * 64})

        self.assertEqual(downloaded, set())

    def test_get_downloaded_hashes_normalizes_mixed_case_input(self):
        HoneypotPayload.objects.create(sha256=("ab" * 32).lower(), payload_file="sample.vir")

        downloaded = self.repo.get_downloaded_hashes({("ab" * 32).upper()})

        self.assertEqual(downloaded, {("ab" * 32).lower()})

    def test_upsert_downloaded_payload_creates_new_row(self):
        incoming = HoneypotPayload(
            sha256="6" * 64,
            md5="m1",
            sha1="s1",
            mime_type="application/octet-stream",
            size=100,
            locator="cowrie/aaa",
            mtime=123.0,
        )
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertTrue(created)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "m1")
        self.assertEqual(payload.sha1, "s1")
        self.assertEqual(payload.mime_type, "application/octet-stream")
        self.assertEqual(payload.size, 100)
        self.assertEqual(payload.locator, "cowrie/aaa")
        self.assertEqual(payload.mtime, 123.0)

    def test_upsert_downloaded_payload_normalizes_sha256(self):
        payload, created = self.repo.upsert_downloaded_payload(HoneypotPayload(sha256="F" * 64))

        self.assertTrue(created)
        self.assertEqual(payload.sha256, "f" * 64)

    def test_upsert_downloaded_payload_rejects_invalid_sha256(self):
        with self.assertRaises(ValueError):
            self.repo.upsert_downloaded_payload(HoneypotPayload(sha256="not-a-sha256"))

    def test_upsert_downloaded_payload_upgrades_existing_stub_with_truthy_fields(self):
        stub = HoneypotPayload.objects.create(sha256="7" * 64, md5="", sha1="")

        incoming = HoneypotPayload(
            sha256="7" * 64,
            md5="m2",
            sha1="s2",
            mime_type="application/x-elf",
            size=200,
            locator="cowrie/bbb",
            mtime=456.0,
        )
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        self.assertEqual(payload.id, stub.id)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "m2")
        self.assertEqual(payload.sha1, "s2")
        self.assertEqual(payload.mime_type, "application/x-elf")
        self.assertEqual(payload.mtime, 456.0)

    def test_upsert_downloaded_payload_keeps_existing_value_when_incoming_is_falsy(self):
        HoneypotPayload.objects.create(sha256="8" * 64, md5="keepme")

        incoming = HoneypotPayload(sha256="8" * 64, md5="", sha1="", mime_type="", size=50, locator="cowrie/ccc", mtime=None)
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        self.assertEqual(payload.md5, "keepme")

    def test_upsert_downloaded_payload_always_overwrites_size_and_locator(self):
        HoneypotPayload.objects.create(sha256="9" * 64, size=1, locator="old/locator")

        incoming = HoneypotPayload(sha256="9" * 64, md5="", sha1="", mime_type="", size=0, locator="new/locator", mtime=None)
        payload, created = self.repo.upsert_downloaded_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        self.assertEqual(payload.size, 0)
        self.assertEqual(payload.locator, "new/locator")

    def test_upsert_metadata_only_payload_creates_new_row(self):
        incoming = HoneypotPayload(sha256="0" * 64, md5="m1", sha1="s1", mime_type="text/plain", size=42, locator="cowrie/ddd", mtime=789.0)
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertTrue(created)
        payload.refresh_from_db()
        self.assertFalse(payload.payload_file)
        self.assertEqual(payload.md5, "m1")
        self.assertEqual(payload.sha1, "s1")
        self.assertEqual(payload.mime_type, "text/plain")
        self.assertEqual(payload.size, 42)
        self.assertEqual(payload.locator, "cowrie/ddd")
        self.assertEqual(payload.mtime, 789.0)

    def test_upsert_metadata_only_payload_normalizes_sha256(self):
        payload, created = self.repo.upsert_metadata_only_payload(HoneypotPayload(sha256="A" * 64))

        self.assertTrue(created)
        self.assertEqual(payload.sha256, "a" * 64)

    def test_upsert_metadata_only_payload_rejects_invalid_sha256(self):
        with self.assertRaises(ValueError):
            self.repo.upsert_metadata_only_payload(HoneypotPayload(sha256="not-a-sha256"))

    def test_upsert_metadata_only_payload_backfills_missing_locator_on_stub(self):
        stub = HoneypotPayload.objects.create(sha256=("cd" * 32).lower())
        self.assertEqual(stub.locator, "")

        incoming = HoneypotPayload(sha256=("cd" * 32).lower(), md5="", sha1="", mime_type="", size=None, locator="cowrie/eee", mtime=None)
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertFalse(created)
        self.assertEqual(payload.id, stub.id)
        payload.refresh_from_db()
        self.assertEqual(payload.locator, "cowrie/eee")

    def test_upsert_metadata_only_payload_does_not_overwrite_existing_locator(self):
        HoneypotPayload.objects.create(sha256=("ef" * 32).lower(), locator="already/set")

        incoming = HoneypotPayload(sha256=("ef" * 32).lower(), md5="", sha1="", mime_type="", size=None, locator="cowrie/fff", mtime=None)
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        self.assertEqual(payload.locator, "already/set")

    def test_upsert_metadata_only_payload_backfill_does_not_update_other_fields(self):
        HoneypotPayload.objects.create(sha256=("01" * 32).lower(), md5="keepme", mime_type="keepme_mime")

        incoming = HoneypotPayload(
            sha256=("01" * 32).lower(),
            md5="different",
            sha1="different",
            mime_type="different",
            size=5,
            locator="cowrie/ggg",
            mtime=1.0,
        )
        payload, created = self.repo.upsert_metadata_only_payload(incoming)

        self.assertFalse(created)
        payload.refresh_from_db()
        # The backfill did fire (locator was empty)...
        self.assertEqual(payload.locator, "cowrie/ggg")
        # ...but nothing else was updated, despite the incoming payload carrying different values for them.
        self.assertEqual(payload.md5, "keepme")
        self.assertEqual(payload.mime_type, "keepme_mime")

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

    def test_payload_hashes_for_ioc_returns_sorted_linked_hashes(self):
        ioc = IOC.objects.create(name="203.0.113.50", type="ip")
        payload_b = HoneypotPayload.objects.create(sha256="b" * 64)
        payload_a = HoneypotPayload.objects.create(sha256="a" * 64)
        payload_b.iocs.add(ioc)
        payload_a.iocs.add(ioc)

        result = IOC.objects.filter(pk=ioc.pk).annotate(payload_hashes=self.repo.payload_hashes_for_ioc()).get()

        self.assertEqual(result.payload_hashes, ["a" * 64, "b" * 64])

    def test_payload_hashes_for_ioc_returns_empty_array_when_no_payloads(self):
        ioc = IOC.objects.create(name="203.0.113.51", type="ip")

        result = IOC.objects.filter(pk=ioc.pk).annotate(payload_hashes=self.repo.payload_hashes_for_ioc()).first()

        self.assertEqual(result.payload_hashes, [])

    def test_sha256_constraint_rejects_uppercase(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            HoneypotPayload.objects.create(sha256="A" * 64)

    def test_sha256_constraint_rejects_non_hex(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            HoneypotPayload.objects.create(sha256="g" * 64)

    def test_sha256_constraint_rejects_wrong_length(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            HoneypotPayload.objects.create(sha256="a" * 63)

    def test_sha256_is_unique(self):
        HoneypotPayload.objects.create(sha256="f" * 64)

        with self.assertRaises(IntegrityError), transaction.atomic():
            HoneypotPayload.objects.create(sha256="f" * 64)
