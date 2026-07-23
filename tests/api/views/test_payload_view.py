# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib.auth.models import Group
from django.core.files.base import ContentFile
from rest_framework.test import APIClient

from api.permissions import THREAT_RESEARCHER_GROUP
from greedybear.models import Honeypot, HoneypotPayload
from tests import CustomTestCase

PAYLOADS_URL = "/api/payloads"
SAMPLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class HoneypotPayloadViewSetTestCase(CustomTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.payload = HoneypotPayload.objects.create(
            sha256=SAMPLE_SHA256,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            mime_type="application/octet-stream",
            size=0,
        )
        hp = Honeypot.objects.get_or_create(name="Dionaea", defaults={"active": True})[0]
        cls.payload.source_honeypots.add(hp)

        cls.payload_with_file = HoneypotPayload.objects.create(
            sha256="aaaa" * 16,
            md5="bbbb" * 8,
            sha1="cccc" * 10,
            mime_type="application/x-elf",
            size=42,
            payload_file=ContentFile(b"MZ\x90\x00", name="test.vir"),
        )
        cls.payload_with_file.source_honeypots.add(hp)

        cls.researcher_group = Group.objects.get_or_create(name=THREAT_RESEARCHER_GROUP)[0]

    def setUp(self):
        super().setUp()
        self.client = APIClient()


class TestListPayloads(HoneypotPayloadViewSetTestCase):
    def test_unauthenticated_is_rejected(self):
        response = self.client.get(PAYLOADS_URL)
        self.assertEqual(response.status_code, 401)

    def test_authenticated_user_can_list(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(PAYLOADS_URL)
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertEqual(len(results), 2)

    def test_list_excludes_file_path(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(PAYLOADS_URL)
        for item in response.json()["results"]:
            self.assertNotIn("payload_file", item)
            self.assertNotIn("file_path", item)

    def test_list_contains_expected_fields(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(PAYLOADS_URL)
        item = next(r for r in response.json()["results"] if r["sha256"] == SAMPLE_SHA256)
        self.assertEqual(item["md5"], self.payload.md5)
        self.assertEqual(item["sha1"], self.payload.sha1)
        self.assertEqual(item["mime_type"], "application/octet-stream")
        self.assertEqual(item["size"], 0)
        self.assertIn("Dionaea", item["source_honeypots"])


class TestRetrievePayload(HoneypotPayloadViewSetTestCase):
    def test_retrieve_by_sha256(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(f"{PAYLOADS_URL}/{SAMPLE_SHA256}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sha256"], SAMPLE_SHA256)

    def test_retrieve_nonexistent_returns_404(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(f"{PAYLOADS_URL}/{'0' * 64}")
        self.assertEqual(response.status_code, 404)


class TestDownloadPayload(HoneypotPayloadViewSetTestCase):
    def test_unauthenticated_is_rejected(self):
        sha = self.payload_with_file.sha256
        response = self.client.get(f"{PAYLOADS_URL}/{sha}/download")
        self.assertEqual(response.status_code, 401)

    def test_regular_user_is_forbidden(self):
        self.client.force_authenticate(user=self.regular_user)
        sha = self.payload_with_file.sha256
        response = self.client.get(f"{PAYLOADS_URL}/{sha}/download")
        self.assertEqual(response.status_code, 403)

    def test_staff_can_download(self):
        self.client.force_authenticate(user=self.superuser)
        sha = self.payload_with_file.sha256
        response = self.client.get(f"{PAYLOADS_URL}/{sha}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Disposition"], f'attachment; filename="{sha}.vir"')
        content = b"".join(response.streaming_content)
        self.assertEqual(content, b"MZ\x90\x00")

    def test_threat_researcher_can_download(self):
        self.regular_user.groups.add(self.researcher_group)
        self.client.force_authenticate(user=self.regular_user)
        sha = self.payload_with_file.sha256
        response = self.client.get(f"{PAYLOADS_URL}/{sha}/download")
        self.assertEqual(response.status_code, 200)
        content = b"".join(response.streaming_content)
        self.assertEqual(content, b"MZ\x90\x00")
        self.regular_user.groups.remove(self.researcher_group)

    def test_download_missing_file_returns_404(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{PAYLOADS_URL}/{SAMPLE_SHA256}/download")
        self.assertEqual(response.status_code, 404)
        self.assertIn("not available", response.json()["detail"])
