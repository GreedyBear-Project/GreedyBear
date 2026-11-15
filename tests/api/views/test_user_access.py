# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import reverse
from rest_framework.test import APIClient

from api.permissions import THREAT_RESEARCHER_GROUP
from tests import CustomTestCase


class TestUserAccessCanDownloadPayloads(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.url = reverse("user_access")

    def _flag(self, user):
        self.client.force_authenticate(user=user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return response.json()["can_download_payloads"]

    def test_regular_user_cannot_download(self):
        self.assertFalse(self._flag(self.regular_user))

    def test_superuser_can_download(self):
        self.assertTrue(self._flag(self.superuser))

    def test_threat_researcher_can_download(self):
        from django.contrib.auth.models import Group

        group, _ = Group.objects.get_or_create(name=THREAT_RESEARCHER_GROUP)
        self.regular_user.groups.add(group)
        try:
            self.assertTrue(self._flag(self.regular_user))
        finally:
            self.regular_user.groups.remove(group)

    def test_user_payload_still_present(self):
        self.client.force_authenticate(user=self.regular_user)
        self.assertIn("user", self.client.get(self.url).json())
