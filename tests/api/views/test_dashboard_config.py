# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import DashboardConfig
from tests import CustomTestCase

URL = "/api/dashboard-config/"

VALID_LAYOUT = {
    "widgetConfigs": [
        {"type": "FeedsTypesChart", "id": "FeedsTypesChart"},
        {"type": "AttackOriginMap", "id": "AttackOriginMap"},
    ],
    "layouts": {
        "lg": [{"i": "FeedsTypesChart", "x": 0, "y": 0, "w": 6, "h": 9}],
        "md": [],
        "sm": [],
    },
}


def _auth_client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


class DashboardConfigTests(CustomTestCase):
    def setUp(self):
        super().setUp()
        DashboardConfig.objects.all().delete()

    # GET

    def test_get_unauthenticated_returns_200(self):
        response = APIClient().get(URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_unauthenticated_returns_null_when_no_record(self):
        response = APIClient().get(URL)
        self.assertIsNone(response.data["layout"])

    def test_get_no_record_returns_null_layout(self):
        response = _auth_client(self.regular_user).get(URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["layout"])

    def test_get_returns_saved_layout(self):
        DashboardConfig.objects.create(layout=VALID_LAYOUT, updated_by=self.superuser)
        response = _auth_client(self.regular_user).get(URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["layout"], VALID_LAYOUT)

    # PUT

    def test_put_unauthenticated_returns_401(self):
        response = APIClient().put(URL, {"layout": VALID_LAYOUT}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_put_regular_user_returns_403(self):
        response = _auth_client(self.regular_user).put(URL, {"layout": VALID_LAYOUT}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_put_invalid_body_returns_400(self):
        response = _auth_client(self.superuser).put(URL, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_creates_record(self):
        _auth_client(self.superuser).put(URL, {"layout": VALID_LAYOUT}, format="json")
        self.assertEqual(DashboardConfig.objects.count(), 1)

    def test_put_returns_saved_layout(self):
        response = _auth_client(self.superuser).put(URL, {"layout": VALID_LAYOUT}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["layout"], VALID_LAYOUT)

    def test_put_twice_keeps_single_record(self):
        client = _auth_client(self.superuser)
        client.put(URL, {"layout": VALID_LAYOUT}, format="json")
        client.put(URL, {"layout": {**VALID_LAYOUT, "widgetConfigs": []}}, format="json")
        self.assertEqual(DashboardConfig.objects.count(), 1)

    def test_put_updates_existing_layout(self):
        client = _auth_client(self.superuser)
        client.put(URL, {"layout": VALID_LAYOUT}, format="json")
        client.put(URL, {"layout": {**VALID_LAYOUT, "widgetConfigs": []}}, format="json")
        self.assertEqual(DashboardConfig.objects.first().layout["widgetConfigs"], [])

    # DELETE

    def test_delete_unauthenticated_returns_401(self):
        response = APIClient().delete(URL)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_regular_user_returns_403(self):
        response = _auth_client(self.regular_user).delete(URL)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_removes_record(self):
        DashboardConfig.objects.create(layout=VALID_LAYOUT, updated_by=self.superuser)
        _auth_client(self.superuser).delete(URL)
        self.assertEqual(DashboardConfig.objects.count(), 0)

    def test_delete_returns_204(self):
        DashboardConfig.objects.create(layout=VALID_LAYOUT, updated_by=self.superuser)
        response = _auth_client(self.superuser).delete(URL)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_when_no_record_returns_204(self):
        response = _auth_client(self.superuser).delete(URL)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_get_after_delete_returns_null(self):
        DashboardConfig.objects.create(layout=VALID_LAYOUT, updated_by=self.superuser)
        _auth_client(self.superuser).delete(URL)
        response = _auth_client(self.regular_user).get(URL)
        self.assertIsNone(response.data["layout"])
