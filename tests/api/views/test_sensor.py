from django.contrib.auth import get_user_model
from django.db import IntegrityError
from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import APISource, AutonomousSystem, Sensor, SourceType
from tests import CustomTestCase

User = get_user_model()

SENSOR_CREATE_URL = "/api/sensor/"


def make_user(username="testuser", password="pass1234!"):
    return User.objects.create_user(username=username, password=password)


def make_apisource(user, name="TestSource"):
    return APISource.objects.create(user=user, name=name)


def auth_client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


VALID_PAYLOAD = {
    "address": "1.2.3.4",
    "honeypot_type": "ssh",
    "honeypot_software": "cowrie",
    "honeypot_description": "test honeypot",
    "sensor_label": "sensor-a",
    "group_label": "group-a",
    "country_code": "NP",
    "asn": 64512,
}


class BaseSensorTestCase(CustomTestCase):
    def setUp(self):
        self.user = make_user()
        self.api_source = make_apisource(self.user)
        self.client = auth_client(self.user)


class SensorCreateAuthTests(BaseSensorTestCase):
    def test_unauthenticated_request_rejected(self):
        response = APIClient().post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
        )

    def test_user_without_apisource_gets_403(self):
        bare_user = make_user(username="bare")
        response = auth_client(bare_user).post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("error", response.data)

    def test_get_method_not_allowed(self):
        response = self.client.get(SENSOR_CREATE_URL)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class SensorCreateTests(BaseSensorTestCase):
    def test_creates_sensor(self):
        response = self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["id"])
        sensor = Sensor.objects.get(address="1.2.3.4")

        self.assertEqual(sensor.api_source, self.api_source)
        self.assertEqual(sensor.source_type, SourceType.EXTERNAL)

    def test_existing_sensor_returns_existing_record(self):
        # first request creates sensor
        self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        # second request should hit existing sensor
        response = self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertTrue(response.data["id"])

        sensor = Sensor.objects.get(address="1.2.3.4")

        # ensure still correctly linked
        self.assertEqual(sensor.api_source, self.api_source)
        self.assertEqual(sensor.source_type, SourceType.EXTERNAL)

    def test_sensor_label_maps_to_model_label(self):
        self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        sensor = Sensor.objects.get(address="1.2.3.4")
        self.assertEqual(sensor.label, "sensor-a")

    def test_country_code_is_uppercased_in_db(self):
        payload = {
            **VALID_PAYLOAD,
            "country_code": "np",
        }

        self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        sensor = Sensor.objects.get(address="1.2.3.4")
        self.assertEqual(sensor.country_code, "NP")

    def test_minimal_payload_succeeds(self):
        response = self.client.post(
            SENSOR_CREATE_URL,
            {"address": "8.8.8.8"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_blank_optional_fields_accepted(self):
        payload = {
            "address": "8.8.8.8",
            "honeypot_type": "",
            "honeypot_software": "",
            "honeypot_description": "",
            "sensor_label": "",
            "group_label": "",
            "country_code": "",
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_source_type_cannot_be_overridden(self):
        payload = {
            **VALID_PAYLOAD,
            "source_type": "internal",
        }

        self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        sensor = Sensor.objects.get(address="1.2.3.4")

        self.assertEqual(sensor.source_type, SourceType.EXTERNAL)

    def test_response_does_not_expose_internal_fields(self):
        response = self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertNotIn("autonomous_system", response.data)
        self.assertNotIn("api_source", response.data)

    def test_internal_sensor_address_must_be_unique(self):
        Sensor.objects.create(
            address="1.2.3.4",
            source_type=SourceType.TPOT,
        )

        with self.assertRaises(IntegrityError):
            Sensor.objects.create(
                address="1.2.3.4",
                source_type=SourceType.TPOT,
            )


class SensorASNTests(BaseSensorTestCase):
    def test_asn_creates_autonomous_system(self):
        self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertTrue(AutonomousSystem.objects.filter(asn=64512).exists())

    def test_sensor_links_to_autonomous_system(self):
        self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        sensor = Sensor.objects.get(address="1.2.3.4")

        self.assertIsNotNone(sensor.autonomous_system)
        self.assertEqual(sensor.autonomous_system.asn, 64512)

    def test_existing_autonomous_system_reused(self):
        AutonomousSystem.objects.create(
            asn=64512,
            name="Existing ASN",
        )

        self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(
            AutonomousSystem.objects.filter(asn=64512).count(),
            1,
        )

    def test_null_asn_is_accepted(self):
        payload = {
            **VALID_PAYLOAD,
            "asn": None,
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        sensor = Sensor.objects.get(address="1.2.3.4")
        self.assertIsNone(sensor.autonomous_system)

    def test_response_returns_id_value(self):
        response = self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertIsInstance(response.data["id"], int)

    def test_blank_asn_returns_400(self):
        payload = {
            **VALID_PAYLOAD,
            "asn": "",
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class SensorValidationTests(BaseSensorTestCase):
    def test_missing_address_returns_400(self):
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "address"}

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_ip_returns_400(self):
        payload = {
            **VALID_PAYLOAD,
            "address": "not-an-ip",
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_country_code_returns_400(self):
        payload = {
            **VALID_PAYLOAD,
            "country_code": "NPL",
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_sensor_label_too_long_returns_400(self):
        payload = {
            **VALID_PAYLOAD,
            "sensor_label": "x" * 129,
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_ipv6_address_accepted(self):
        payload = {
            **VALID_PAYLOAD,
            "address": "2001:db8::1",
        }

        response = self.client.post(
            SENSOR_CREATE_URL,
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_duplicate_address_does_not_create_new_sensor(self):
        self.client.post(SENSOR_CREATE_URL, VALID_PAYLOAD, format="json")

        self.client.post(SENSOR_CREATE_URL, VALID_PAYLOAD, format="json")

        self.assertEqual(Sensor.objects.filter(address="1.2.3.4").count(), 1)

    def test_invalid_address_does_not_create_sensor(self):
        self.client.post(
            SENSOR_CREATE_URL,
            {
                **VALID_PAYLOAD,
                "address": "invalid-ip",
            },
            format="json",
        )

        self.assertEqual(Sensor.objects.count(), 0)

    def test_inactive_apisource_cannot_create_sensor(self):
        self.api_source.is_active = False
        self.api_source.save()

        response = self.client.post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class SensorMultiUserTests(CustomTestCase):
    def setUp(self):
        self.user_a = make_user(username="user-a")
        self.user_b = make_user(username="user-b")

        self.api_source_a = make_apisource(self.user_a, "SourceA")
        self.api_source_b = make_apisource(self.user_b, "SourceB")

    def test_sensor_attached_to_correct_users_apisource(self):
        auth_client(self.user_a).post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        sensor = Sensor.objects.get(address="1.2.3.4")

        self.assertEqual(sensor.api_source, self.api_source_a)

    def test_multiple_users_can_create_different_sensors(self):
        auth_client(self.user_a).post(
            SENSOR_CREATE_URL,
            {
                **VALID_PAYLOAD,
                "address": "10.0.0.1",
            },
            format="json",
        )

        auth_client(self.user_b).post(
            SENSOR_CREATE_URL,
            {
                **VALID_PAYLOAD,
                "address": "10.0.0.2",
            },
            format="json",
        )

        self.assertEqual(Sensor.objects.count(), 2)

    def test_different_users_can_create_same_address(self):
        response_a = auth_client(self.user_a).post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        response_b = auth_client(self.user_b).post(
            SENSOR_CREATE_URL,
            VALID_PAYLOAD,
            format="json",
        )

        self.assertEqual(response_a.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_b.status_code, status.HTTP_201_CREATED)

        self.assertEqual(
            Sensor.objects.filter(address="1.2.3.4").count(),
            2,
        )

        sensor_a = Sensor.objects.get(
            address="1.2.3.4",
            api_source=self.api_source_a,
        )

        sensor_b = Sensor.objects.get(
            address="1.2.3.4",
            api_source=self.api_source_b,
        )

        self.assertNotEqual(sensor_a.id, sensor_b.id)
