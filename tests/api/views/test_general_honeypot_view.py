from rest_framework.exceptions import ValidationError

from api.serializers import HoneypotRequestSerializer
from greedybear.models import Honeypot
from tests import CustomTestCase


class HoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        initial_count = Honeypot.objects.count()
        # add a general honeypot not active
        Honeypot(name="Adbhoney", active=False).save()
        self.assertEqual(Honeypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/general_honeypot")
        self.assertEqual(response.status_code, 200)
        # Verify the newly created honeypot is in the response
        self.assertIn("Adbhoney", response.json())

    def test_200_active_general_honeypots(self):
        response = self.client.get("/api/general_honeypot?onlyActive=true")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # Should include active honeypots from CustomTestCase
        self.assertIn("Heralding", result)
        self.assertIn("Ciscoasa", result)
        # Should NOT include inactive honeypot
        self.assertNotIn("Ddospot", result)

    def test_200_all_honeypots(self):
        response = self.client.get("/api/honeypot/")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("Heralding", result)
        # Inactive honeypots are listed as well
        self.assertIn("Ddospot", result)

    def test_200_active_honeypots(self):
        response = self.client.get("/api/honeypot/?only_active=true")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("Heralding", result)
        self.assertIn("Ciscoasa", result)
        self.assertNotIn("Ddospot", result)

    def test_200_presence_flag_without_value(self):
        # a valueless query param is treated as truthy
        for query in ["?only_active", "?onlyActive"]:
            with self.subTest(query=query):
                response = self.client.get(f"/api/honeypot/{query}")
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("Ddospot", response.json())

    def test_200_flag_disabled(self):
        for query in ["?only_active=false", "?onlyActive=false"]:
            with self.subTest(query=query):
                response = self.client.get(f"/api/honeypot/{query}")
                self.assertEqual(response.status_code, 200)
                self.assertIn("Ddospot", response.json())

    def test_400_invalid_flag_value(self):
        response = self.client.get("/api/honeypot/?only_active=not_a_bool")
        self.assertEqual(response.status_code, 400)


class HoneypotRequestSerializerTestCase(CustomTestCase):
    def test_default(self):
        serializer = HoneypotRequestSerializer(data={})
        serializer.is_valid(raise_exception=True)
        self.assertEqual(serializer.validated_data, {"only_active": False})

    def test_legacy_alias_is_normalized(self):
        # the deprecated spelling maps onto only_active and does not leak through
        serializer = HoneypotRequestSerializer(data={"onlyActive": "true"})
        serializer.is_valid(raise_exception=True)
        self.assertEqual(serializer.validated_data, {"only_active": True})

    def test_either_spelling_enables_the_filter(self):
        for data in [{"only_active": "true"}, {"onlyActive": "true"}, {"only_active": "false", "onlyActive": "true"}]:
            with self.subTest(data=data):
                serializer = HoneypotRequestSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                self.assertEqual(serializer.validated_data, {"only_active": True})

    def test_invalid_value(self):
        serializer = HoneypotRequestSerializer(data={"only_active": "not_a_bool"})
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
