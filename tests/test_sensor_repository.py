from unittest.mock import patch

from greedybear.cronjobs.repositories import SensorRepository
from greedybear.models import Sensor

from . import CustomTestCase


class TestSensorRepository(CustomTestCase):
    def setUp(self):
        self.repo = SensorRepository()

    def test_get_or_create_sensor_creates_new_sensor(self):
        result = self.repo.get_or_create_sensor("192.168.1.3")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, Sensor)
        self.assertEqual(result.address, "192.168.1.3")
        self.assertTrue(Sensor.objects.filter(address="192.168.1.3").exists())
        self.assertIn("192.168.1.3", self.repo.cache)

    def test_get_or_create_sensor_returns_existing_sensor(self):
        first_result = self.repo.get_or_create_sensor("192.168.1.1")
        second_result = self.repo.get_or_create_sensor("192.168.1.1")
        self.assertEqual(first_result.pk, second_result.pk)
        self.assertEqual(Sensor.objects.filter(address="192.168.1.1").count(), 1)

    def test_get_or_create_sensor_rejects_non_ip(self):
        result = self.repo.get_or_create_sensor("not-an-ip")
        self.assertIsNone(result)

    def test_get_or_create_sensor_rejects_domain(self):
        result = self.repo.get_or_create_sensor("example.com")
        self.assertIsNone(result)

    def test_cache_populated_on_init(self):
        Sensor.objects.create(address="192.168.1.1")
        Sensor.objects.create(address="192.168.1.2")
        repo = SensorRepository()
        self.assertEqual(len(repo.cache), 2)
        self.assertIn("192.168.1.1", repo.cache)
        self.assertIn("192.168.1.2", repo.cache)

    def test_cache_stores_sensor_objects(self):
        sensor = Sensor.objects.create(address="192.168.1.1")
        repo = SensorRepository()
        cached_sensor = repo.cache.get("192.168.1.1")
        self.assertIsInstance(cached_sensor, Sensor)
        self.assertEqual(cached_sensor.pk, sensor.pk)

    def test_get_or_create_sensor_updates_cache(self):
        initial_cache_size = len(self.repo.cache)
        self.repo.get_or_create_sensor("192.168.1.1")
        self.assertEqual(len(self.repo.cache), initial_cache_size + 1)

    def test_get_or_create_sensor_accepts_valid_ipv4(self):
        test_ips = ["1.2.3.4", "192.168.1.1", "10.0.0.1", "8.8.8.8"]
        for ip in test_ips:
            result = self.repo.get_or_create_sensor(ip)
            self.assertIsNotNone(result)
            self.assertIsInstance(result, Sensor)

    def test_get_or_create_sensor_accepts_valid_ipv6(self):
        result = self.repo.get_or_create_sensor("2001:db8::1")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, Sensor)
        self.assertEqual(result.address, "2001:db8::1")
        self.assertTrue(Sensor.objects.filter(address="2001:db8::1").exists())

    def test_get_or_create_sensor_has_empty_label(self):
        """get_or_create_sensor should create a sensor with an empty label."""
        result = self.repo.get_or_create_sensor("192.168.1.10")
        self.assertEqual(result.label, "")

    def test_update_country_sets_country(self):
        """update_country sets the Sensor's country if different."""
        sensor = Sensor.objects.create(address="1.2.3.4", country="")

        self.repo.update_country(sensor, "Nepal")

        sensor.refresh_from_db()
        self.assertEqual(sensor.country, "Nepal")

    def test_update_country_skips_if_same_value(self):
        """update_country does not call save if country is unchanged."""
        sensor = Sensor.objects.create(address="1.2.3.5", country="Nepal")

        with patch.object(Sensor, "save") as mock_save:
            self.repo.update_country(sensor, "Nepal")
            mock_save.assert_not_called()

    def test_update_country_updates_if_different(self):
        """update_country writes to DB if country differs."""
        sensor = Sensor.objects.create(address="1.2.3.6", country="India")

        with patch.object(Sensor, "save") as mock_save:
            self.repo.update_country(sensor, "Nepal")
            mock_save.assert_called_once()

    def test_update_country_skips_if_invalid_input(self):
        """update_country should not save if sensor is None or country is empty."""
        sensor = Sensor.objects.create(address="1.2.3.7", country="")

        with patch.object(Sensor, "save") as mock_save:
            self.repo.update_country(None, "Nepal")
            self.repo.update_country(sensor, "")
            mock_save.assert_not_called()
