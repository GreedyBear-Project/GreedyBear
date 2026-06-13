import random
from itertools import product

from rest_framework.serializers import ValidationError

from api.serializers import (
    AdvancedFeedRequestSerializer,
    IOCSerializer,
    SimpleFeedResponseSerializer,
    feed_type_as_list,
)
from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.enums import IpReputation
from greedybear.models import IOC, Honeypot, Sensor
from tests import CustomTestCase


class ParseFeedTypesTestCase(CustomTestCase):
    def test_single_type(self):
        self.assertEqual(feed_type_as_list("cowrie"), ["cowrie"])

    def test_multiple_types(self):
        self.assertEqual(feed_type_as_list("cowrie,adbhoney"), ["cowrie", "adbhoney"])

    def test_strips_whitespace(self):
        self.assertEqual(feed_type_as_list(" cowrie , adbhoney "), ["cowrie", "adbhoney"])

    def test_empty_string(self):
        self.assertEqual(feed_type_as_list(""), [])

    def test_only_commas(self):
        self.assertEqual(feed_type_as_list(",,,"), [])

    def test_all_type(self):
        self.assertEqual(feed_type_as_list("all"), ["all"])


class AdvancedFeedRequestSerializersTestCase(CustomTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.adbhoney = Honeypot.objects.filter(name__iexact="adbhoney").first()
        if not cls.adbhoney:
            cls.adbhoney = Honeypot.objects.create(name="Adbhoney", active=True)

    def test_valid_fields(self):
        choices = {
            "feed_type": ["all", "log4pot", "cowrie", "adbhoney"],
            "attack_type": ["all", "scanner", "payload_request"],
            "ioc_type": ["ip", "domain", "all"],
            "max_age": [str(n) for n in [1, 2, 4, 8, 16]],
            "min_days_seen": [str(n) for n in [1, 2, 4, 8, 16]],
            "include_reputation": [
                "",
                str(IpReputation.KNOWN_ATTACKER),
                f"{IpReputation.KNOWN_ATTACKER};{IpReputation.MASS_SCANNER}",
            ],
            "exclude_reputation": [
                "",
                str(IpReputation.KNOWN_ATTACKER),
                f"{IpReputation.KNOWN_ATTACKER};{IpReputation.MASS_SCANNER}",
            ],
            "feed_size": [str(n) for n in [100, 200, 5000, 10_000_000]],
            "ordering": [field.name for field in IOC._meta.get_fields()],
            "verbose": ["true", "false"],
            "paginate": ["true", "false"],
            "format": ["txt", "json", "csv"],
        }

        # generate n random sets of valid input data
        n = 1_000
        for _ in range(n):
            data_ = {field: random.choice(values) for field, values in choices.items()}
            serializer = AdvancedFeedRequestSerializer(data=data_)
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_multi_feed_type_valid(self):
        data_ = {
            "feed_type": "cowrie,log4pot",
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "1",
            "min_days_seen": "1",
            "include_reputation": "",
            "exclude_reputation": "",
            "feed_size": "1",
            "ordering": "last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
        }
        serializer = AdvancedFeedRequestSerializer(data=data_)
        self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_multi_feed_type_partially_invalid(self):
        """one invalid type, must fail validation"""
        data_ = {
            "feed_type": "cowrie,invalid_type",
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "1",
            "min_days_seen": "1",
            "include_reputation": "",
            "exclude_reputation": "",
            "feed_size": "1",
            "ordering": "last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
        }
        serializer = AdvancedFeedRequestSerializer(data=data_)
        try:
            serializer.is_valid(raise_exception=True)
            self.fail("ValidationError not raised for partially invalid feed_type")
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)

    def test_empty_feed_type_invalid(self):
        """empty or whitespace-only feed_type must be rejected"""
        base_data = {
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "1",
            "min_days_seen": "1",
            "include_reputation": "",
            "exclude_reputation": "",
            "feed_size": "1",
            "ordering": "last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
        }
        for feed_type_str in ("", ",", "  ,  "):
            with self.subTest(feed_type=repr(feed_type_str)):
                serializer = AdvancedFeedRequestSerializer(data={**base_data, "feed_type": feed_type_str})
                with self.assertRaises(ValidationError):
                    serializer.is_valid(raise_exception=True)
                self.assertIn("feed_type", serializer.errors)

    def test_multi_feed_type_all_combined_invalid(self):
        """'all' combined with any other type must be rejected"""
        base_data = {
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "1",
            "min_days_seen": "1",
            "include_reputation": "",
            "exclude_reputation": "",
            "feed_size": "1",
            "ordering": "last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
        }
        for feed_type_str in ("all,cowrie", "cowrie,all", "all,cowrie,adbhoney"):
            with self.subTest(feed_type=feed_type_str):
                serializer = AdvancedFeedRequestSerializer(data={**base_data, "feed_type": feed_type_str})
                with self.assertRaises(ValidationError):
                    serializer.is_valid(raise_exception=True)
                self.assertIn("feed_type", serializer.errors)

    def test_invalid_fields(self):
        data_ = {
            "feed_type": "invalid_feed_type",
            "attack_type": "invalid_attack_type",
            "max_age": "0",
            "min_days_seen": "0",
            "include_reputation": "x" * 121,  # exceeds child CharField(max_length=120)
            "exclude_reputation": "x" * 121,
            "feed_size": "0",
            "ordering": "invalid_ordering",
            "verbose": "invalid_value",
            "paginate": "invalid_value",
            "format": "invalid_format",
        }
        serializer = AdvancedFeedRequestSerializer(data=data_)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("attack_type", serializer.errors)
            self.assertIn("max_age", serializer.errors)
            self.assertIn("min_days_seen", serializer.errors)
            self.assertIn("include_reputation", serializer.errors)
            self.assertIn("exclude_reputation", serializer.errors)
            self.assertIn("feed_size", serializer.errors)
            self.assertIn("ordering", serializer.errors)
            self.assertIn("verbose", serializer.errors)
            self.assertIn("paginate", serializer.errors)
            self.assertIn("format", serializer.errors)

    def _base_request_data(self):
        return {
            "feed_type": "all",
            "attack_type": "all",
            "ioc_type": "all",
            "max_age": "1",
            "min_days_seen": "1",
            "include_reputation": "",
            "exclude_reputation": "",
            "feed_size": "1",
            "ordering": "last_seen",
            "verbose": "false",
            "paginate": "false",
            "format": "json",
        }

    def test_min_expected_interactions_valid(self):
        """min_expected_interactions accepts valid non-negative floats and None."""
        for value in ["0", "0.0", "5.5", "100"]:
            with self.subTest(value=value):
                data_ = {**self._base_request_data(), "min_expected_interactions": value}
                serializer = AdvancedFeedRequestSerializer(data=data_)
                self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_min_expected_interactions_invalid(self):
        """min_expected_interactions rejects negative values."""
        data_ = {**self._base_request_data(), "min_expected_interactions": "-0.1"}
        serializer = AdvancedFeedRequestSerializer(data=data_)
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
        self.assertIn("min_expected_interactions", serializer.errors)


class FeedResponseSerializersTestCase(CustomTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.adbhoney = Honeypot.objects.filter(name__iexact="adbhoney").first()
        if not cls.adbhoney:
            cls.adbhoney = Honeypot.objects.create(name="Adbhoney", active=True)

    def test_valid_fields(self):
        scanner_choices = [True, False]
        payload_request_choices = [True, False]
        feed_type_choices = ["all", "log4pot", "cowrie", "adbhoney"]

        # generete all possible valid input data using cartesian product
        valid_data_choices = product(scanner_choices, payload_request_choices, feed_type_choices)

        for element in valid_data_choices:
            data_ = {
                "feed_type": [element[2]],
                "value": "140.246.171.141",
                SCANNER: element[0],
                PAYLOAD_REQUEST: element[1],
                "first_seen": "2023-03-20",
                "last_seen": "2023-03-21",
                "attack_count": "5",
                "interaction_count": "50",
                "ip_reputation": IpReputation.KNOWN_ATTACKER,
                "firehol_categories": [],
                "asn": "8400",
                "destination_port_count": "14",
                "login_attempts": "0",
                "recurrence_probability": "0.1",
                "expected_interactions": "11.1",
                "attacker_country": "Nepal",
                "attacker_country_code": "NP",
            }
            serializer = SimpleFeedResponseSerializer(
                data=data_,
                context={"valid_feed_types": frozenset(feed_type_choices)},
            )
            valid = serializer.is_valid(raise_exception=True)
            self.assertEqual(valid, True)

    def test_invalid_fields(self):
        valid_feed_types = frozenset(["all", "log4pot", "cowrie", "adbhoney"])
        data_ = {
            "feed_type": "invalid_feed_type",
            "value": True,
            SCANNER: "invalid_scanner",
            PAYLOAD_REQUEST: "invalid_payload_request",
            "first_seen": "31-2023-03",
            "last_seen": "31-2023-03",
            "attack_count": "0",
            "interaction_count": "0",
            "ip_reputation": "A" * 64,
            "asn": "8400ABC",
            "destination_port_count": "-1",
            "login_attempts": "-1",
            "recurrence_probability": "1.1",
            "expected_interactions": "-1",
            "attacker_country_code": "INV",
        }
        serializer = SimpleFeedResponseSerializer(
            data=data_,
            context={"valid_feed_types": valid_feed_types},
        )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            self.assertIn("feed_type", serializer.errors)
            self.assertIn("value", serializer.errors)
            self.assertIn(SCANNER, serializer.errors)
            self.assertIn(PAYLOAD_REQUEST, serializer.errors)
            self.assertIn("first_seen", serializer.errors)
            self.assertIn("last_seen", serializer.errors)
            self.assertIn("attack_count", serializer.errors)
            self.assertIn("interaction_count", serializer.errors)
            self.assertIn("ip_reputation", serializer.errors)
            self.assertIn("asn", serializer.errors)
            self.assertIn("login_attempts", serializer.errors)
            self.assertIn("recurrence_probability", serializer.errors)
            self.assertIn("expected_interactions", serializer.errors)
            self.assertIn("attacker_country_code", serializer.errors)


class IOCSerializerTestCase(CustomTestCase):
    def test_ioc_serializer_with_sensors(self):
        s1 = Sensor.objects.create(address="10.0.0.1", label="home-pi")
        s2 = Sensor.objects.create(address="10.0.0.2")

        self.ioc.sensors.add(s1, s2)

        serializer = IOCSerializer(self.ioc)
        data = serializer.data

        self.assertIn("sensors", data)
        self.assertEqual(len(data["sensors"]), 2)

        sensors_data = sorted(data["sensors"], key=lambda x: x["address"])
        self.assertEqual(sensors_data[0]["address"], "10.0.0.1")
        self.assertEqual(sensors_data[0]["label"], "home-pi")
        self.assertEqual(sensors_data[1]["address"], "10.0.0.2")
        self.assertEqual(sensors_data[1]["label"], "")
