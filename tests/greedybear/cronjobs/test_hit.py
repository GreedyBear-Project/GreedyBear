from datetime import datetime

from greedybear.cronjobs.extraction.hit import Hit, SkipHitError
from tests import CustomTestCase

TS = "2026-09-29T10:00:00.000Z"


class TestHitMapping(CustomTestCase):
    """A wrapped hit must still work where hits are treated as plain dicts."""

    def test_reads_like_a_dict(self):
        hit = Hit({"src_ip": "1.2.3.4"})
        self.assertEqual(hit["src_ip"], "1.2.3.4")
        self.assertIn("src_ip", hit)
        self.assertEqual(len(hit), 1)

    def test_writes_like_a_dict(self):
        """ExtractionPipeline.execute() sets hit['_sensor'] on the way through."""
        hit = Hit({"src_ip": "1.2.3.4"})
        hit["_sensor"] = "sensor-object"
        self.assertEqual(hit["_sensor"], "sensor-object")

    def test_get_and_iteration(self):
        hit = Hit({"a": 1, "b": 2})
        self.assertEqual(hit.get("a"), 1)
        self.assertIsNone(hit.get("missing"))
        self.assertEqual(hit.get("missing", "fallback"), "fallback")
        self.assertEqual(sorted(hit), ["a", "b"])
        self.assertEqual(dict(hit), {"a": 1, "b": 2})

    def test_missing_key_still_raises_keyerror(self):
        with self.assertRaises(KeyError):
            Hit({})["nope"]

    def test_delete(self):
        hit = Hit({"a": 1})
        del hit["a"]
        self.assertEqual(len(hit), 0)


class TestRequire(CustomTestCase):
    def test_returns_value(self):
        self.assertEqual(Hit({"src_ip": "1.2.3.4"}).require("src_ip"), "1.2.3.4")

    def test_missing_key(self):
        with self.assertRaises(SkipHitError):
            Hit({}).require("src_ip")

    def test_none_value(self):
        with self.assertRaises(SkipHitError):
            Hit({"src_ip": None}).require("src_ip")

    def test_blank_string(self):
        """execute() already treats a whitespace-only src_ip as missing."""
        for blank in ("", "   ", "\t\n"):
            with self.assertRaises(SkipHitError):
                Hit({"src_ip": blank}).require("src_ip")

    def test_zero_is_not_missing(self):
        """A falsy non-string value is still a value."""
        self.assertEqual(Hit({"dest_port": 0}).require("dest_port"), 0)
        self.assertEqual(Hit({"duration": 0.0}).require("duration"), 0.0)

    def test_message_names_the_field(self):
        with self.assertRaises(SkipHitError) as ctx:
            Hit({}).require("@timestamp")
        self.assertIn("@timestamp", str(ctx.exception))


class TestRequireStr(CustomTestCase):
    def test_strips(self):
        self.assertEqual(Hit({"type": "  Cowrie  "}).require_str("type"), "Cowrie")

    def test_coerces(self):
        self.assertEqual(Hit({"session": 1234}).require_str("session"), "1234")

    def test_missing(self):
        with self.assertRaises(SkipHitError):
            Hit({}).require_str("type")


class TestRequireTime(CustomTestCase):
    def test_parses(self):
        self.assertEqual(Hit({"@timestamp": TS}).require_time("@timestamp"), datetime(2026, 9, 29, 10, 0, 0))

    def test_missing(self):
        with self.assertRaises(SkipHitError):
            Hit({}).require_time("@timestamp")

    def test_unparsable_is_skipped_not_raised_raw(self):
        """parse_timestamp raises ValueError on junk and TypeError on None."""
        for bad in ("not-a-date", "", "2026-13-45"):
            with self.assertRaises(SkipHitError):
                Hit({"@timestamp": bad}).require_time("@timestamp")

    def test_message_includes_the_value(self):
        with self.assertRaises(SkipHitError) as ctx:
            Hit({"@timestamp": "junk"}).require_time("@timestamp")
        self.assertIn("junk", str(ctx.exception))


class TestGetStr(CustomTestCase):
    def test_returns_stripped(self):
        self.assertEqual(Hit({"url": "  http://x  "}).get_str("url"), "http://x")

    def test_default_when_missing(self):
        self.assertEqual(Hit({}).get_str("url"), "")
        self.assertEqual(Hit({}).get_str("url", "none"), "none")

    def test_default_when_blank(self):
        self.assertEqual(Hit({"url": "   "}).get_str("url", "none"), "none")

    def test_default_when_none(self):
        self.assertEqual(Hit({"url": None}).get_str("url", "none"), "none")

    def test_coerces_non_string(self):
        self.assertEqual(Hit({"dest_port": 22}).get_str("dest_port"), "22")


class TestGetInt(CustomTestCase):
    def test_returns_int(self):
        self.assertEqual(Hit({"dest_port": 22}).get_int("dest_port"), 22)

    def test_parses_numeric_string(self):
        self.assertEqual(Hit({"dest_port": "22"}).get_int("dest_port"), 22)

    def test_default_when_missing(self):
        self.assertIsNone(Hit({}).get_int("dest_port"))
        self.assertEqual(Hit({}).get_int("dest_port", 0), 0)

    def test_default_when_not_numeric(self):
        self.assertEqual(Hit({"dest_port": "ssh"}).get_int("dest_port", -1), -1)

    def test_zero_is_preserved(self):
        self.assertEqual(Hit({"dest_port": 0}).get_int("dest_port", -1), 0)


class TestGetFloat(CustomTestCase):
    def test_returns_float(self):
        self.assertEqual(Hit({"duration": 12.5}).get_float("duration"), 12.5)

    def test_parses_numeric_string(self):
        self.assertEqual(Hit({"duration": "12.5"}).get_float("duration"), 12.5)

    def test_does_not_truncate(self):
        """CowrieSession.duration is a FloatField, so seconds must not be lost."""
        self.assertEqual(Hit({"duration": 0.75}).get_float("duration"), 0.75)

    def test_default_when_missing(self):
        self.assertIsNone(Hit({}).get_float("duration"))
        self.assertEqual(Hit({}).get_float("duration", 0.0), 0.0)

    def test_default_when_not_numeric(self):
        self.assertEqual(Hit({"duration": "long"}).get_float("duration", -1.0), -1.0)

    def test_zero_is_preserved(self):
        self.assertEqual(Hit({"duration": 0.0}).get_float("duration", -1.0), 0.0)


class TestGetTime(CustomTestCase):
    def test_parses(self):
        self.assertEqual(Hit({"@timestamp": TS}).get_time("@timestamp"), datetime(2026, 9, 29, 10, 0, 0))

    def test_default_when_missing(self):
        self.assertIsNone(Hit({}).get_time("@timestamp"))

    def test_default_when_unparsable(self):
        self.assertIsNone(Hit({"@timestamp": "junk"}).get_time("@timestamp"))

    def test_explicit_default(self):
        fallback = datetime(2020, 1, 1)
        self.assertEqual(Hit({"@timestamp": "junk"}).get_time("@timestamp", fallback), fallback)


class TestGetDict(CustomTestCase):
    def test_returns_dict(self):
        self.assertEqual(Hit({"geoip": {"country_name": "X"}}).get_dict("geoip"), {"country_name": "X"})

    def test_empty_when_missing(self):
        self.assertEqual(Hit({}).get_dict("geoip"), {})

    def test_empty_when_not_a_dict(self):
        """geoip is read with .get() chains, which break on a non-object."""
        for bad in ("string", 42, ["a"], None):
            self.assertEqual(Hit({"geoip": bad}).get_dict("geoip"), {})

    def test_chaining_is_safe(self):
        self.assertEqual(Hit({"geoip": "oops"}).get_dict("geoip").get("country_name", ""), "")
