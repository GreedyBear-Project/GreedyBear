from django.test import SimpleTestCase

from api.serializers.events import (
    NUL_REPLACEMENT,
    SURROGATE_REPLACEMENT,
    EventSerializer,
    sanitize_json,
    sanitize_text,
)


class SanitizeTextTests(SimpleTestCase):
    def test_nul_replaced_with_visible_marker(self):
        self.assertEqual(sanitize_text("admin\x00"), f"admin{NUL_REPLACEMENT}")

    def test_unpaired_surrogate_replaced_with_visible_marker(self):
        self.assertEqual(sanitize_text("x\ud800y"), f"x{SURROGATE_REPLACEMENT}y")

    def test_does_not_truncate_long_strings(self):
        payload = "a" * 300
        self.assertEqual(len(sanitize_text(payload)), 300)

    def test_clean_string_unchanged(self):
        self.assertEqual(sanitize_text("root"), "root")


class SanitizeJsonTests(SimpleTestCase):
    def test_nested_dict_value(self):
        result = sanitize_json({"outer": {"raw_username": "admin\x00"}})
        self.assertEqual(result["outer"]["raw_username"], f"admin{NUL_REPLACEMENT}")

    def test_nested_list(self):
        result = sanitize_json({"cmds": ["id", "whoami\x00"]})
        self.assertEqual(result["cmds"], ["id", f"whoami{NUL_REPLACEMENT}"])

    def test_dict_key_with_nul(self):
        result = sanitize_json({"bad\x00key": "ok"})
        self.assertEqual(result, {f"bad{NUL_REPLACEMENT}key": "ok"})

    def test_long_string_in_data_not_truncated(self):
        blob = "x" * 400
        result = sanitize_json({"note": blob})
        self.assertEqual(len(result["note"]), 400)

    def test_numbers_bools_none_unchanged(self):
        payload = {"n": 1, "ok": True, "missing": None, "f": 1.5}
        self.assertEqual(sanitize_json(payload), payload)

    def test_empty_dict_unchanged(self):
        self.assertEqual(sanitize_json({}), {})

    def test_tuple_walked_like_a_list(self):
        self.assertEqual(sanitize_json(("a\x00", 2)), [f"a{NUL_REPLACEMENT}", 2])


class EventSerializerDefaultDataTests(SimpleTestCase):
    def test_missing_data_defaults_to_dict(self):
        serializer = EventSerializer(
            data={
                "src_ip": "1.2.3.4",
                "event_type": "login_attempt",
                "timestamp": "2026-01-01T00:00:00",
                "sensor_id": 1,
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["data"], {})
