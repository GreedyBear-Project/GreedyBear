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

    def test_clean_over_max_length_is_not_truncated(self):
        # A clean value that is already too long must still fail CharField
        # validation. Only the expansion from a marker is fitted.
        value = "a" * 256
        self.assertEqual(sanitize_text(value, max_length=255), value)

    def test_surrogate_expansion_fits_max_length_and_keeps_marker(self):
        result = sanitize_text("a" * 254 + "\ud800", max_length=255)
        self.assertEqual(result, "a" * 250 + SURROGATE_REPLACEMENT)
        self.assertEqual(len(result), 255)

    def test_nul_expansion_fits_max_length_and_keeps_marker(self):
        # 254 chars + NUL would be 258 after replacement, over a 255 cap.
        # Naive slicing would cut the marker to "[NU".
        result = sanitize_text("a" * 254 + "\x00", max_length=255)
        self.assertEqual(result, "a" * 250 + NUL_REPLACEMENT)
        self.assertEqual(len(result), 255)
        self.assertNotIn("\x00", result)

    def test_leading_nul_keeps_marker_and_drops_the_tail(self):
        result = sanitize_text("\x00" + "a" * 254, max_length=255)
        self.assertEqual(result, NUL_REPLACEMENT + "a" * 250)

    def test_multiple_markers_are_kept_whole(self):
        result = sanitize_text("a" * 251 + "\x00\x00", max_length=255)
        self.assertEqual(result, "a" * 245 + NUL_REPLACEMENT * 2)
        self.assertEqual(len(result), 255)

    def test_surplus_markers_are_dropped_whole(self):
        # 60 NULs expand to 300 chars. 51 markers fill 255 exactly.
        result = sanitize_text("\x00" * 60, max_length=255)
        self.assertEqual(result, NUL_REPLACEMENT * 51)
        self.assertEqual(len(result), 255)

    def test_no_max_length_leaves_long_dirty_text(self):
        result = sanitize_text("a" * 300 + "\x00")
        self.assertEqual(result, "a" * 300 + NUL_REPLACEMENT)


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

    def test_colliding_sanitised_keys_keep_both_values(self):
        result = sanitize_json({"a\x00": "first", "a[NUL]": "second"})
        self.assertEqual(result["a[NUL]"], "first")
        self.assertEqual(result["a[NUL]~2"], "second")

    def test_suffix_itself_colliding_is_not_overwritten(self):
        result = sanitize_json({"a\x00": "first", "a[NUL]": "second", "a[NUL]~2": "third"})
        self.assertEqual(result["a[NUL]"], "first")
        self.assertEqual(result["a[NUL]~2"], "second")
        self.assertEqual(result["a[NUL]~2~2"], "third")

    def test_long_string_in_data_not_truncated(self):
        blob = "x" * 400
        result = sanitize_json({"note": blob})
        self.assertEqual(len(result["note"]), 400)

    def test_numbers_bools_none_unchanged(self):
        payload = {"n": 1, "ok": True, "missing": None, "f": 1.5}
        self.assertEqual(sanitize_json(payload), payload)

    def test_empty_dict_unchanged(self):
        self.assertEqual(sanitize_json({}), {})

    def test_nested_list_of_objects(self):
        result = sanitize_json([{"user\x00": "a\x00"}, "ok"])
        self.assertEqual(result, [{f"user{NUL_REPLACEMENT}": f"a{NUL_REPLACEMENT}"}, "ok"])


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

    def test_username_at_254_plus_nul_stays_valid(self):
        serializer = EventSerializer(
            data={
                "src_ip": "1.2.3.4",
                "event_type": "login_attempt",
                "timestamp": "2026-01-01T00:00:00",
                "sensor_id": 1,
                "username": "a" * 254 + "\x00",
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        username = serializer.validated_data["username"]
        self.assertEqual(username, "a" * 250 + NUL_REPLACEMENT)
        self.assertLessEqual(len(username), 255)

    def test_clean_username_over_max_length_is_rejected(self):
        serializer = EventSerializer(
            data={
                "src_ip": "1.2.3.4",
                "event_type": "login_attempt",
                "timestamp": "2026-01-01T00:00:00",
                "sensor_id": 1,
                "username": "a" * 256,
            }
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("username", serializer.errors)

    def test_command_is_not_capped(self):
        command = "a" * 300 + "\x00"
        serializer = EventSerializer(
            data={
                "src_ip": "1.2.3.4",
                "event_type": "login_attempt",
                "timestamp": "2026-01-01T00:00:00",
                "sensor_id": 1,
                "command": command,
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["command"], "a" * 300 + NUL_REPLACEMENT)
