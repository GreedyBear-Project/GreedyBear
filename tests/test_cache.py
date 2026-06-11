from hashlib import sha256

from django.core.cache import caches
from django.test import override_settings

from greedybear.cache import Cache, build_versioned_key
from greedybear.consts import API_CACHE_ALIAS
from tests import CustomTestCase

TEST_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greedybear-default",
    },
    "api": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greedybear-test-api-cache",
    },
}


class TestBuildVersionedKey(CustomTestCase):
    def test_key_has_expected_structure(self):
        material = "FeedsView|/api/feeds/|type=ip"
        expected_digest = sha256(material.encode("utf-8")).hexdigest()
        self.assertEqual(build_versioned_key("feeds", 3, material), f"feeds_v3_{expected_digest}")

    def test_key_is_deterministic(self):
        self.assertEqual(
            build_versioned_key("feeds", 1, "same-material"),
            build_versioned_key("feeds", 1, "same-material"),
        )

    def test_different_material_yields_different_key(self):
        self.assertNotEqual(
            build_versioned_key("feeds", 1, "material-a"),
            build_versioned_key("feeds", 1, "material-b"),
        )

    def test_version_bump_changes_key(self):
        self.assertNotEqual(
            build_versioned_key("feeds", 1, "material"),
            build_versioned_key("feeds", 2, "material"),
        )

    def test_namespace_changes_key(self):
        self.assertNotEqual(
            build_versioned_key("feeds", 1, "material"),
            build_versioned_key("enrichment", 1, "material"),
        )


@override_settings(CACHES=TEST_CACHES)
class TestCache(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cache = Cache(API_CACHE_ALIAS)

    def test_set_then_get_preserves_value(self):
        self.cache.set("key", {"a": 1})
        self.assertEqual(self.cache.get("key"), {"a": 1})

    def test_get_missing_key_returns_none(self):
        self.assertIsNone(self.cache.get("does-not-exist"))

    def test_targets_the_configured_alias(self):
        self.cache.set("key", "some_odd_value")
        self.assertEqual(caches[API_CACHE_ALIAS].get("key"), "some_odd_value")
        self.assertIsNone(caches["default"].get("key"))

    def test_get_data_version_defaults_to_one_when_unset(self):
        self.assertEqual(self.cache.get_data_version("ver"), 1)

    def test_get_data_version_returns_stored_value(self):
        self.cache.set("ver", 7)
        self.assertEqual(self.cache.get_data_version("ver"), 7)

    def test_bump_data_version_from_unset_sets_two(self):
        self.cache.bump_data_version("ver")
        self.assertEqual(self.cache.get_data_version("ver"), 2)

    def test_bump_data_version_increments_existing_value(self):
        self.cache.set("ver", 5)
        self.cache.bump_data_version("ver")
        self.assertEqual(self.cache.get_data_version("ver"), 6)

    def test_repeated_bumps_keep_incrementing(self):
        self.cache.bump_data_version("ver")  # -> 2
        self.cache.bump_data_version("ver")  # -> 3
        self.cache.bump_data_version("ver")  # -> 4
        self.assertEqual(self.cache.get_data_version("ver"), 4)
