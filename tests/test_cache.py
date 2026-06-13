from hashlib import sha256
from unittest.mock import MagicMock, patch

from django.core.cache import caches
from django.test import override_settings

from greedybear.cache import Cache, build_versioned_key
from greedybear.consts import API_CACHE_ALIAS, IOC_DATA_VERSION_KEY
from greedybear.models import IOC, IocType
from tests import CustomTestCase, E2ETestCase, MockElasticHit

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


@override_settings(CACHES=TEST_CACHES)
class FeedsCacheInvalidationEndpointTest(CustomTestCase):
    """Ensures the CachedResponseMixin caches the rendered response
    and that bumping the data version orphans it."""

    URL = "/api/feeds/all/all/recent.json?include_mass_scanners&include_tor_exit_nodes"

    def _get_ioc_names(self, response) -> set:
        return {ioc["value"] for ioc in response.json()["iocs"]}

    def _create_feed_ioc(self, name: str) -> IOC:
        """Create an active-honeypot IP IOC that will be incuded in the feed."""
        ioc = IOC.objects.create(
            name=name,
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[self.current_time.date()],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="",
            destination_ports=[22],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=1.0,
        )
        ioc.honeypots.add(self.cowrie_hp)
        ioc.save()
        return ioc

    def test_response_is_cached_then_invalidated_by_version_bump(self):
        # 1. Populate cache
        first = self.client.get(self.URL)
        self.assertEqual(first.status_code, 200)
        baseline = self._get_ioc_names(first)
        self.assertIn(self.ioc.name, baseline)

        # 2. Add a new IOC WITHOUT bumping the version
        new_ip = "22.3.4.55"
        self._create_feed_ioc(new_ip)
        cached = self.client.get(self.URL)
        self.assertEqual(cached.status_code, 200)
        self.assertEqual(self._get_ioc_names(cached), baseline)
        self.assertNotIn(new_ip, self._get_ioc_names(cached))

        # 3. Bump the data version
        Cache(API_CACHE_ALIAS).bump_data_version(IOC_DATA_VERSION_KEY)
        fresh = self.client.get(self.URL)
        self.assertEqual(fresh.status_code, 200)
        self.assertIn(new_ip, self._get_ioc_names(fresh))
        self.assertEqual(self._get_ioc_names(fresh), baseline | {new_ip})


class FeedsCacheInvalidationPipelineTest(E2ETestCase):
    """Ensures a working pipeline invalidation trigger."""

    def _data_version(self) -> int:
        """Helper for retrieving the data version from cache."""
        return Cache(API_CACHE_ALIAS).get_data_version(IOC_DATA_VERSION_KEY)

    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_does_not_bump_version_when_no_iocs(self, _mock_scores):
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.elastic_repo.search.return_value = []  # no chunks -> 0 IOCs -> no invalidation

        before = self._data_version()
        count = pipeline.execute()

        self.assertEqual(count, 0)
        self.assertEqual(self._data_version(), before)

    @patch("greedybear.cronjobs.extraction.pipeline.BucketUpdater")
    @patch("greedybear.cronjobs.extraction.pipeline.ExtractionStrategyFactory")
    @patch("greedybear.cronjobs.extraction.pipeline.UpdateScores")
    def test_execute_bumps_version_when_iocs_processed(self, _mock_scores, mock_factory_cls, mock_bucket_cls):
        pipeline = self._create_pipeline_with_real_factory()
        pipeline.elastic_repo.search.return_value = [[MockElasticHit({"src_ip": "1.2.3.4", "type": "Cowrie"})]]
        pipeline.ioc_repo.is_ready_for_extraction.return_value = True

        # Strategy yields one IOC record -> invalidation
        strategy = MagicMock()
        strategy.ioc_records = [MagicMock()]
        mock_factory_cls.return_value.get_strategy.return_value = strategy
        # Keep the trending-cache branch out of this test.
        mock_bucket_cls.return_value.total_update_count = 0

        before = self._data_version()
        count = pipeline.execute()

        self.assertEqual(count, 1)
        self.assertEqual(self._data_version(), before + 1)
