import json
from hashlib import sha256
from unittest.mock import MagicMock, patch

from django.core.cache import caches
from django.test import override_settings
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory

from api.views.feeds import AdvancedFeedView
from greedybear.cache import Cache, build_versioned_key, invalidate_ioc_cache
from greedybear.consts import API_CACHE_ALIAS, IOC_DATA_VERSION_KEY
from greedybear.cronjobs.enrichment.base_enrichment import BaseEnrichmentJob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC, IocType, Tag
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

# Same backend as production. TIMEOUT=0 makes anything saved with the default timeout expire immediately.
DB_CACHES = {
    **TEST_CACHES,
    "api": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "greedybear_api_cache",
        "TIMEOUT": 0,
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

    def test_invalidate_ioc_cache_bumps_version(self):
        before = self.cache.get_data_version(IOC_DATA_VERSION_KEY)
        invalidate_ioc_cache()
        self.assertEqual(self.cache.get_data_version(IOC_DATA_VERSION_KEY), before + 1)


@override_settings(CACHES=TEST_CACHES)
class EnrichmentWriteInvalidationTestCase(CustomTestCase):
    """Tag writes through the shared enrichment funnel must orphan cached feeds."""

    def test_write_tags_bumps_version(self):
        class ProbeJob(BaseEnrichmentJob):
            SOURCE_NAME = "probe-source"

            def run(self) -> None:
                pass

        cache = Cache(API_CACHE_ALIAS)
        before = cache.get_data_version(IOC_DATA_VERSION_KEY)
        ProbeJob(tag_repo=TagRepository())._write_tags([{"ioc_id": self.ioc.id, "key": "k", "value": "v"}])
        self.assertEqual(cache.get_data_version(IOC_DATA_VERSION_KEY), before + 1)
        self.assertTrue(Tag.objects.filter(source="probe-source").exists())


@override_settings(CACHES=DB_CACHES)
class TestCacheDataVersionOnDatabaseCache(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cache = Cache(API_CACHE_ALIAS)
        self.cache.clear()

    def test_repeated_bumps_do_not_expire(self):
        self.cache.bump_data_version("ver")  # -> 2
        self.cache.bump_data_version("ver")  # -> 3
        self.assertEqual(self.cache.get_data_version("ver"), 3)


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

    @override_settings(FEEDS_LICENSE="")
    def test_empty_text_feeds_are_not_cached(self):
        IOC.objects.all().delete()

        for feed_format in ("txt", "csv"):
            with self.subTest(feed_format=feed_format):
                url = f"/api/feeds/all/all/recent.{feed_format}"
                first = self.client.get(url)
                second = self.client.get(url)

                self.assertEqual(first.status_code, 200)
                self.assertEqual(first.content, b"")
                self.assertEqual(second.status_code, 200)
                self.assertEqual(second.content, b"")


@override_settings(CACHES=TEST_CACHES)
class CacheKeyMediaTypeTest(CustomTestCase):
    """The negotiated media type has to reach the key material."""

    def _cache_key(self, accepted_media_type: str | None = None) -> str | None:
        """Build the cache key a feed view would use for the given negotiated media type.
        Leave accepted_media_type unset to model a request that never reached negotiation."""
        view = AdvancedFeedView()
        request = Request(APIRequestFactory().get("/api/feeds/advanced/"))
        if accepted_media_type is not None:
            request.accepted_media_type = accepted_media_type
        view.request = request
        return view.cache_key

    def test_different_media_types_yield_different_keys(self):
        self.assertNotEqual(
            self._cache_key("application/json"),
            self._cache_key("application/x-ndjson"),
        )

    def test_same_media_type_yields_the_same_key(self):
        self.assertEqual(
            self._cache_key("application/json"),
            self._cache_key("application/json"),
        )

    def test_unnegotiated_request_still_gets_a_key(self):
        self.assertIsNotNone(self._cache_key())


@override_settings(CACHES=TEST_CACHES)
class FeedsCacheMediaTypeTest(CustomTestCase):
    """AdvancedFeedView picks NDJSON off the Accept header, so an NDJSON client
    must not be served the entry a JSON client warmed for the same URL."""

    URL = "/api/feeds/advanced/"
    NDJSON_HEADER = {"HTTP_ACCEPT": "application/x-ndjson"}

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
        caches[API_CACHE_ALIAS].clear()
        self.expected_values = {self.ioc.name, self.ioc_2.name, self.ioc_3.name, self.ioc_domain.name}

    def _json_values(self, response) -> set:
        """Extract the IOC values from a JSON feed envelope."""
        return {ioc["value"] for ioc in response.json()["iocs"]}

    def _ndjson_values(self, response) -> set:
        """Extract the IOC values from an NDJSON feed, one record per line."""
        body = b"".join(response.streaming_content).decode("utf-8")
        return {json.loads(line)["value"] for line in body.splitlines() if line.strip()}

    def test_ndjson_client_is_not_served_the_cached_json_response(self):
        warm = self.client.get(self.URL)
        self.assertEqual(warm.status_code, 200)
        self.assertEqual(warm["content-type"], "application/json")
        self.assertEqual(self._json_values(warm), self.expected_values)

        ndjson = self.client.get(self.URL, **self.NDJSON_HEADER)
        self.assertEqual(ndjson.status_code, 200)
        self.assertEqual(ndjson["content-type"], "application/x-ndjson")
        self.assertEqual(self._ndjson_values(ndjson), self.expected_values)

    def test_json_client_is_not_affected_by_an_ndjson_request(self):
        self.client.get(self.URL, **self.NDJSON_HEADER)

        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["content-type"], "application/json")
        self.assertEqual(self._json_values(response), self.expected_values)

    def test_json_response_is_still_cached(self):
        first = self.client.get(self.URL)
        self.assertEqual(first.status_code, 200)

        with patch.object(AdvancedFeedView, "get_queryset") as mocked_queryset:
            second = self.client.get(self.URL)

        self.assertEqual(second.status_code, 200)
        self.assertEqual(self._json_values(second), self.expected_values)
        mocked_queryset.assert_not_called()


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
