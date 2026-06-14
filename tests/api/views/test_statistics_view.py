from django.test import override_settings

from greedybear.cache import Cache
from greedybear.consts import API_CACHE_ALIAS, IOC_DATA_VERSION_KEY
from greedybear.models import IOC, Honeypot, IocType, Statistics, ViewType
from tests import CustomTestCase

TEST_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greedybear-default",
    },
    "api": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "greedybear-test-statistics-api-cache",
    },
}


class StatisticsViewTestCase(CustomTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        Statistics.objects.all().delete()
        Statistics.objects.create(source="140.246.171.141", view=ViewType.FEEDS_VIEW.value)
        Statistics.objects.create(source="140.246.171.141", view=ViewType.ENRICHMENT_VIEW.value)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Statistics.objects.all().delete()

    def test_200_feeds_sources(self):
        response = self.client.get("/api/statistics/sources/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_feeds_downloads(self):
        response = self.client.get("/api/statistics/downloads/feeds")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Downloads"], 1)

    def test_200_enrichment_sources(self):
        response = self.client.get("/api/statistics/sources/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Sources"], 1)

    def test_200_enrichment_requests(self):
        response = self.client.get("/api/statistics/requests/enrichment")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["Requests"], 1)

    def test_200_feed_types(self):
        # Count honeypots before adding new one
        initial_count = Honeypot.objects.count()
        # add a general honeypot without associated ioc
        Honeypot(name="Tanner", active=True).save()
        self.assertEqual(Honeypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/statistics/feeds_types")
        self.assertEqual(response.status_code, 200)
        # Expecting 3 because setupTestData creates 3 IOCs (ioc, ioc_2, ioc_domain) associated with Heralding
        self.assertEqual(response.json()[0]["Heralding"], 3)
        self.assertEqual(response.json()[0]["Ciscoasa"], 2)
        self.assertEqual(response.json()[0]["Log4pot"], 3)
        self.assertEqual(response.json()[0]["Cowrie"], 3)
        self.assertEqual(response.json()[0]["Tanner"], 0)

    def test_200_countries(self):
        response = self.client.get("/api/statistics/countries")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        countries = [item["country"] for item in data]
        counts = {item["country"]: item["count"] for item in data}
        # China appears on ioc + ioc_2 (both active), United States on ioc_3 (active)
        # Russia is only on ioc_inactive_country (ddospot, inactive); must be excluded
        self.assertIn("China", countries)
        self.assertIn("United States", countries)
        self.assertNotIn("Russia", countries)
        self.assertEqual(counts["China"], 2)
        self.assertEqual(counts["United States"], 1)

        # check codes
        codes = {item["country"]: item["code"] for item in data}
        self.assertEqual(codes["China"], "CN")
        self.assertEqual(codes["United States"], "US")

        # Results must be ordered descending by count
        count_values = [item["count"] for item in data]
        self.assertEqual(count_values, sorted(count_values, reverse=True))


@override_settings(CACHES=TEST_CACHES)
class StatisticsIocCacheTestCase(CustomTestCase):
    def _create_country_ioc(self, name: str, country: str, code: str) -> IOC:
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
            attacker_country=country,
            attacker_country_code=code,
        )
        ioc.honeypots.add(self.cowrie_hp)
        ioc.save()
        return ioc

    def _country_names(self, response) -> set[str]:
        return {item["country"] for item in response.json()}

    def test_countries_response_is_cached_then_invalidated_by_version_bump(self):
        url = "/api/statistics/countries?range=7d"

        first = self.client.get(url)
        self.assertEqual(first.status_code, 200)
        baseline = self._country_names(first)
        self.assertIn("China", baseline)

        self._create_country_ioc("22.3.4.66", "Japan", "JP")
        cached = self.client.get(url)
        self.assertEqual(cached.status_code, 200)
        self.assertEqual(self._country_names(cached), baseline)
        self.assertNotIn("Japan", self._country_names(cached))

        Cache(API_CACHE_ALIAS).bump_data_version(IOC_DATA_VERSION_KEY)
        fresh = self.client.get(url)
        self.assertEqual(fresh.status_code, 200)
        self.assertIn("Japan", self._country_names(fresh))

    def test_countries_cache_key_includes_range(self):
        seven_day = "/api/statistics/countries?range=7d"
        one_day = "/api/statistics/countries?range=1d"

        first = self.client.get(seven_day)
        self.assertEqual(first.status_code, 200)
        seven_day_baseline = self._country_names(first)

        self._create_country_ioc("22.3.4.67", "Japan", "JP")
        different_range = self.client.get(one_day)
        self.assertEqual(different_range.status_code, 200)
        self.assertEqual(self._country_names(self.client.get(seven_day)), seven_day_baseline)
        self.assertIn("Japan", self._country_names(different_range))

    def test_feeds_types_response_is_cached_then_invalidated_by_version_bump(self):
        url = "/api/statistics/feeds_types?range=7d"

        first = self.client.get(url)
        self.assertEqual(first.status_code, 200)
        baseline = first.json()[0]

        tanner = Honeypot.objects.create(name="Tanner", active=True)
        ioc = self._create_country_ioc("22.3.4.68", "Japan", "JP")
        ioc.honeypots.add(tanner)
        ioc.save()

        cached = self.client.get(url)
        self.assertEqual(cached.status_code, 200)
        self.assertEqual(cached.json()[0], baseline)
        self.assertNotIn("Tanner", cached.json()[0])

        Cache(API_CACHE_ALIAS).bump_data_version(IOC_DATA_VERSION_KEY)
        fresh = self.client.get(url)
        self.assertEqual(fresh.status_code, 200)
        self.assertEqual(fresh.json()[0]["Tanner"], 1)
