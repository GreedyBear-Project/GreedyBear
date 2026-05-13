from datetime import datetime
from unittest.mock import patch

from django.core.cache import cache, caches

from api.throttles import FeedsThrottle
from greedybear.models import AttackerActivityBucket
from tests import CustomTestCase


class FeedsTrendingViewTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        caches["django-q"].clear()
        self.url = "/api/feeds/trending/"

    def test_200_trending_returns_ranked_attackers(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                # Previous window: 08:00-09:00
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 8, 0),
                    interaction_count=2,
                ),
                # Current window: 09:00-10:00
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=10,
                ),
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=5,
                ),
            ]
        )

        with patch("api.views.feeds.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            response = self.client.get(f"{self.url}?feed_type=cowrie&window_minutes=60&limit=10")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["window_minutes"], 60)
        self.assertEqual(payload["feed_type"], ["cowrie"])
        self.assertEqual(payload["data_source"], "aggregated")
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["attackers"][0]["attacker_ip"], "1.1.1.1")
        self.assertTrue(payload["current_window"]["end"].startswith("2026-03-20T10:00:00"))
        self.assertTrue(payload["previous_window"]["end"].startswith("2026-03-20T09:00:00"))

    def test_200_trending_filters_by_feed_type(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="3.3.3.3",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=4,
                ),
                AttackerActivityBucket(
                    attacker_ip="4.4.4.4",
                    feed_type="heralding",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=9,
                ),
            ]
        )

        with patch("api.views.feeds.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            cowrie_response = self.client.get(f"{self.url}?feed_type=cowrie&window_minutes=60&limit=10")
            all_response = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")

        self.assertEqual(cowrie_response.status_code, 200)
        cowrie_attackers = {entry["attacker_ip"] for entry in cowrie_response.json()["attackers"]}
        self.assertEqual(cowrie_attackers, {"3.3.3.3"})

        self.assertEqual(all_response.status_code, 200)
        all_attackers = {entry["attacker_ip"] for entry in all_response.json()["attackers"]}
        self.assertEqual(all_attackers, {"3.3.3.3", "4.4.4.4"})

    def test_400_trending_rejects_invalid_window_minutes(self):
        response = self.client.get(f"{self.url}?window_minutes=90")
        self.assertEqual(response.status_code, 400)
        errors = response.json().get("errors", response.json())
        self.assertIn("window_minutes", errors)

    def test_trending_uses_cache_for_same_query_and_window(self):
        with patch("api.views.feeds.TrendingBucketRepository.get_counts_in_window") as mock_get_counts:
            mock_get_counts.side_effect = [
                {"5.5.5.5": 10},
                {"5.5.5.5": 6},
            ]
            with patch("api.views.feeds.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
                response_1 = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")
                response_2 = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")

        self.assertEqual(response_1.status_code, 200)
        self.assertEqual(response_2.status_code, 200)
        self.assertEqual(mock_get_counts.call_count, 2)
        self.assertEqual(response_1.json(), response_2.json())

    def test_trending_cache_version_bump_forces_recompute(self):
        with patch("api.views.feeds.TrendingBucketRepository.get_counts_in_window") as mock_get_counts:
            mock_get_counts.side_effect = [
                {"6.6.6.6": 7},
                {"6.6.6.6": 2},
                {"6.6.6.6": 7},
                {"6.6.6.6": 2},
            ]
            with patch("api.views.feeds.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
                first = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")
                shared_cache = caches["django-q"]
                try:
                    shared_cache.incr("trending_feeds_version")
                except ValueError:
                    shared_cache.set("trending_feeds_version", 2, timeout=None)
                second = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(mock_get_counts.call_count, 4)

    def test_trending_endpoint_uses_feeds_throttle(self):
        cache.clear()
        try:
            with patch.object(FeedsThrottle, "THROTTLE_RATES", {"feeds": "1/minute"}):
                first = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")
                second = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")
        finally:
            cache.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_trending_and_regular_feeds_share_same_throttle_scope(self):
        cache.clear()
        try:
            with patch.object(FeedsThrottle, "THROTTLE_RATES", {"feeds": "1/minute"}):
                first = self.client.get("/api/feeds/all/all/recent.json")
                second = self.client.get(f"{self.url}?feed_type=all&window_minutes=60&limit=10")
        finally:
            cache.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
