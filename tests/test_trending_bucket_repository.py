from collections import Counter
from datetime import datetime

from greedybear.cronjobs.repositories.trending_bucket import TrendingBucketRepository
from greedybear.models import AttackerActivityBucket, Honeypot
from tests import CustomTestCase


class TestTrendingBucketRepository(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.repo = TrendingBucketRepository()

    def test_build_upsert_query_contains_expected_placeholders(self):
        query = self.repo._build_upsert_query('"greedybear_attackeractivitybucket"', 3)

        self.assertIn("INSERT INTO", query)
        self.assertEqual(query.count("(%s, %s, %s, %s)"), 3)
        self.assertIn("ON CONFLICT (attacker_ip, feed_type, bucket_start)", query)

    def test_build_upsert_params_flattens_batch(self):
        batch = [
            (("1.1.1.1", "cowrie", datetime(2026, 3, 20, 9, 0)), 2),
            (("2.2.2.2", "heralding", datetime(2026, 3, 20, 10, 0)), 4),
        ]

        params = self.repo._build_upsert_params(batch)

        self.assertEqual(
            params,
            [
                "1.1.1.1",
                "cowrie",
                datetime(2026, 3, 20, 9, 0),
                2,
                "2.2.2.2",
                "heralding",
                datetime(2026, 3, 20, 10, 0),
                4,
            ],
        )

    def test_normalize_feed_types_from_string(self):
        self.assertEqual(self.repo._normalize_feed_types("cowrie"), ["cowrie"])

    def test_normalize_feed_types_from_iterable(self):
        self.assertEqual(self.repo._normalize_feed_types(("cowrie", "heralding")), ["cowrie", "heralding"])

    def test_upsert_bucket_counts_returns_zero_for_empty_counter(self):
        self.assertEqual(self.repo.upsert_bucket_counts(Counter()), 0)

    def test_get_counts_in_window_filters_feed_types(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=4,
                ),
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="heralding",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=2,
                ),
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=3,
                ),
            ]
        )

        counts = self.repo.get_counts_in_window(
            window_start=datetime(2026, 3, 20, 9, 0),
            window_end=datetime(2026, 3, 20, 10, 0),
            feed_types=["cowrie"],
        )

        self.assertEqual(counts, {"1.1.1.1": 4, "2.2.2.2": 3})

    def test_get_counts_in_window_with_all_feed_type_combines_totals(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=4,
                ),
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="heralding",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=2,
                ),
            ]
        )

        counts = self.repo.get_counts_in_window(
            window_start=datetime(2026, 3, 20, 9, 0),
            window_end=datetime(2026, 3, 20, 10, 0),
            feed_types="all",
        )

        self.assertEqual(counts, {"1.1.1.1": 6})

    def test_get_counts_in_window_ignores_disabled_honeypots(self):
        # Ddospot is disabled in the test fixtures
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=4,
                ),
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="ddospot",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=100,
                ),
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="ddospot",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=500,
                ),
            ]
        )

        counts = self.repo.get_counts_in_window(
            window_start=datetime(2026, 3, 20, 9, 0),
            window_end=datetime(2026, 3, 20, 10, 0),
            feed_types="all",
        )

        self.assertEqual(counts, {"1.1.1.1": 4})

    def test_get_counts_in_window_returns_empty_for_disabled_honeypot_feed_type(self):
        AttackerActivityBucket.objects.create(
            attacker_ip="2.2.2.2",
            feed_type="ddospot",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=500,
        )

        counts = self.repo.get_counts_in_window(
            window_start=datetime(2026, 3, 20, 9, 0),
            window_end=datetime(2026, 3, 20, 10, 0),
            feed_types=["ddospot"],
        )

        self.assertEqual(counts, {})

    def test_get_counts_in_window_stops_counting_a_honeypot_once_disabled(self):
        AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=4,
        )
        window = {"window_start": datetime(2026, 3, 20, 9, 0), "window_end": datetime(2026, 3, 20, 10, 0), "feed_types": "all"}
        self.assertEqual(self.repo.get_counts_in_window(**window), {"1.1.1.1": 4})

        Honeypot.objects.filter(name="Cowrie").update(active=False)

        self.assertEqual(self.repo.get_counts_in_window(**window), {})

    def test_get_counts_in_window_returns_empty_when_no_matches(self):
        counts = self.repo.get_counts_in_window(
            window_start=datetime(2026, 3, 20, 9, 0),
            window_end=datetime(2026, 3, 20, 10, 0),
            feed_types=["cowrie"],
        )
        self.assertEqual(counts, {})

    def test_delete_older_than_removes_only_older_rows(self):
        old_bucket = AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 7, 0),
            interaction_count=1,
        )
        fresh_bucket = AttackerActivityBucket.objects.create(
            attacker_ip="2.2.2.2",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=1,
        )

        deleted_count = self.repo.delete_older_than(datetime(2026, 3, 20, 8, 0))

        self.assertEqual(deleted_count, 1)
        self.assertFalse(AttackerActivityBucket.objects.filter(id=old_bucket.id).exists())
        self.assertTrue(AttackerActivityBucket.objects.filter(id=fresh_bucket.id).exists())
