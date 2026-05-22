from datetime import datetime
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from greedybear.cronjobs.bucket_cleanup import TrendingBucketCleanupCron
from greedybear.cronjobs.extraction.bucket_updater import BucketUpdater
from greedybear.cronjobs.repositories.trending_bucket import TrendingBucketRepository
from greedybear.cronjobs.trending import (
    attacker_sort_tuple,
    build_ranked_attackers,
    growth_score,
    rank_delta,
    validate_window_minutes,
)
from greedybear.models import AttackerActivityBucket
from tests import CustomTestCase


class TrendingHelpersTestCase(SimpleTestCase):
    def test_growth_score(self):
        self.assertEqual(growth_score(10, 0), 10.0)
        self.assertEqual(growth_score(12, 8), 0.5)
        self.assertEqual(growth_score(8, 12), -0.3333)

    def test_rank_delta(self):
        self.assertEqual(rank_delta(2, 5), 3)
        self.assertEqual(rank_delta(None, 5), -5)
        self.assertIsNone(rank_delta(3, None))
        self.assertIsNone(rank_delta(None, None))

    def test_attacker_sort_tuple_prefers_ranked_entries(self):
        ranked = attacker_sort_tuple("1.1.1.1", 2, 10, 7)
        unranked = attacker_sort_tuple("2.2.2.2", None, 10, 7)
        self.assertLess(ranked, unranked)

    def test_build_ranked_attackers_uses_current_and_previous_candidates(self):
        current_counts = {"1.1.1.1": 12, "2.2.2.2": 10, "3.3.3.3": 8}
        previous_counts = {"9.9.9.9": 30, "1.1.1.1": 9}

        ranked = build_ranked_attackers(current_counts, previous_counts, limit=3)

        self.assertEqual(len(ranked), 3)
        self.assertEqual(ranked[0]["attacker_ip"], "1.1.1.1")
        returned_ips = {entry["attacker_ip"] for entry in ranked}
        self.assertIn("9.9.9.9", returned_ips)
        self.assertEqual(next(entry for entry in ranked if entry["attacker_ip"] == "9.9.9.9")["current_rank"], None)


class ValidateWindowMinutesTestCase(SimpleTestCase):
    def test_validate_window_minutes_returns_valid_value(self):
        self.assertEqual(validate_window_minutes(120, 240), 120)

    def test_validate_window_minutes_raises_when_above_max(self):
        with self.assertRaisesMessage(ValueError, "window_minutes cannot be greater than 240"):
            validate_window_minutes(300, 240)

    def test_validate_window_minutes_raises_when_not_multiple_of_60(self):
        with self.assertRaisesMessage(ValueError, "window_minutes must be a multiple of 60"):
            validate_window_minutes(90, 240)


class UpdateActivityBucketsFromHitsTestCase(CustomTestCase):
    def test_upsert_increments_existing_bucket_and_creates_missing_bucket(self):
        AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=3,
        )

        bu = BucketUpdater()
        bu.collect_hits(
            [
                {"src_ip": "1.1.1.1", "type": "Cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "1.1.1.1", "type": "cowrie", "@timestamp": "2026-03-20T09:50:00"},
                {"src_ip": "2.2.2.2", "type": "Heralding", "@timestamp": "2026-03-20T09:10:00"},
            ]
        )
        unique_keys = bu.update()

        self.assertEqual(unique_keys, 2)

        existing_bucket = AttackerActivityBucket.objects.get(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
        )
        self.assertEqual(existing_bucket.interaction_count, 5)

        created_bucket = AttackerActivityBucket.objects.get(
            attacker_ip="2.2.2.2",
            feed_type="heralding",
            bucket_start=datetime(2026, 3, 20, 9, 0),
        )
        self.assertEqual(created_bucket.interaction_count, 1)

    def test_invalid_hits_are_ignored(self):
        bu = BucketUpdater()
        bu.collect_hits(
            [
                {"src_ip": "", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "999.999.999.999", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "3.3.3.3", "type": "", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "3.3.3.3", "type": "cowrie"},
            ]
        )
        unique_keys = bu.update()

        self.assertEqual(unique_keys, 0)
        self.assertEqual(AttackerActivityBucket.objects.count(), 0)

    def test_invalid_timestamp_is_ignored(self):
        bu = BucketUpdater()
        bu.collect_hits(
            [
                {"src_ip": "8.8.8.8", "type": "cowrie", "@timestamp": "not-a-timestamp"},
            ]
        )
        unique_keys = bu.update()

        self.assertEqual(unique_keys, 0)
        self.assertEqual(AttackerActivityBucket.objects.count(), 0)

    def test_non_global_ip_hits_are_ignored(self):
        bu = BucketUpdater()
        bu.collect_hits(
            [
                {"src_ip": "10.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "127.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "224.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "169.254.1.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "240.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "8.8.8.8", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
            ]
        )
        unique_keys = bu.update()

        self.assertEqual(unique_keys, 1)
        self.assertEqual(AttackerActivityBucket.objects.count(), 1)
        self.assertTrue(AttackerActivityBucket.objects.filter(attacker_ip="8.8.8.8").exists())

    def test_global_ipv6_hit_is_counted(self):
        bu = BucketUpdater()
        bu.collect_hits(
            [
                {"src_ip": "2001:4860:4860::8888", "type": "Cowrie", "@timestamp": "2026-03-20T09:15:00"},
            ]
        )
        unique_keys = bu.update()

        self.assertEqual(unique_keys, 1)
        self.assertTrue(
            AttackerActivityBucket.objects.filter(
                attacker_ip="2001:4860:4860::8888",
                feed_type="cowrie",
                bucket_start=datetime(2026, 3, 20, 9, 0),
            ).exists()
        )

    def test_upsert_uses_multiple_batches_for_large_counter_sets(self):
        counters = {
            ("10.0.0.1", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.2", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.3", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.4", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.5", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
        }

        repository = TrendingBucketRepository()
        with (
            patch.object(TrendingBucketRepository, "UPSERT_BATCH_SIZE", 2),
            patch("greedybear.cronjobs.repositories.trending_bucket.connection.cursor") as mock_cursor_factory,
        ):
            mock_cursor = mock_cursor_factory.return_value.__enter__.return_value
            inserted = repository.upsert_bucket_counts(counters)

        self.assertEqual(inserted, 5)
        self.assertEqual(mock_cursor.execute.call_count, 3)

    @patch("greedybear.cronjobs.extraction.bucket_updater.TrendingBucketRepository.upsert_bucket_counts", side_effect=Exception("db down"))
    def test_upsert_failure_returns_zero(self, mock_upsert):
        bu = BucketUpdater()
        bu.collect_hits([{"src_ip": "8.8.8.8", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"}])
        unique_keys = bu.update()
        self.assertEqual(unique_keys, 0)
        mock_upsert.assert_called_once()


class TrendingBucketCleanupCronTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cron = TrendingBucketCleanupCron()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=2,
        TRENDING_MAX_WINDOW_MINUTES=60,
    )
    def test_run_applies_bucket_retention_cleanup(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 7, 0),
                    interaction_count=1,
                ),
                AttackerActivityBucket(
                    attacker_ip="3.3.3.3",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=1,
                ),
            ]
        )

        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            self.cron.run()

        self.assertFalse(AttackerActivityBucket.objects.filter(attacker_ip="2.2.2.2").exists())
        self.assertTrue(AttackerActivityBucket.objects.filter(attacker_ip="3.3.3.3").exists())

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=0,
    )
    def test_run_raises_on_invalid_retention_hours(self):
        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)), self.assertRaises(ValueError):
            self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=1,
        TRENDING_MAX_WINDOW_MINUTES=60,
    )
    def test_run_raises_when_retention_cannot_cover_two_windows(self):
        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)), self.assertRaises(ValueError):
            self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=1,
        TRENDING_MAX_WINDOW_MINUTES=120,
    )
    def test_run_raises_when_max_window_exceeds_retention_horizon(self):
        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)), self.assertRaises(ValueError):
            self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=4,
        TRENDING_MAX_WINDOW_MINUTES=59,
    )
    def test_run_raises_when_max_window_below_60(self):
        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)), self.assertRaises(ValueError):
            self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=4,
        TRENDING_MAX_WINDOW_MINUTES=130,
    )
    def test_run_raises_when_max_window_not_multiple_of_60(self):
        with patch("greedybear.cronjobs.bucket_cleanup.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)), self.assertRaises(ValueError):
            self.cron.run()

    def test_positive_int_setting_rejects_non_numeric(self):
        with self.assertRaisesMessage(ValueError, "TRENDING_BUCKET_RETENTION_HOURS must be a positive integer"):
            self.cron._positive_int_setting("TRENDING_BUCKET_RETENTION_HOURS", "abc")
