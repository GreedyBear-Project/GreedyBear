from datetime import datetime, timedelta

from greedybear.cronjobs.repositories import FireHolRepository
from greedybear.models import FireHolList

from . import CustomTestCase


class TestFireHolRepository(CustomTestCase):
    """Tests for FireHolRepository."""

    def setUp(self):
        self.repo = FireHolRepository()

    def test_get_or_create_creates_new_entry(self):
        entry, created = self.repo.get_or_create("1.2.3.4", "blocklist_de")

        self.assertTrue(created)
        self.assertEqual(entry.ip_address, "1.2.3.4")
        self.assertEqual(entry.source, "blocklist_de")
        self.assertTrue(FireHolList.objects.filter(ip_address="1.2.3.4", source="blocklist_de").exists())

    def test_get_or_create_returns_existing(self):
        FireHolList.objects.create(ip_address="5.6.7.8", source="greensnow")

        entry, created = self.repo.get_or_create("5.6.7.8", "greensnow")

        self.assertFalse(created)
        self.assertEqual(entry.ip_address, "5.6.7.8")
        self.assertEqual(FireHolList.objects.filter(ip_address="5.6.7.8", source="greensnow").count(), 1)

    def test_get_or_create_refreshes_added(self):
        """An entry seen again has its added timestamp moved forward."""
        old_date = datetime.now() - timedelta(days=20)
        entry = FireHolList.objects.create(ip_address="7.7.7.7", source="greensnow")
        FireHolList.objects.filter(pk=entry.pk).update(added=old_date)

        self.repo.get_or_create("7.7.7.7", "greensnow")

        entry.refresh_from_db()
        self.assertGreater(entry.added, old_date)

    def test_entry_still_listed_survives_cleanup(self):
        """An old entry seen again is not deleted, because added was refreshed."""
        old_date = datetime.now() - timedelta(days=31)
        entry = FireHolList.objects.create(ip_address="8.8.8.8", source="dshield")
        FireHolList.objects.filter(pk=entry.pk).update(added=old_date)

        self.repo.get_or_create("8.8.8.8", "dshield")
        deleted_count = self.repo.cleanup_old_entries(days=30)

        self.assertEqual(deleted_count, 0)
        self.assertTrue(FireHolList.objects.filter(pk=entry.pk).exists())

    def test_cleanup_old_entries_custom_days(self):
        old_date = datetime.now() - timedelta(days=65)
        old_entry = FireHolList.objects.create(ip_address="4.4.4.4", source="test")
        FireHolList.objects.filter(pk=old_entry.pk).update(added=old_date)

        deleted_count = self.repo.cleanup_old_entries(days=60)

        self.assertEqual(deleted_count, 1)
