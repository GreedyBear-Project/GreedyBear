from unittest.mock import MagicMock

from greedybear.cronjobs.invalid_event_retention import (
    InvalidEventRetentionCron,
)
from greedybear.models import APISource
from tests import CustomTestCase, make_user, make_api_source


class APISourceRetentionCronTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()

        # Create users first
        self.user1 = make_user(username="user1")
        self.user2 = make_user(username="user2")
        self.user3 = make_user(username="user3")

        # Create API sources linked to users
        self.source_1 = make_api_source(self.user1, name="source_1")
        self.source_2 = make_api_source(self.user2, name="source_2")
        self.source_3 = make_api_source(self.user3, name="source_3")

        # Set different invalid_event_count values
        APISource.objects.filter(id=self.source_1.id).update(invalid_event_count=5)
        APISource.objects.filter(id=self.source_2.id).update(invalid_event_count=10)
        APISource.objects.filter(id=self.source_3.id).update(invalid_event_count=0)

    def test_retention_resets_invalid_event_count_to_zero(self):
        cronjob = InvalidEventRetentionCron()
        cronjob.log = MagicMock()

        cronjob.execute()

        self.source_1.refresh_from_db()
        self.source_2.refresh_from_db()
        self.source_3.refresh_from_db()

        self.assertEqual(self.source_1.invalid_event_count, 0)
        self.assertEqual(self.source_2.invalid_event_count, 0)
        self.assertEqual(self.source_3.invalid_event_count, 0)

        cronjob.log.info.assert_called()

    def test_retention_no_crash_when_already_clean(self):
        APISource.objects.update(invalid_event_count=0)

        cronjob = InvalidEventRetentionCron()
        cronjob.log = MagicMock()

        cronjob.execute()

        self.assertTrue(
            APISource.objects.filter(invalid_event_count=0).count() >= 1
        )