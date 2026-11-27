from datetime import datetime

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from greedybear.admin import ExtractionRunAdmin
from greedybear.models import ExtractionJobName, ExtractionRun

from . import CustomTestCase


class ExtractionRunAdminTestCase(CustomTestCase):
    """Runs hold the extraction watermark, so the admin shows them read-only."""

    def setUp(self):
        super().setUp()
        self.admin = ExtractionRunAdmin(ExtractionRun, AdminSite())
        self.request = RequestFactory().get("/")
        self.request.user = self.superuser
        self.run = ExtractionRun.objects.create(
            job_name=ExtractionJobName.EXTRACTION,
            window_start=datetime(2025, 1, 1, 10, 0),
            window_end=datetime(2025, 1, 1, 10, 10),
        )

    def test_runs_cannot_be_added(self):
        self.assertFalse(self.admin.has_add_permission(self.request))

    def test_runs_cannot_be_changed(self):
        self.assertFalse(self.admin.has_change_permission(self.request, self.run))

    def test_runs_cannot_be_deleted(self):
        self.assertFalse(self.admin.has_delete_permission(self.request))
        self.assertFalse(self.admin.has_delete_permission(self.request, self.run))

    def test_delete_action_is_not_offered(self):
        self.assertNotIn("delete_selected", self.admin.get_actions(self.request))
