from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory

from greedybear.admin import PayloadObservationInline
from greedybear.models import HoneypotPayload

from . import CustomTestCase


class PayloadObservationInlineTestCase(CustomTestCase):
    """Observations are written by the payload extraction only, so the admin shows them read-only."""

    def setUp(self):
        super().setUp()
        self.inline = PayloadObservationInline(HoneypotPayload, AdminSite())
        self.request = RequestFactory().get("/")
        self.request.user = self.superuser
        self.payload = HoneypotPayload.objects.create(sha256="a" * 64)

    def test_observations_cannot_be_added(self):
        self.assertFalse(self.inline.has_add_permission(self.request, self.payload))

    def test_observations_cannot_be_deleted(self):
        self.assertFalse(self.inline.has_delete_permission(self.request, self.payload))

    def test_all_fields_are_read_only(self):
        self.assertEqual(list(self.inline.get_readonly_fields(self.request, self.payload)), ["sensor", "locator", "mtime"])
