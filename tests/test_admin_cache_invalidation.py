from unittest.mock import Mock

from django.contrib import admin
from django.test import override_settings

from greedybear.admin import IOCModelAdmin
from greedybear.cache import Cache
from greedybear.consts import API_CACHE_ALIAS, IOC_DATA_VERSION_KEY
from greedybear.models import IOC, Honeypot

from . import CustomTestCase, make_api_source, make_sensor
from .test_cache import TEST_CACHES


@override_settings(CACHES=TEST_CACHES)
class AdminCacheInvalidationTestCase(CustomTestCase):
    """Every admin write has to bump the IOC data version."""

    HONEYPOT_CHANGELIST = "/admin/greedybear/honeypot/"

    def setUp(self):
        super().setUp()
        self.cache = Cache(API_CACHE_ALIAS)
        self.client.force_login(self.superuser)

    def _version(self) -> int:
        return self.cache.get_data_version(IOC_DATA_VERSION_KEY)

    def _run_action(self, action: str, honeypots: list[Honeypot]):
        return self.client.post(
            self.HONEYPOT_CHANGELIST,
            {"action": action, "_selected_action": [h.pk for h in honeypots]},
        )

    def test_change_page_save_bumps_version(self):
        before = self._version()
        response = self.client.post(
            f"{self.HONEYPOT_CHANGELIST}{self.cowrie_hp.pk}/change/",
            {"name": self.cowrie_hp.name},  # unchecked checkbox = active False
        )
        self.assertEqual(response.status_code, 302)
        self.cowrie_hp.refresh_from_db()
        self.assertFalse(self.cowrie_hp.active)
        self.assertEqual(self._version(), before + 1)

    def test_add_page_save_bumps_version(self):
        before = self._version()
        response = self.client.post(f"{self.HONEYPOT_CHANGELIST}add/", {"name": "NewPot", "active": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Honeypot.objects.filter(name="NewPot").exists())
        self.assertEqual(self._version(), before + 1)

    def test_list_editable_save_bumps_version(self):
        sensor = make_sensor(make_api_source(self.superuser))
        before = self._version()
        response = self.client.post(
            "/admin/greedybear/sensor/",
            {
                "form-TOTAL_FORMS": "1",
                "form-INITIAL_FORMS": "1",
                "form-0-id": str(sensor.pk),
                "form-0-label": "renamed",
                "_save": "Save",
            },
        )
        self.assertEqual(response.status_code, 302)
        sensor.refresh_from_db()
        self.assertEqual(sensor.label, "renamed")
        self.assertEqual(self._version(), before + 1)

    def test_version_bumped_after_m2m_and_inlines_are_saved(self):
        model_admin = IOCModelAdmin(IOC, admin.site)
        before = self._version()
        versions_seen = []
        form = Mock(save_m2m=Mock(side_effect=lambda: versions_seen.append(self._version())))
        formset = Mock(save=Mock(side_effect=lambda: versions_seen.append(self._version())))
        model_admin.save_related(Mock(), form, [formset], change=True)
        self.assertEqual(versions_seen, [before, before])
        self.assertEqual(self._version(), before + 1)

    def test_delete_page_bumps_version(self):
        honeypot = Honeypot.objects.create(name="ToDelete")
        before = self._version()
        response = self.client.post(f"{self.HONEYPOT_CHANGELIST}{honeypot.pk}/delete/", {"post": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Honeypot.objects.filter(pk=honeypot.pk).exists())
        self.assertEqual(self._version(), before + 1)

    def test_bulk_delete_bumps_version(self):
        honeypots = [Honeypot.objects.create(name="ToDelete1"), Honeypot.objects.create(name="ToDelete2")]
        before = self._version()
        response = self.client.post(
            self.HONEYPOT_CHANGELIST,
            {"action": "delete_selected", "_selected_action": [h.pk for h in honeypots], "post": "yes"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Honeypot.objects.filter(pk__in=[h.pk for h in honeypots]).exists())
        self.assertEqual(self._version(), before + 1)

    def test_disable_action_bumps_version(self):
        before = self._version()
        response = self._run_action("disable_honeypot", [self.cowrie_hp])
        self.assertEqual(response.status_code, 302)
        self.cowrie_hp.refresh_from_db()
        self.assertFalse(self.cowrie_hp.active)
        self.assertEqual(self._version(), before + 1)

    def test_enable_action_bumps_version(self):
        before = self._version()
        response = self._run_action("enable_honeypot", [self.ddospot])
        self.assertEqual(response.status_code, 302)
        self.ddospot.refresh_from_db()
        self.assertTrue(self.ddospot.active)
        self.assertEqual(self._version(), before + 1)

    def test_actions_without_updates_keep_version(self):
        before = self._version()
        self._run_action("disable_honeypot", [self.ddospot])  # already inactive
        self._run_action("enable_honeypot", [self.cowrie_hp])  # already active
        self.assertEqual(self._version(), before)

    def test_cached_feed_reflects_disabled_honeypot(self):
        url = "/api/feeds/all/all/recent.json?include_mass_scanners&include_tor_exit_nodes"
        first = self.client.get(url)
        self.assertEqual(first.status_code, 200)
        first_names = {ioc["value"] for ioc in first.json()["iocs"]}
        self.assertIn(self.ioc_3.name, first_names)  # ioc_3 is only seen by Cowrie

        self._run_action("disable_honeypot", [self.cowrie_hp])

        fresh = self.client.get(url)
        self.assertEqual(fresh.status_code, 200)
        self.assertEqual({ioc["value"] for ioc in fresh.json()["iocs"]}, first_names - {self.ioc_3.name})
