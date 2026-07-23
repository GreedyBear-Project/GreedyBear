# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from unittest.mock import Mock

from django.contrib.auth.models import Group

from api.permissions import THREAT_RESEARCHER_GROUP, IsThreatResearcherOrAdmin
from tests import CustomTestCase


class IsThreatResearcherOrAdminTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.permission = IsThreatResearcherOrAdmin()
        self.researcher_group = Group.objects.get_or_create(name=THREAT_RESEARCHER_GROUP)[0]

    def _make_request(self, user=None):
        request = Mock()
        request.user = user
        return request

    def test_anonymous_user_denied(self):
        anon = Mock()
        anon.is_authenticated = False
        self.assertFalse(self.permission.has_permission(self._make_request(anon), None))

    def test_regular_user_denied(self):
        self.assertFalse(self.permission.has_permission(self._make_request(self.regular_user), None))

    def test_staff_user_allowed(self):
        self.assertTrue(self.permission.has_permission(self._make_request(self.superuser), None))

    def test_threat_researcher_allowed(self):
        self.regular_user.groups.add(self.researcher_group)
        self.assertTrue(self.permission.has_permission(self._make_request(self.regular_user), None))
        self.regular_user.groups.remove(self.researcher_group)

    def test_none_user_denied(self):
        self.assertFalse(self.permission.has_permission(self._make_request(None), None))
