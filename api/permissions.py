# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.permissions import BasePermission

THREAT_RESEARCHER_GROUP = "threat_researcher"


class IsThreatResearcherOrAdmin(BasePermission):
    """Allow access only to staff users or members of the ``threat_researcher`` group."""

    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and (user.is_staff or user.groups.filter(name=THREAT_RESEARCHER_GROUP).exists())
