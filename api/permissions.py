# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.permissions import SAFE_METHODS, BasePermission

THREAT_RESEARCHER_GROUP = "threat_researcher"


class IsThreatResearcherOrAdmin(BasePermission):
    """Allow access only to staff users or members of the ``threat_researcher`` group."""

    def has_permission(self, request, view):
        user = request.user
        return user and user.is_authenticated and (user.is_staff or user.groups.filter(name=THREAT_RESEARCHER_GROUP).exists())


class IsSuperuserOrReadOnly(BasePermission):
    """Allow read access to anyone; restrict write access to superusers only."""

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return request.user and request.user.is_authenticated and request.user.is_superuser
