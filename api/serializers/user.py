# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from certego_saas.apps.user.serializers import UserAccessSerializer
from rest_framework import serializers as rfs

from api.permissions import THREAT_RESEARCHER_GROUP


class GreedyBearUserAccessSerializer(UserAccessSerializer):
    """Extends the certego access payload with GreedyBear specific permissions."""

    class Meta(UserAccessSerializer.Meta):
        fields = ("user", "can_download_payloads")

    can_download_payloads = rfs.SerializerMethodField()

    def get_can_download_payloads(self, obj) -> bool:
        return bool(obj.is_staff or obj.groups.filter(name=THREAT_RESEARCHER_GROUP).exists())
