# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers

from greedybear.models import HoneypotPayload


class HoneypotPayloadSerializer(serializers.ModelSerializer):
    source_honeypots = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field="name",
    )

    class Meta:
        model = HoneypotPayload
        fields = [
            "id",
            "sha256",
            "md5",
            "sha1",
            "mime_type",
            "size",
            "source_honeypots",
        ]
