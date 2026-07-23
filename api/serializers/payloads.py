# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers

from greedybear.models import HoneypotPayload


class HoneypotPayloadSerializer(serializers.ModelSerializer):
    source_honeypots = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field="name",
        help_text="Names of the honeypots that captured this payload.",
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
        extra_kwargs = {
            "id": {"help_text": "Unique identifier of the payload."},
            "sha256": {"help_text": "SHA256 hash of the payload."},
            "md5": {"help_text": "MD5 hash of the payload."},
            "sha1": {"help_text": "SHA1 hash of the payload."},
            "mime_type": {"help_text": "MIME type of the payload file."},
            "size": {"help_text": "Size of the payload in bytes."},
        }
