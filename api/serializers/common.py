import logging
import re

from rest_framework import serializers

from api.serializers.utils import PresenceFlagField
from greedybear.consts import REGEX_DOMAIN
from greedybear.models import IOC, Sensor, Tag
from greedybear.utils import is_ip_address

logger = logging.getLogger(__name__)


class HoneypotRelatedField(serializers.SlugRelatedField):
    """Flattens a Honeypot relation to its bare name. Used for nested representations."""

    def __init__(self, **kwargs):
        kwargs.setdefault("slug_field", "name")
        kwargs.setdefault("read_only", True)
        super().__init__(**kwargs)


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["key", "value", "source"]


class SensorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sensor
        fields = ["address", "label"]


class IOCSerializer(serializers.ModelSerializer):
    general_honeypot = HoneypotRelatedField(many=True, read_only=True, source="honeypots")
    tags = TagSerializer(many=True, read_only=True)
    sensors = SensorSerializer(many=True, read_only=True)

    class Meta:
        model = IOC
        exclude = [
            "related_urls",
        ]


class EnrichmentRequestSerializer(serializers.Serializer):
    query = serializers.CharField(max_length=250, help_text="The IP address or domain to lookup.")

    def validate(self, data):
        """
        Validate that the query is a valid IP address (IPv4/IPv6) or domain.
        """
        observable = data["query"].strip()
        data["query"] = observable

        # A valid domain must match the domain regex AND contain at least one alphabetic character
        is_domain = bool(re.match(REGEX_DOMAIN, observable)) and any(c.isalpha() for c in observable)

        if not is_ip_address(observable) and not is_domain:
            raise serializers.ValidationError("Observable is not a valid IP address or domain")
        return data


class EnrichmentSerializer(serializers.Serializer):
    found = serializers.BooleanField(read_only=True, default=False)
    ioc = IOCSerializer(read_only=True, default=None, allow_null=True)
    query = serializers.CharField(max_length=250)


class HoneypotRequestSerializer(serializers.Serializer):
    """Query params for the honeypot list endpoint.
    ``onlyActive`` is the legacy camelCase spelling kept for backwards compatibility.
    Either spelling enables the filter.
    """

    only_active = PresenceFlagField(default=False, help_text="Include only active honeypots.")
    onlyActive = PresenceFlagField(  # noqa: N815
        default=False,
        help_text="Deprecated alias for only_active.",
    )

    def validate(self, data):
        data["only_active"] = data["only_active"] or data.pop("onlyActive")
        return data
