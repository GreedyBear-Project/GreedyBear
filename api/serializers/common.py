import logging
import re

from rest_framework import serializers

from greedybear.consts import REGEX_DOMAIN
from greedybear.models import IOC, Honeypot, Sensor, Tag
from greedybear.utils import is_ip_address

logger = logging.getLogger(__name__)


class HoneypotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Honeypot

    def to_representation(self, value):
        return value.name


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["key", "value", "source"]


class SensorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sensor
        fields = ["address", "label"]


class IOCSerializer(serializers.ModelSerializer):
    general_honeypot = HoneypotSerializer(many=True, read_only=True, source="honeypots")
    tags = TagSerializer(many=True, read_only=True)
    sensors = SensorSerializer(many=True, read_only=True)

    class Meta:
        model = IOC
        exclude = [
            "related_urls",
        ]


class EnrichmentSerializer(serializers.Serializer):
    found = serializers.BooleanField(read_only=True, default=False)
    ioc = IOCSerializer(read_only=True, default=None)
    query = serializers.CharField(max_length=250)

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

        try:
            required_object = IOC.objects.prefetch_related("tags", "sensors").get(name=observable)
            data["found"] = True
            data["ioc"] = required_object
        except IOC.DoesNotExist:
            data["found"] = False
        return data


class SensorCreateSerializer(serializers.ModelSerializer):
    sensor_label = serializers.CharField(source="label", required=False, allow_blank=True, max_length=128)

    asn = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=1,
    )

    class Meta:
        model = Sensor
        fields = [
            "id",
            "address",
            "honeypot_type",
            "honeypot_software",
            "honeypot_description",
            "sensor_label",
            "group_label",
            "country_code",
            "asn",
        ]

        extra_kwargs = {
            "address": {"validators": []},
        }

        read_only_fields = ["id"]

    def validate_country_code(self, value):
        """
        Validates that the input is exactly 2 alphabet letters using regex,
        and converts it to uppercase.
        """
        if value:
            # Regex pattern: ^[A-Za-z]{2}$ means exactly two letters (A-Z or a-z)
            if not re.match(r"^[A-Za-z]{2}$", value):
                raise serializers.ValidationError("Country code must be a 2-character ISO code containing letters only (e.g. 'NP', 'IN').")
            return value.upper()

        return value

    def validate_address(self, value):
        if not is_ip_address(value):
            raise serializers.ValidationError("Invalid IP address")
        return value
