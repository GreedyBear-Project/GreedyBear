import logging
import re

from django.utils import timezone
from rest_framework import serializers

from greedybear.models import Sensor
from greedybear.utils import is_ip_address

logger = logging.getLogger(__name__)


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


class EventSerializer(serializers.Serializer):
    # required fields
    src_ip = serializers.IPAddressField(required=True)
    event_type = serializers.CharField(required=True, max_length=100)
    timestamp = serializers.DateTimeField(required=True)
    sensor_id = serializers.IntegerField(required=True, min_value=0)

    # optional string fields
    session_id = serializers.CharField(default="", max_length=100, allow_blank=True)
    token_id = serializers.CharField(default="", max_length=100, allow_blank=True)
    protocol = serializers.CharField(default="", max_length=50, allow_blank=True)
    service_name = serializers.CharField(default="", max_length=100, allow_blank=True)
    username = serializers.CharField(default="", max_length=255, allow_blank=True)
    password = serializers.CharField(default="", max_length=255, allow_blank=True)
    cve_id = serializers.CharField(default="", max_length=50, allow_blank=True)
    command = serializers.CharField(default="", allow_blank=True)
    src_port = serializers.IntegerField(default=None, min_value=1, max_value=65535, allow_null=True)
    dest_port = serializers.IntegerField(default=None, min_value=1, max_value=65535, allow_null=True)
    related_url = serializers.URLField(default="", max_length=900, allow_blank=True)
    payload_hash = serializers.CharField(default="", max_length=64, allow_blank=True)
    data = serializers.JSONField(default=dict)

    def validate_timestamp(self, value):
        if value > timezone.now():
            raise serializers.ValidationError("Timestamp cannot be in the future.")
        return value


class InjectionSerializer(serializers.Serializer):
    events = serializers.ListField(
        child=EventSerializer(),
        min_length=1,
        max_length=10000,
        error_messages={"min_length": "At least one event is required.", "max_length": "Batch size cannot exceed 10,000 events."},
    )
