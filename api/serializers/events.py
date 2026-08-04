import logging
import re

from django.utils import timezone
from rest_framework import serializers

from greedybear.models import EventStatus, Sensor
from greedybear.utils import is_ip_address

logger = logging.getLogger(__name__)


class SensorCreateSerializer(serializers.ModelSerializer):
    sensor_label = serializers.CharField(
        source="label",
        required=False,
        allow_blank=True,
        max_length=128,
        help_text="Optional human-readable label to identify this sensor.",
    )
    asn = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=1,
        max_value=2147483647,
        help_text="Autonomous System Number.",
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
            "address": {
                "validators": [],  # drops the model's uniqueness check, which ignores api_source scoping
                "help_text": "IPv4 or IPv6 address of the sensor.",
            },
            "honeypot_type": {"help_text": "Type of honeypot."},
            "honeypot_software": {"help_text": "Honeypot software name."},
            "honeypot_description": {"help_text": "Description of the sensor."},
            "group_label": {"help_text": "Group classification label."},
            "country_code": {"help_text": "2-letter ISO country code."},
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
        """
        Validates the address format. Required because Meta.extra_kwargs clears this field's validators.
        """
        if not is_ip_address(value):
            raise serializers.ValidationError("Invalid IP address")
        return value


class SensorCreateResponseSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    message = serializers.CharField(read_only=True)


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

    def validate_payload_hash(self, value):
        if value and not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise serializers.ValidationError("payload_hash must be a 64-character hex sha256 digest.")
        return value.lower() if value else value

    def validate_protocol(self, value):
        return value.strip().lower() if value else value

    def validate_cve_id(self, value):
        value = value.strip().upper()
        if value and not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            raise serializers.ValidationError("cve_id must follow the CVE format: CVE-YYYY-NNNNN (e.g. CVE-2021-44228).")
        return value


class InjectionSerializer(serializers.Serializer):
    events = serializers.ListField(
        child=EventSerializer(),
        min_length=1,
        max_length=10000,
        error_messages={"min_length": "At least one event is required.", "max_length": "Batch size cannot exceed 10,000 events."},
    )


class InjectionResponseSerializer(serializers.Serializer):
    message = serializers.CharField(read_only=True)
    task_id = serializers.CharField(read_only=True)
    status_url = serializers.CharField(read_only=True)


class BatchStatusRequestSerializer(serializers.Serializer):
    task_id = serializers.RegexField(
        r"^[0-9a-f]{32}$",
        help_text="The unique string identifier assigned to the background processing job.",
        error_messages={"invalid": "task_id must be a 32-character lowercase hex string."},
    )


class BatchStatusSerializer(serializers.ModelSerializer):
    batch_id = serializers.IntegerField(source="id", read_only=True)
    last_error = serializers.SerializerMethodField()

    class Meta:
        model = EventStatus
        fields = [
            "task_id",
            "batch_id",
            "status",
            "ioc_count",
            "last_error",
            "processed_at",
            "created_at",
        ]

    def get_last_error(self, obj) -> str | None:
        """Normalizes the blank default to null, so clients only test for one empty value."""
        return obj.last_error or None
