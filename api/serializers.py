import logging
import re
from functools import cache

from django.core.exceptions import FieldDoesNotExist
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


def parse_feed_types(feed_type_str: str) -> list:
    """Split a comma-separated feed type string into a stripped list of individual feed types.

    Args:
        feed_type_str (str): Comma-separated feed type string (e.g. "cowrie,adbhoney").

    Returns:
        list[str]: List of non-empty, stripped feed type tokens.
    """
    return [ft.strip() for ft in feed_type_str.split(",") if ft.strip()]


def feed_type_validation(feed_type: str, valid_feed_types: frozenset) -> str:
    """Validates that a given feed type exists in the set of valid feed types.

    Args:
        feed_type (str): The feed type to validate
        valid_feed_types (frozenset): Set of allowed feed type values

    Returns:
        str: The validated feed type string, unchanged

    Raises:
        serializers.ValidationError: If feed_type is not found in valid_feed_types
    """
    if feed_type not in valid_feed_types:
        logger.info(f"Feed type {feed_type} not in feed_choices {valid_feed_types}")
        raise serializers.ValidationError(f"Invalid feed_type: {feed_type}")
    return feed_type


@cache
def ordering_validation(ordering: str) -> str:
    """Validates that given ordering corresponds to a field in the IOC model.

    Args:
        ordering (str): The ordering to validate

    Returns:
        str: The validated ordering string, unchanged

    Raises:
        serializers.ValidationError: If ordering does not correspond to a field in the IOC model
    """
    if not ordering:
        raise serializers.ValidationError("Invalid ordering: <empty string>")
    # remove minus sign if present
    field_name = ordering.removeprefix("-")
    try:
        IOC._meta.get_field(field_name)
    except FieldDoesNotExist as exc:
        raise serializers.ValidationError(f"Invalid ordering: {ordering}") from exc
    return ordering


class FeedsRequestSerializer(serializers.Serializer):
    feed_type = serializers.CharField()
    attack_type = serializers.ChoiceField(choices=["scanner", "payload_request", "all"])
    ioc_type = serializers.ChoiceField(choices=["ip", "domain", "all"])
    max_age = serializers.IntegerField(min_value=1)
    min_days_seen = serializers.IntegerField(min_value=1)
    min_credential_count = serializers.IntegerField(required=False, min_value=1)
    max_credential_count = serializers.IntegerField(required=False, min_value=0)
    include_reputation = serializers.ListField(child=serializers.CharField(max_length=120))
    exclude_reputation = serializers.ListField(child=serializers.CharField(max_length=120))
    feed_size = serializers.IntegerField(min_value=1)
    ordering = serializers.CharField(max_length=120)
    verbose = serializers.ChoiceField(choices=["true", "false"])
    paginate = serializers.ChoiceField(choices=["true", "false"])
    format = serializers.ChoiceField(choices=["csv", "json", "txt", "stix21"])
    asn = serializers.IntegerField(min_value=1, required=False, allow_null=True)
    min_score = serializers.FloatField(min_value=0, max_value=1, required=False, allow_null=True)
    min_expected_interactions = serializers.FloatField(min_value=0, required=False, allow_null=True)
    port = serializers.IntegerField(min_value=1, max_value=65535, required=False, allow_null=True)
    start_date = serializers.DateField(format="%Y-%m-%d", required=False, allow_null=True)
    end_date = serializers.DateField(format="%Y-%m-%d", required=False, allow_null=True)
    tag_key = serializers.CharField(max_length=128, required=False, allow_blank=True)
    tag_value = serializers.CharField(max_length=256, required=False, allow_blank=True)
    country_code = serializers.CharField(max_length=2, required=False, allow_blank=True)

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsRequestSerializer - validation feed_type: '{feed_type}'")
        feed_types = parse_feed_types(feed_type)
        if not feed_types:
            raise serializers.ValidationError("Invalid feed_type: must not be empty")
        valid_feed_types = self.context["valid_feed_types"]
        if len(feed_types) > len(valid_feed_types):
            raise serializers.ValidationError(f"Invalid feed_type: too many types specified (max {len(valid_feed_types)})")
        if "all" in feed_types and len(feed_types) > 1:
            raise serializers.ValidationError("Invalid feed_type: 'all' cannot be combined with other feed types")
        for ft in feed_types:
            feed_type_validation(ft, valid_feed_types)
        return feed_type

    def validate_ordering(self, ordering):
        logger.debug(f"FeedsRequestSerializer - validation ordering: '{ordering}'")
        return ordering_validation(ordering)

    def validate(self, data):
        min_cc = data.get("min_credential_count")
        max_cc = data.get("max_credential_count")
        if min_cc is not None and max_cc is not None and min_cc > max_cc:
            raise serializers.ValidationError("min_credential_count must be less than or equal to max_credential_count")
        return data


class ASNFeedsOrderingSerializer(FeedsRequestSerializer):
    ALLOWED_ORDERING_FIELDS = frozenset(
        {
            "asn",
            "as_name",
            "ioc_count",
            "total_attack_count",
            "total_interaction_count",
            "total_login_attempts",
            "expected_ioc_count",
            "expected_interactions",
            "first_seen",
            "last_seen",
        }
    )

    def validate_ordering(self, ordering):
        field_name = ordering.lstrip("-").strip()

        if field_name not in self.ALLOWED_ORDERING_FIELDS:
            raise serializers.ValidationError(
                f"Invalid ordering field for ASN aggregated feed: '{field_name}'. Allowed fields: {', '.join(sorted(self.ALLOWED_ORDERING_FIELDS))}"
            )

        return ordering


class FeedsResponseSerializer(serializers.Serializer):
    """
    Serializer for feed response data structure.

    NOTE: This serializer is currently NOT used in production code (as of #629).
    It has been kept in the codebase for the following reasons:

    1. **Documentation**: Serves as a clear schema definition for the API response contract
    2. **Testing**: Validates the expected response structure through unit tests
    3. **Future-proofing**: Allows easy re-enabling of validation if security requirements change
    4. **Reference**: Useful for API consumers and developers to understand the response format

    Performance Optimization Context:
    Previously, this serializer was instantiated and validated for each IOC in the response
    (up to 5000 times per request), causing significant overhead (~1.8s for 5000 IOCs).
    The optimization removed this per-item validation since the data is constructed internally
    in api/views/utils.py::feeds_response() and guaranteed to match this schema.

    The response is now built directly without serializer validation, reducing response time
    to ~0.03s (50-90x speedup) while maintaining the exact same API contract defined here.

    See: #629 for benchmarking details and discussion.
    """

    feed_type = serializers.ListField(child=serializers.CharField(max_length=120))
    value = serializers.CharField(max_length=256)
    scanner = serializers.BooleanField()
    payload_request = serializers.BooleanField()
    first_seen = serializers.DateField(format="%Y-%m-%d")
    last_seen = serializers.DateField(format="%Y-%m-%d")
    attack_count = serializers.IntegerField(min_value=1)
    interaction_count = serializers.IntegerField(min_value=1)
    ip_reputation = serializers.CharField(allow_blank=True, max_length=32)
    firehol_categories = serializers.ListField(child=serializers.CharField(max_length=64), allow_empty=True)
    asn = serializers.IntegerField(allow_null=True, min_value=1)
    destination_port_count = serializers.IntegerField(min_value=0)
    login_attempts = serializers.IntegerField(min_value=0)
    recurrence_probability = serializers.FloatField(min_value=0, max_value=1)
    expected_interactions = serializers.FloatField(min_value=0)
    attacker_country = serializers.CharField(allow_null=True, allow_blank=True, max_length=120)
    attacker_country_code = serializers.CharField(allow_null=True, allow_blank=True, max_length=2)
    tags = TagSerializer(many=True, required=False, default=list)
    sensors = SensorSerializer(many=True, required=False, default=list)

    def validate_feed_type(self, feed_type):
        logger.debug(f"FeedsResponseSerializer - validation feed_type: '{feed_type}'")
        return [feed_type_validation(feed, self.context["valid_feed_types"]) for feed in feed_type]
