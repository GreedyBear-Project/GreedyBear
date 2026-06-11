import hashlib
import logging
from collections.abc import Mapping

from django.core import signing
from django.core.exceptions import FieldDoesNotExist
from rest_framework import serializers

from api.serializers.common import SensorSerializer, TagSerializer
from api.serializers.utils import feed_type_as_list, get_valid_feed_types
from greedybear.consts import SHARE_TOKEN_MAX_AGE, SHARE_TOKEN_SALT
from greedybear.enums import IpReputation
from greedybear.models import IOC, ShareToken

logger = logging.getLogger(__name__)

FEED_DEFAULTS = {
    "max_age": 3,
    "min_days_seen": 1,
    "feed_size": 5000,
    "include_reputation": [],
    "exclude_reputation": [],
    "verbose": False,
    "paginate": False,
}

PRIORITIZATION_PRESETS = {
    "recent": {"max_age": 3, "min_days_seen": 1, "ordering": "-last_seen"},
    "persistent": {"max_age": 14, "min_days_seen": 10, "ordering": "-attack_count"},
    "likely_to_recur": {"max_age": 30, "min_days_seen": 1, "ordering": "-recurrence_probability"},
    "most_expected_hits": {"max_age": 30, "min_days_seen": 1, "ordering": "-expected_interactions"},
}


### FIELDS ###
class FeedTypeField(serializers.CharField):
    """CharField for the feed_type query parameter.
    Accepts a single value or a comma-separated list of strings.
    Although the field is exposed as as CharField,
    the internal representation is always a list.
    """

    def to_internal_value(self, data: str) -> list[str]:
        feed_type_str = super().to_internal_value(data)
        logger.debug(f"Validating feed_type: {feed_type_str}")
        feed_type_list = feed_type_as_list(feed_type_str)
        if not feed_type_list:
            raise serializers.ValidationError("Invalid feed_type: must not be empty")
        if "all" in feed_type_list and len(feed_type_list) > 1:
            raise serializers.ValidationError("Invalid feed_type: 'all' cannot be combined with other feed types")
        invalid_feed_types = set(feed_type_list) - get_valid_feed_types()
        if invalid_feed_types:
            raise serializers.ValidationError(f"Invalid feed_type: {', '.join(sorted(invalid_feed_types))} not supported")
        return feed_type_list

    def get_default(self) -> list[str]:
        """Convert the declared default ("all") to a list ["all"]
        to match internal representaion of other values.
        """
        return [super().get_default()]


class PresenceFlagField(serializers.BooleanField):
    """BooleanField for presence-flag query params.
    Makes sure that a valueless query param such as include_mass_scanners
    is treated as truthy.
    """

    TRUE_VALUES = serializers.BooleanField.TRUE_VALUES | {""}


class ReputationListField(serializers.ListField):
    """ListField for the include_reputation and exclude_reputation query params.
    Takes a query string that contains ``;``-separated values
    and represents it as a list.
    """

    def to_internal_value(self, data: str) -> list[str]:
        logger.debug(f"Converting reputation list: {data}")
        reputations = data.split(";") if data else []
        return super().to_internal_value(reputations)


### REQUESTS ###
class BaseFeedRequestSerializer(serializers.Serializer):
    """Shared base for the feed request serializers (simple, advanced, ASN).
    Declares the parameters common to every feed endpoint
    and the query-string normalization they all rely on.

    Not used directly as an endpoint serializer;
    subclasses add their own fields and validation logic.
    """

    feed_type = FeedTypeField(default="all", help_text="Honeypot name (e.g. `cowrie`), a comma-separated list, or `all`.")
    attack_type = serializers.ChoiceField(
        choices=["scanner", "payload_request", "all"], default="all", help_text="Restrict to scanners, payload requests, or both."
    )
    ioc_type = serializers.ChoiceField(choices=["ip", "domain", "all"], default="all", help_text="Restrict to IPs, domains, or both.")
    ordering = serializers.CharField(default="-last_seen", help_text="IOC field to order by; prefix with `-` for descending (e.g. `-last_seen`).")
    format = serializers.ChoiceField(choices=["csv", "json", "txt", "stix21"], default="json", help_text="Output representation.")

    def to_internal_value(self, data: Mapping) -> dict:
        """Normalize raw query params before field validation:
        - lower-case all string values
        - accept format_ (legacy name) as an alias for format
        """
        logger.debug("Normalizing raw query")
        if isinstance(data, Mapping):
            data = {key: value.lower() if isinstance(value, str) else value for key, value in data.items()}
            if "format_" in data and "format" not in data:
                data["format"] = data["format_"]
        return super().to_internal_value(data)

    def validate_ordering(self, ordering: str) -> str:
        """Validate ordering against the IOC model fields and return it normalized."""
        logger.debug(f"Validating ordering: {ordering}")
        if not ordering:
            raise serializers.ValidationError("Invalid ordering: <empty string>")
        normalized_ordering = ordering.lower().replace("value", "name")
        field_name = normalized_ordering.removeprefix("-")
        try:
            IOC._meta.get_field(field_name)
        except FieldDoesNotExist as exc:
            raise serializers.ValidationError(f"Invalid ordering: {ordering}") from exc
        return normalized_ordering


class SimpleFeedRequestSerializer(BaseFeedRequestSerializer):
    """Serializer for the public feed endpoints.
    Exposes only a curated set of inputs
    and expands them into the full parameter set the views consume
    using presets and default fallbacks.
    """

    prioritize = serializers.ChoiceField(
        choices=["recent", "persistent", "likely_to_recur", "most_expected_hits"],
        default="recent",
        help_text="Preset selecting the age window, minimum days seen and default ordering.",
    )
    include_mass_scanners = PresenceFlagField(default=False, help_text="Include IOCs flagged as mass scanners.")
    include_tor_exit_nodes = PresenceFlagField(default=False, help_text="Include IOCs that are Tor exit nodes.")
    # allows explicit override of the ordering in PRIORITIZATION_PRESETS
    ordering = serializers.CharField(required=False, help_text="Override the preset ordering, e.g. `-attack_count`.")

    def validate(self, data: dict) -> dict:
        logger.debug("Validating simple feed request")
        data = super().validate(data)
        prioritization_preset = PRIORITIZATION_PRESETS[data["prioritize"]]
        exclude_reputation = []
        if not data["include_mass_scanners"]:
            exclude_reputation.append(IpReputation.MASS_SCANNER)
        if not data["include_tor_exit_nodes"]:
            exclude_reputation.append(IpReputation.TOR_EXIT_NODE)
        return {
            **FEED_DEFAULTS,
            **prioritization_preset,
            **data,
            "exclude_reputation": exclude_reputation,
        }


class AdvancedFeedRequestSerializer(BaseFeedRequestSerializer):
    """Serializer for the authenticated advanced feed endpoint.
    Exposes the full set of filtering, scoring and pagination parameters directly,
    taking default fallback values from FEED_DEFAULTS.
    """

    max_age = serializers.IntegerField(min_value=1, default=FEED_DEFAULTS["max_age"], help_text="Maximum age in days since an IOC was last seen.")
    min_days_seen = serializers.IntegerField(min_value=1, default=FEED_DEFAULTS["min_days_seen"], help_text="Minimum distinct days an IOC has been seen.")
    feed_size = serializers.IntegerField(min_value=1, default=FEED_DEFAULTS["feed_size"], help_text="Maximum number of IOCs to return.")
    include_reputation = ReputationListField(
        child=serializers.CharField(max_length=120), default=FEED_DEFAULTS["include_reputation"], help_text="`;`-separated reputations to include."
    )
    exclude_reputation = ReputationListField(
        child=serializers.CharField(max_length=120), default=FEED_DEFAULTS["exclude_reputation"], help_text="`;`-separated reputations to exclude."
    )
    verbose = serializers.BooleanField(default=FEED_DEFAULTS["verbose"], help_text="Include extended per-IOC fields in JSON output.")
    paginate = serializers.BooleanField(default=FEED_DEFAULTS["paginate"], help_text="Paginate the response (forces JSON output).")
    min_credential_count = serializers.IntegerField(required=False, min_value=1, help_text="Only IOCs with at least this many associated credentials.")
    max_credential_count = serializers.IntegerField(required=False, min_value=0, help_text="Only IOCs with at most this many associated credentials.")
    asn = serializers.IntegerField(min_value=1, required=False, allow_null=True, help_text="Filter by autonomous system number.")
    min_score = serializers.FloatField(min_value=0, max_value=1, required=False, allow_null=True, help_text="Minimum recurrence probability between 0 and 1.")
    min_expected_interactions = serializers.FloatField(min_value=0, required=False, allow_null=True, help_text="Minimum expected interactions.")
    port = serializers.IntegerField(min_value=1, max_value=65535, required=False, allow_null=True, help_text="Filter by attacked destination port.")
    start_date = serializers.DateField(format="%Y-%m-%d", required=False, allow_null=True, help_text="Only IOCs last seen on or after this date (YYYY-MM-DD).")
    end_date = serializers.DateField(format="%Y-%m-%d", required=False, allow_null=True, help_text="Only IOCs last seen on or before this date (YYYY-MM-DD).")
    tag_key = serializers.CharField(max_length=128, required=False, allow_blank=True, help_text="Filter by tag key.")
    tag_value = serializers.CharField(max_length=256, required=False, allow_blank=True, help_text="Filter by tag value.")
    country_code = serializers.CharField(max_length=2, required=False, allow_blank=True, help_text="Filter by 2-letter attacker country code.")

    def validate(self, data: dict) -> dict:
        logger.debug("Validating advanced feed request")
        data = super().validate(data)
        if data["paginate"]:
            data["format"] = "json"
        min_cc = data.get("min_credential_count")
        max_cc = data.get("max_credential_count")
        if min_cc is not None and max_cc is not None and min_cc > max_cc:
            raise serializers.ValidationError("min_credential_count must be less than or equal to max_credential_count")
        return data


class ASNFeedRequestSerializer(AdvancedFeedRequestSerializer):
    """Serializer for the ASN-aggregated feed endpoint.
    Restricts ordering to the aggregated fields in ALLOWED_ORDERING_FIELDS
    rather than IOC model fields.
    """

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

    # Remove inherited advanced fields that have no effect on the aggregated ASN feed
    format = None
    feed_size = None
    verbose = None
    paginate = None

    asn = serializers.IntegerField(min_value=1, required=False, allow_null=True, help_text="Only display results of this autonomous system number.")
    ordering = serializers.CharField(default="-ioc_count", help_text="Aggregate field to order by (e.g. `-ioc_count`, `-total_attack_count`).")

    def validate(self, data: dict) -> dict:
        return data

    def validate_ordering(self, ordering: str) -> str:
        logger.debug(f"Validating ordering: {ordering}")
        field_name = ordering.removeprefix("-")
        if field_name not in self.ALLOWED_ORDERING_FIELDS:
            raise serializers.ValidationError(
                f"Invalid ordering field for ASN aggregated feed: '{field_name}'. Allowed fields: {', '.join(sorted(self.ALLOWED_ORDERING_FIELDS))}"
            )

        return ordering


class ShareFeedRequestSerializer(AdvancedFeedRequestSerializer):
    """Validate a share request: the advanced-feed params plus an optional reason note."""

    reason = serializers.CharField(
        required=False, allow_blank=True, default="", help_text="Optional free-text note stored for auditing (truncated to 256 chars)."
    )

    def to_internal_value(self, data: Mapping) -> dict:
        validated = super().to_internal_value(data)
        if isinstance(data, Mapping) and "reason" in data:
            validated["reason"] = data["reason"].strip()[:256]  # keep original case and truncate
        return validated


class TokenRequestSerializer(serializers.Serializer):
    """Resolve a signed share token to its DB record and decoded feed parameters."""

    token = serializers.CharField(help_text="A valid and signed share token.")

    def validate(self, data: dict) -> dict:
        logger.debug("Validating share token")
        token = data["token"]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            data["share_token"] = ShareToken.objects.get(token_hash=token_hash)
        except ShareToken.DoesNotExist as exc:
            raise serializers.ValidationError("Invalid or expired token") from exc
        try:
            data["feed_params"] = signing.loads(token, salt=SHARE_TOKEN_SALT, max_age=SHARE_TOKEN_MAX_AGE)
        except signing.BadSignature as exc:
            raise serializers.ValidationError("Invalid or expired token") from exc
        return data


class TokenConsumeRequestSerializer(TokenRequestSerializer):
    """Consume additionally rejects revoked tokens (a revoked link must not return data)."""

    def validate(self, data: dict) -> dict:
        data = super().validate(data)
        if data["share_token"].revoked:
            raise serializers.ValidationError("Token has been revoked")
        return data


### RESPONSES ###
class ASNFeedSerializer(serializers.Serializer):
    """Response for the AS endpoint with aggregated IOC data."""

    asn = serializers.IntegerField(min_value=1)
    as_name = serializers.CharField(max_length=256, allow_blank=True)
    ioc_count = serializers.IntegerField(min_value=0)
    total_attack_count = serializers.IntegerField(min_value=0)
    total_interaction_count = serializers.IntegerField(min_value=0)
    total_login_attempts = serializers.IntegerField(min_value=0)
    expected_ioc_count = serializers.FloatField(min_value=0)
    expected_interactions = serializers.FloatField(min_value=0)
    first_seen = serializers.DateTimeField()
    last_seen = serializers.DateTimeField()
    honeypots = serializers.ListField(child=serializers.CharField(max_length=120))


class ShareTokenResponseSerializer(serializers.Serializer):
    """Response for the share endpoint: the public consume and revoke URLs."""

    url = serializers.URLField(help_text="Public URL that consumes the shared feed.")
    revoke_url = serializers.URLField(help_text="URL that revokes the share token.")


class ShareTokenListItemSerializer(serializers.Serializer):
    """One row of the caller's share-token list (metadata only, no token value)."""

    hash_prefix = serializers.SerializerMethodField(help_text="First 12 characters of the token hash.")
    reason = serializers.CharField(allow_blank=True)
    created_at = serializers.DateTimeField()
    revoked = serializers.BooleanField()
    revoked_at = serializers.DateTimeField(allow_null=True)

    def get_hash_prefix(self, obj) -> str:
        return obj["token_hash"][:12]


"""
== Serializers for feed response data structure. ==
NOTE: The serializers below are currently NOT used in production code (as of #629).
It has been kept in the codebase for the following reasons:

1. **Documentation**: Serves as a clear schema definition for the API response contract
2. **Testing**: Validates the expected response structure through unit tests
3. **Future-proofing**: Allows easy re-enabling of validation if security requirements change
4. **Reference**: Useful for API consumers and developers to understand the response format

Performance Optimization Context:
Previously, this serializer was instantiated and validated for each IOC in the response
(up to 5000 times per request), causing significant overhead (~1.8s for 5000 IOCs).
The optimization removed this per-item validation since the data is constructed internally
in api/views/utils.py (build_ioc_json_list / build_feed_dict) and guaranteed to match this schema.

The response is now built directly without serializer validation, reducing response time
to ~0.03s (50-90x speedup) while maintaining the exact same API contract defined here.

See: #629 for benchmarking details and discussion.
"""


class SimpleFeedResponseSerializer(serializers.Serializer):
    feed_type = serializers.ListField(child=serializers.CharField(max_length=120))
    value = serializers.CharField(max_length=256)
    scanner = serializers.BooleanField()
    payload_request = serializers.BooleanField()
    first_seen = serializers.DateField(format="%Y-%m-%d")
    last_seen = serializers.DateField(format="%Y-%m-%d")
    attack_count = serializers.IntegerField(min_value=1)
    interaction_count = serializers.IntegerField(min_value=1)
    ip_reputation = serializers.CharField(allow_blank=True, max_length=32)
    asn = serializers.IntegerField(allow_null=True, min_value=1)
    destination_port_count = serializers.IntegerField(min_value=0)
    login_attempts = serializers.IntegerField(min_value=0)
    recurrence_probability = serializers.FloatField(min_value=0, max_value=1)
    expected_interactions = serializers.FloatField(min_value=0)
    attacker_country = serializers.CharField(allow_null=True, allow_blank=True, max_length=120)
    attacker_country_code = serializers.CharField(allow_null=True, allow_blank=True, max_length=2)
    tags = TagSerializer(many=True, required=False, default=list)


class AdvancedFeedResponseSerializer(SimpleFeedResponseSerializer):
    credential_count = serializers.IntegerField(min_value=0)
    sensors = SensorSerializer(many=True, required=False, default=list)
    firehol_categories = serializers.ListField(child=serializers.CharField(max_length=64), allow_empty=True, required=False)
    destination_ports = serializers.ListField(child=serializers.IntegerField(min_value=1, max_value=65535), required=False)
    days_seen = serializers.ListField(child=serializers.DateField(format="%Y-%m-%d"), required=False)


class BaseFeedEnvelopeSerializer(serializers.Serializer):
    license = serializers.CharField(required=False, help_text="Feed license text, present when configured.")


class SimpleFeedEnvelopeSerializer(BaseFeedEnvelopeSerializer):
    iocs = SimpleFeedResponseSerializer(many=True)


class PaginatedSimpleFeedSerializer(serializers.Serializer):
    count = serializers.IntegerField(help_text="Total number of IOCs across all pages.")
    total_pages = serializers.IntegerField(help_text="Total number of pages.")
    results = SimpleFeedEnvelopeSerializer()


class AdvancedFeedEnvelopeSerializer(BaseFeedEnvelopeSerializer):
    iocs = AdvancedFeedResponseSerializer(many=True)
