# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import hashlib
import logging
import urllib.parse
from datetime import datetime, timedelta

import feedparser
import requests
from django.conf import settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.core.cache import cache, caches
from django.db.models import Count, F, Max, Min, Q, Sum, Value
from django.db.models.functions import JSONObject
from django.http import HttpResponse, HttpResponseBadRequest, StreamingHttpResponse
from rest_framework import status
from rest_framework.response import Response
from stix2 import Bundle, ExternalReference, Indicator

from api.serializers import FeedsRequestSerializer, parse_feed_types
from greedybear.consts import CACHE_KEY_GREEDYBEAR_NEWS, CACHE_TIMEOUT_SECONDS, RSS_FEED_URL
from greedybear.enums import IpReputation
from greedybear.models import IOC, Honeypot, Statistics
from greedybear.utils import is_ip_address, is_valid_domain

logger = logging.getLogger(__name__)


class UnableToExtractSourceIPError(Exception):
    """Raised when no valid source IP can be extracted from the request."""


class Echo:
    """An object that implements just the write method of the file-like
    interface.
    This class is used to stream data in CSV format.
    """

    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer.

        Args:
            value (str): The value to be written.

        Returns:
            str: The same value that was passed.
        """
        return value


def get_request_source_ip(request) -> str:
    """Extract a normalized client IP from request metadata (X-Forwarded-For header)

    Raises:
        UnableToExtractSourceIPError: When no valid IP is found
    """

    forwarded_for = str(request.META.get("HTTP_X_FORWARDED_FOR", ""))

    candidates = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]

    for candidate in candidates:
        if is_ip_address(candidate):
            return candidate

    logger.error("Unable to extract valid source IP from request. X-Forwarded-For: %s", forwarded_for)
    raise UnableToExtractSourceIPError("No valid source IP found in request metadata")


class FeedRequestParams:
    """A class to handle and validate feed request parameters.
    It processes and stores query parameters for feed requests,
    providing default values.

    Attributes:
        feed_type (str): comma-separated feed type string as supplied by the
            caller (default: "all").
        feed_types (list[str]): List of individual feed type values derived from
            ``feed_type`` by splitting on commas.
        attack_type (str): Type of attack to filter (default: "all")
        ioc_type (str): Type of IOC to filter - 'ip', 'domain', or 'all' (default: "all")
        max_age (str): Maximum number of days since last occurrence (default: "3")
        min_days_seen (str): Minimum number of days on which an IOC must have been seen (default: "1")
        include_reputation (list): List of reputation values to include (default: [])
        exclude_reputation (list): List of reputation values to exclude (default: [])
        feed_size (int): Number of items to return in feed (default: "5000")
        ordering (str): Field to order results by (default: "-last_seen")
        verbose (str): Whether to include IOC properties that contain a lot of data (default: "false")
        paginate (str): Whether to paginate results (default: "false")
        format_ (str): Response format type (default: "json")
    """

    def __init__(self, query_params: dict):
        """Initialize a new FeedRequestParams instance.

        Parameters:
            query_params (dict): Dictionary containing query parameters for feed configuration.
        """
        feed_type_str = query_params.get("feed_type", "all").lower()
        self.feed_type = feed_type_str
        self.feed_types = parse_feed_types(feed_type_str)
        self.attack_type = query_params.get("attack_type", "all").lower()
        self.ioc_type = query_params.get("ioc_type", "all").lower()
        self.max_age = query_params.get("max_age", "3")
        self.min_days_seen = query_params.get("min_days_seen", "1")
        # Handle reputation lists (could be list from JSON or string from QueryDict)
        inc_rep = query_params.get("include_reputation", [])
        if isinstance(inc_rep, list):
            self.include_reputation = inc_rep
        else:
            self.include_reputation = inc_rep.split(";") if inc_rep else []

        exc_rep = query_params.get("exclude_reputation", [])
        if isinstance(exc_rep, list):
            self.exclude_reputation = exc_rep
        else:
            self.exclude_reputation = exc_rep.split(";") if exc_rep else []

        self.feed_size = query_params.get("feed_size", "5000")
        self.ordering = query_params.get("ordering", "-last_seen").lower().replace("value", "name")
        self.verbose = query_params.get("verbose", "false").lower()
        self.paginate = query_params.get("paginate", "false").lower()
        # Support both format_ and format
        self.format = query_params.get("format_", query_params.get("format", "json")).lower()
        self.feed_type_sorting = None
        self.asn = query_params.get("asn")
        self.min_score = query_params.get("min_score")
        self.min_expected_interactions = query_params.get("min_expected_interactions")
        self.port = query_params.get("port")
        self.start_date = query_params.get("start_date")
        self.end_date = query_params.get("end_date")
        self.country_code = query_params.get("country_code")
        self.min_credential_count = query_params.get("min_credential_count")
        self.max_credential_count = query_params.get("max_credential_count")

    def apply_default_filters(self, query_params):
        if not query_params:
            query_params = {}
        if "include_mass_scanners" not in query_params:
            self.exclude_reputation.append(IpReputation.MASS_SCANNER)
        if "include_tor_exit_nodes" not in query_params:
            self.exclude_reputation.append(IpReputation.TOR_EXIT_NODE)

    def set_prioritization(self, prioritize: str):
        match prioritize:
            case "recent":
                self.max_age = "3"
                self.min_days_seen = "1"
                if "feed_type" in self.ordering:
                    self.feed_type_sorting = self.ordering
                    self.ordering = "-last_seen"
            case "persistent":
                self.max_age = "14"
                self.min_days_seen = "10"
                if "feed_type" in self.ordering:
                    self.feed_type_sorting = self.ordering
                    self.ordering = "-attack_count"
            case "likely_to_recur":
                self.max_age = "30"
                self.min_days_seen = "1"
                self.ordering = "-recurrence_probability"
            case "most_expected_hits":
                self.max_age = "30"
                self.min_days_seen = "1"
                self.ordering = "-expected_interactions"


def get_valid_feed_types() -> frozenset[str]:
    """
    Retrieve all valid feed types, combining predefined types with active general honeypot names.

    Returns:
        frozenset[str]: An immutable set of valid feed type strings
    """
    honeypots = Honeypot.objects.filter(active=True)
    feed_types = ["all"] + [hp.name.lower() for hp in honeypots]
    return frozenset(feed_types)


def get_queryset(
    request,
    feed_params,
    valid_feed_types,
    is_aggregated=False,
    serializer_class=FeedsRequestSerializer,
    tag_key="",
    tag_value="",
    include_sensors=False,
    include_credential_count=False,
):
    """
    Build a queryset to filter IOC data based on the request parameters.

    Args:
        request: The incoming request object.
        feed_params: A FeedRequestParams instance.
        valid_feed_types (frozenset): The set of all valid feed types.
        is_aggregated (bool, optional):
            - If True, disables slicing (`feed_size`) and model-level ordering.
            - Ensures full dataset is available for aggregation or specialized computation.
            - Default: False.
        serializer_class (class, optional):
            - Serializer class used to validate request parameters.
            - Allows injecting a custom serializer to enforce rules for specific feed types
              (e.g., to restrict ordering fields or validation for specialized feeds).
            - Default: `FeedsRequestSerializer`.
        tag_key (str, optional): Filter IOCs by tag key. Only passed from feeds_advanced.
        tag_value (str, optional): Filter IOCs by tag value (case-insensitive substring). Only passed from feeds_advanced.
        include_sensors (bool, optional): If True, annotates sensors_json for each IOC.
            Only passed from authenticated views like feeds_advanced. Default: False.
        include_credential_count (bool, optional): If True, annotates credential Count for each IOC.
            Only passed from authenticated views like feeds_advanced. Default: False.
    Returns:
        QuerySet: The filtered queryset of IOC data.
    """
    source = str(request.user)
    logger.info(
        f"request from {source}. Feed type: {feed_params.feed_type}, attack_type: {feed_params.attack_type}, "
        f"Age: {feed_params.max_age}, format: {feed_params.format}"
    )

    feed_params_data = {k: v for k, v in vars(feed_params).items() if v is not None}
    serializer = serializer_class(
        data=feed_params_data,
        context={"valid_feed_types": valid_feed_types},
    )
    serializer.is_valid(raise_exception=True)

    query_dict = {}
    if feed_params.attack_type != "all":
        query_dict[feed_params.attack_type] = True

    if feed_params.ioc_type != "all":
        query_dict["type"] = feed_params.ioc_type

    # Advanced filters
    if feed_params.asn:
        query_dict["autonomous_system__asn"] = feed_params.asn
    if feed_params.min_score is not None:
        query_dict["recurrence_probability__gte"] = feed_params.min_score
    if feed_params.min_expected_interactions is not None:
        query_dict["expected_interactions__gte"] = feed_params.min_expected_interactions
    if feed_params.port:
        query_dict["destination_ports__contains"] = [int(feed_params.port)]
    if feed_params.country_code:
        query_dict["attacker_country_code"] = feed_params.country_code.upper()

    # Date handling
    if feed_params.start_date:
        query_dict["last_seen__gte"] = feed_params.start_date
    if feed_params.end_date:
        query_dict["last_seen__lte"] = feed_params.end_date

    # Fallback to max_age ONLY if no date range is specified
    if not (feed_params.start_date or feed_params.end_date):
        query_dict["last_seen__gte"] = datetime.now() - timedelta(days=int(feed_params.max_age))

    if int(feed_params.min_days_seen) > 1:
        query_dict["number_of_days_seen__gte"] = int(feed_params.min_days_seen)
    if feed_params.include_reputation:
        query_dict["ip_reputation__in"] = feed_params.include_reputation

    if tag_key:
        query_dict["tags__key"] = tag_key[:128]  # Truncate to Tag.key max_length
    if tag_value:
        query_dict["tags__value__icontains"] = tag_value[:256]  # Truncate to Tag.value max_length

    iocs = IOC.objects.filter(**query_dict).exclude(ip_reputation__in=feed_params.exclude_reputation).annotate(value=F("name")).distinct()

    # credential count filtering is only available on the advanced feed
    if include_credential_count:
        iocs = iocs.annotate(credential_count=Count("credentials", distinct=True))
        min_credential_count = serializer.validated_data.get("min_credential_count")
        max_credential_count = serializer.validated_data.get("max_credential_count")
        if min_credential_count is not None:
            iocs = iocs.filter(credential_count__gte=min_credential_count)
        if max_credential_count is not None:
            iocs = iocs.filter(credential_count__lte=max_credential_count)

    # apply feed type filter as union;
    if "all" not in feed_params.feed_types:
        type_filter = Q()
        for ft in feed_params.feed_types:
            type_filter |= Q(honeypots__name__iexact=ft)
        iocs = iocs.filter(type_filter)

    # aggregated feeds calculate metrics differently and need all rows to be accurate.
    if not is_aggregated:
        iocs = iocs.filter(honeypots__active=True)
        iocs = iocs.annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
        # Only annotate tags metadata when the response format needs it (e.g. JSON),
        # to avoid unnecessary joins and aggregation work for txt/csv feeds.
        if getattr(feed_params, "format", "").lower() == "json":
            iocs = iocs.annotate(
                tags_json=ArrayAgg(
                    JSONObject(key=F("tags__key"), value=F("tags__value"), source=F("tags__source")),
                    filter=Q(tags__isnull=False),
                    default=Value([]),
                    distinct=True,
                )
            )
            if include_sensors:
                iocs = iocs.annotate(
                    sensors_json=ArrayAgg(
                        JSONObject(address=F("sensors__address"), label=F("sensors__label")),
                        filter=Q(sensors__isnull=False),
                        default=Value([]),
                        distinct=True,
                    )
                )
        iocs = iocs.order_by(feed_params.ordering)
        iocs = iocs[: int(feed_params.feed_size)]

    # save request source for statistics
    try:
        source_ip = get_request_source_ip(request)
        request_source = Statistics(source=source_ip)
        request_source.save()
    except UnableToExtractSourceIPError:
        logger.warning("Skipping statistics recording due to unable to extract source IP")
    return iocs


def ioc_as_dict(ioc, fields: set) -> dict:
    """
    Convert an IOC object to a dictionary containing only the specified fields.

    Args:
        ioc: An IOC object
        fields (set): A set of field names to include in the output dictionary

    Returns:
        dict: A dictionary containing all fields from the IOC object where the field name exists in fields
    """
    return {k: v for k, v in ioc.__dict__.items() if k in fields}


def feeds_response(request=None, iocs=None, feed_params=None, valid_feed_types=None, dict_only=False, verbose=False, include_sensors=False):
    """
    Format the IOC data into the requested format (e.g., JSON, CSV, TXT).

    Args:
        iocs (QuerySet): The filtered queryset of IOC data.
        feed_params (FeedRequestParams): Request parameters including format.
        valid_feed_types (frozenset): The set of all valid feed types.
        dict_only (bool): Return IOC dictionary instead of Response object.
        verbose (bool): Include verbose fields (days_seen, destination_ports, honeypots, firehol_categories).

    Returns:
        Response: The HTTP response containing formatted IOC data.
    """
    logger.info(f"Format feeds in: {feed_params.format}")
    match feed_params.format:
        case "txt":
            text_lines = [f"# {settings.FEEDS_LICENSE}"] if settings.FEEDS_LICENSE else []
            text_lines += [ioc[0] for ioc in iocs.values_list("name")]
            return HttpResponse("\n".join(text_lines), content_type="text/plain")
        case "csv":
            rows = [[f"# {settings.FEEDS_LICENSE}"]] if settings.FEEDS_LICENSE else []
            rows += [list(ioc) for ioc in iocs.values_list("name")]
            pseudo_buffer = Echo()
            writer = csv.writer(pseudo_buffer, quoting=csv.QUOTE_NONE)
            return StreamingHttpResponse(
                (writer.writerow(row) for row in rows),
                content_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="feeds.csv"'},
                status=200,
            )
        case "json":
            json_list = []

            # Base fields always returned
            base_fields = (
                "value",
                "first_seen",
                "last_seen",
                "attack_count",
                "credential_count",
                "interaction_count",
                "scanner",
                "payload_request",
                "ip_reputation",
                "login_attempts",
                "recurrence_probability",
                "expected_interactions",
                "honeypot_names",  # used to build feed_type; removed from response
                "destination_ports",  # used to calculate destination_port_count
                "attacker_country",
                "attacker_country_code",
                "autonomous_system",
                "tags",
            )

            verbose_only_fields = (
                "days_seen",
                "firehol_categories",
            )

            required_fields = base_fields + verbose_only_fields if verbose else base_fields

            # `tags_json` is annotated in get_queryset (only for JSON format) to avoid conflicting
            # with the `tags` reverse FK on IOC. When the queryset comes from a repository method
            # that does not annotate `tags_json` (e.g. the ML scoring path), exclude the field.
            # `sensors_json` follows the same pattern and is only annotated for authenticated views.
            if isinstance(iocs, list):
                has_tags_annotation = bool(iocs) and hasattr(iocs[0], "tags_json")
                has_sensors_annotation = include_sensors and bool(iocs) and hasattr(iocs[0], "sensors_json")
                has_credential_count = bool(iocs) and hasattr(iocs[0], "credential_count")
            else:
                has_tags_annotation = "tags_json" in getattr(iocs, "query", type("", (), {"annotations": {}})()).annotations
                has_sensors_annotation = include_sensors and "sensors_json" in getattr(iocs, "query", type("", (), {"annotations": {}})()).annotations
                has_credential_count = "credential_count" in getattr(iocs, "query", type("", (), {"annotations": {}})()).annotations
            required_fields = tuple(("tags_json" if f == "tags" else f) for f in required_fields if f != "tags" or has_tags_annotation)
            required_fields = tuple(f for f in required_fields if f != "credential_count" or has_credential_count)
            if has_sensors_annotation:
                required_fields = (*required_fields, "sensors_json")

            iocs_iter: object
            if isinstance(iocs, list):
                iocs_iter = (ioc_as_dict(ioc, set(required_fields)) for ioc in iocs)
            else:
                iocs_iter = iocs.values(*required_fields).iterator(chunk_size=2000)
            for ioc in iocs_iter:
                ioc_feed_type = [hp.lower() for hp in ioc.get("honeypot_names", []) if hp]

                data_ = ioc | {
                    "first_seen": ioc["first_seen"].strftime("%Y-%m-%d"),
                    "last_seen": ioc["last_seen"].strftime("%Y-%m-%d"),
                    "feed_type": ioc_feed_type,
                    "destination_port_count": len(ioc.get("destination_ports", [])),
                    "asn": ioc.get("autonomous_system", ""),
                    "tags": ioc.pop("tags_json", []),
                    **({"sensors": ioc.pop("sensors_json", [])} if has_sensors_annotation else {}),
                }

                if not verbose:
                    data_.pop("destination_ports", None)
                data_.pop("autonomous_system", None)
                data_.pop("honeypot_names", None)
                data_.pop("id", None)

                json_list.append(data_)

            if feed_params.feed_type_sorting is not None:
                logger.info("Return feeds sorted by feed_type field")
                json_list = sorted(
                    json_list,
                    key=lambda k: k["feed_type"],
                    reverse=feed_params.feed_type_sorting == "-feed_type",
                )

            logger.info(f"Number of feeds returned: {len(json_list)}")
            resp_data = {"iocs": json_list}
            if settings.FEEDS_LICENSE:
                resp_data["license"] = settings.FEEDS_LICENSE
            if dict_only:
                return resp_data
            return Response(resp_data, status=status.HTTP_200_OK)
        case "stix21":
            stix_fields = {
                "value",
                "type",
                "first_seen",
                "last_seen",
                "recurrence_probability",
                "honeypot_names",
                "ip_reputation",
            }
            # Fetch fields from database
            iocs = (ioc_as_dict(ioc, stix_fields) for ioc in iocs) if isinstance(iocs, list) else iocs.values(*stix_fields)

            stix_objects = []
            for ioc in iocs:
                value = ioc["value"]
                ioc_type = ioc["type"]

                # Validate and sanitize value before inserting into STIX pattern
                # to prevent pattern injection via malicious IOC values.
                if ioc_type == "ip":
                    if not is_ip_address(value):
                        logger.warning(f"Skipping IOC with invalid IP value for STIX export: {value!r}")
                        continue
                    stix_type = "ipv6-addr" if ":" in value else "ipv4-addr"
                    pattern = f"[{stix_type}:value = '{value}']"
                else:  # domain
                    if not is_valid_domain(value):
                        logger.warning(f"Skipping IOC with unsafe domain value for STIX export: {value!r}")
                        continue
                    pattern = f"[domain-name:value = '{value}']"

                # Confidence 0-100.
                # We use a fixed high confidence (90) for honeypot observations as they are highly reliable.
                confidence = 90

                # Labels
                labels = [hp.lower() for hp in ioc.get("honeypot_names", []) if hp]
                if ioc.get("ip_reputation"):
                    labels.append(ioc["ip_reputation"])

                indicator = Indicator(
                    name=value,
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=ioc["first_seen"],
                    valid_until=ioc["last_seen"] + timedelta(days=1),
                    labels=labels,
                    confidence=confidence,
                    description=f"Detected by GreedyBear honeypots: {', '.join(labels)}",
                    external_references=[
                        ExternalReference(
                            source_name="GreedyBear",
                            url=(request.build_absolute_uri(f"/?query={value}") if request else f"https://greedybear.honeynet.org/?query={value}"),
                        )
                    ],
                )
                stix_objects.append(indicator)

            bundle = Bundle(objects=stix_objects)
            return HttpResponse(bundle.serialize(), content_type="application/json")
        case _:
            return HttpResponseBadRequest()


def asn_aggregated_queryset(iocs_qs, request, feed_params):
    """
    Retrieve ASN aggregation data. Caches the heavy aggregation query
    since the data only updates during the extraction cronjob.

    Args
        iocs_qs (QuerySet): Filtered IOC queryset from get_queryset;
        request (Request): The API request object;
        feed_params (FeedRequestParams): Validated parameter object

    Returns: A list of dicts with aggregated metrics and honeypot arrays per ASN.
    """

    # Build reliable cache key from query params
    sorted_params = sorted(request.query_params.lists())
    params_string = urllib.parse.urlencode(sorted_params, doseq=True)
    param_hash = hashlib.sha256(params_string.encode("utf-8")).hexdigest()

    # To prevent per-worker continuous RAM bloat, use the shared DB-backed cache
    # instead of the default LocMemCache, since the JSON response size can be large.
    # The extraction pipeline invalidates this cache by bumping the version counter.
    shared_cache = caches["django-q"]
    version = shared_cache.get("asn_feeds_version", 1)
    cache_key = f"asn_feeds_v{version}_{param_hash}"

    cached_result = shared_cache.get(cache_key)
    if cached_result is not None:
        return cached_result

    asn_filter = request.query_params.get("asn")
    if asn_filter:
        iocs_qs = iocs_qs.filter(autonomous_system__asn=asn_filter)

    # default ordering is overridden here because of serializer default(-last-seen) behaviour
    ordering = feed_params.ordering
    if not ordering or ordering.strip() in {"", "-last_seen", "last_seen"}:
        ordering = "-ioc_count"

    numeric_agg = (
        iocs_qs.exclude(autonomous_system__isnull=True)
        .values(
            asn=F("autonomous_system__asn"),
            as_name=F("autonomous_system__name"),
        )
        .annotate(
            ioc_count=Count("id"),
            total_attack_count=Sum("attack_count"),
            total_interaction_count=Sum("interaction_count"),
            total_login_attempts=Sum("login_attempts"),
            expected_ioc_count=Sum("recurrence_probability"),
            expected_interactions=Sum("expected_interactions"),
            first_seen=Min("first_seen"),
            last_seen=Max("last_seen"),
        )
    )
    numeric_agg = numeric_agg.order_by(ordering)

    # Honeypot names still require a lightweight aggregation because
    # they depend on the active flag which can change independently.
    honeypot_agg = (
        iocs_qs.exclude(autonomous_system__isnull=True)
        .filter(honeypots__active=True)
        .values(asn=F("autonomous_system__asn"))
        .annotate(
            honeypot_names=ArrayAgg(
                "honeypots__name",
                distinct=True,
            )
        )
    )

    hp_lookup = {row["asn"]: row["honeypot_names"] or [] for row in honeypot_agg}

    result = []
    for row in numeric_agg:
        asn = row["asn"]
        row_dict = dict(row)
        row_dict["honeypots"] = sorted(hp_lookup.get(asn, []))
        result.append(row_dict)

    # Set cache with a 60-minute timeout (max extraction interval length) to prevent memory bloat
    shared_cache.set(cache_key, result, timeout=3600)

    return result


def get_greedybear_news() -> list[dict]:
    """
    Fetch GreedyBear-related blog posts from the IntelOwl RSS feed.

    Returns:
        List of dicts with keys: title, date, link, subtext
        Sorted newest first, or empty list on failure.
    """
    cached = cache.get(CACHE_KEY_GREEDYBEAR_NEWS)
    if cached is not None:
        return cached

    try:
        response = requests.get(RSS_FEED_URL, timeout=5)
        response.raise_for_status()
        feed = feedparser.parse(response.content)

        filtered_entries = sorted(
            [entry for entry in feed.entries if entry.get("published_parsed")],
            key=lambda e: e.published_parsed,
            reverse=True,
        )

        news_items: list[dict] = []
        for entry in filtered_entries:
            summary = entry.get("summary", "").strip().replace("\n", " ")

            subtext = summary[:180].rsplit(" ", 1)[0] + "..." if len(summary) > 180 else summary

            news_items.append(
                {
                    "title": entry.get("title"),
                    "date": entry.get("published"),
                    "link": entry.get("link"),
                    "subtext": subtext,
                }
            )
    except Exception:
        logger.exception("Failed to fetch GreedyBear news from RSS feed")
        return []
    else:
        cache.set(
            CACHE_KEY_GREEDYBEAR_NEWS,
            news_items,
            CACHE_TIMEOUT_SECONDS,
        )
        return news_items
