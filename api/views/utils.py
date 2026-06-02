# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import csv
import hashlib
import logging
import urllib.parse
from datetime import timedelta

import feedparser
import requests
from django.conf import settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.core.cache import cache, caches
from django.db import transaction
from django.db.models import Count, F, Max, Min, Sum
from django.http import HttpResponse, HttpResponseBadRequest, StreamingHttpResponse
from rest_framework import status
from rest_framework.response import Response
from stix2 import Bundle, ExternalReference, Indicator

from greedybear.consts import CACHE_KEY_GREEDYBEAR_NEWS, CACHE_TIMEOUT_SECONDS, RSS_FEED_URL
from greedybear.models import AutonomousSystem, Sensor, SourceType, Statistics
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


def save_request_source(request):
    try:
        source_ip = get_request_source_ip(request)
        request_source = Statistics(source=source_ip)
        request_source.save()
    except UnableToExtractSourceIPError:
        logger.warning("Skipping statistics recording due to unable to extract source IP")


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


def feeds_response(request=None, iocs=None, response_format="json", dict_only=False, verbose=False, include_sensors=False):
    """
    Format the IOC data into the requested format (e.g., JSON, CSV, TXT).

    Args:
        iocs (QuerySet): The filtered queryset of IOC data.
        feed_params (dict): Validated request parameters (serializer validated_data), including format.
        dict_only (bool): Return IOC dictionary instead of Response object.
        verbose (bool): Include verbose fields (days_seen, destination_ports, honeypots, firehol_categories).

    Returns:
        Response: The HTTP response containing formatted IOC data.
    """
    logger.info(f"Format feeds in: {response_format}")
    match response_format:
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
        feed_params (dict): Validated request parameters (serializer validated_data)

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
    ordering = feed_params["ordering"]
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


@transaction.atomic
def create_or_get_sensor(*, api_source, validated_data):
    """
    Logic for sensor creation/retrieval.
    """

    asn_value = validated_data.pop("asn", None)

    autonomous_system = None
    if asn_value:
        autonomous_system, _ = AutonomousSystem.objects.get_or_create(
            asn=asn_value,
            defaults={"name": ""},
        )
        validated_data["autonomous_system"] = autonomous_system

    address = validated_data["address"]

    sensor, created = Sensor.objects.get_or_create(
        address=address,
        api_source=api_source,
        defaults={
            **validated_data,
            "source_type": SourceType.EXTERNAL,
        },
    )

    return sensor, created
