# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
import uuid
from datetime import timedelta

import feedparser
import requests
from django.conf import settings
from django.contrib.postgres.aggregates import ArrayAgg
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, F, Max, Min, Sum
from rest_framework import status
from rest_framework.response import Response
from stix2 import Bundle, ExternalReference, Indicator

from greedybear.consts import APISOURCE_LOCKED_THRESHOLD, CACHE_KEY_GREEDYBEAR_NEWS, CACHE_TIMEOUT_SECONDS, RSS_FEED_URL
from greedybear.models import APISource, AutonomousSystem, EventStatus, EventStatusType, RawEvent, Sensor, SourceType, Statistics
from greedybear.utils import is_ip_address, is_valid_domain

logger = logging.getLogger(__name__)


class UnableToExtractSourceIPError(Exception):
    """Raised when no valid source IP can be extracted from the request."""


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


# JSON output fields. `honeypot_names` and `destination_ports` are fetched to derive
# `feed_type` / `destination_port_count` and then dropped from each row.
JSON_BASE_FIELDS = (
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
    "honeypot_names",
    "destination_ports",
    "attacker_country",
    "attacker_country_code",
    "autonomous_system",
    "tags",
)
JSON_VERBOSE_FIELDS = (
    "days_seen",
    "firehol_categories",
)
STIX_FIELDS = {
    "value",
    "type",
    "first_seen",
    "last_seen",
    "recurrence_probability",
    "honeypot_names",
    "ip_reputation",
}


def build_ioc_json_list(iocs, verbose=False, include_sensors=False) -> list[dict]:
    """Shape a queryset (or list) of IOCs into the JSON feed row dicts.

    Pure data logic shared by the JSON renderer and the ML scoring path; it
    builds the per-row dicts but performs no HTTP/encoding work.

    Args:
        iocs (QuerySet | list): Filtered IOCs to render.
        verbose (bool): Include verbose fields (days_seen, destination_ports, firehol_categories).
        include_sensors (bool): Emit a `sensors` array when the `sensors_json` annotation is present.

    Returns: A list of JSON-serializable IOC dicts.
    """
    required_fields = JSON_BASE_FIELDS + JSON_VERBOSE_FIELDS if verbose else JSON_BASE_FIELDS

    # `tags_json` is annotated in get_queryset (only for JSON format) to avoid conflicting
    # with the `tags` reverse FK on IOC. When the queryset comes from a repository method
    # that does not annotate `tags_json` (e.g. the ML scoring path), exclude the field.
    # `sensors_json` follows the same pattern and is only annotated for authenticated views.
    if isinstance(iocs, list):
        has_tags_annotation = bool(iocs) and hasattr(iocs[0], "tags_json")
        has_sensors_annotation = include_sensors and bool(iocs) and hasattr(iocs[0], "sensors_json")
        has_credential_count = bool(iocs) and hasattr(iocs[0], "credential_count")
    else:
        annotations = getattr(getattr(iocs, "query", None), "annotations", {})
        has_tags_annotation = "tags_json" in annotations
        has_sensors_annotation = include_sensors and "sensors_json" in annotations
        has_credential_count = "credential_count" in annotations
    required_fields = tuple(("tags_json" if f == "tags" else f) for f in required_fields if f != "tags" or has_tags_annotation)
    required_fields = tuple(f for f in required_fields if f != "credential_count" or has_credential_count)
    if has_sensors_annotation:
        required_fields = (*required_fields, "sensors_json")

    if isinstance(iocs, list):
        iocs_iter = (ioc_as_dict(ioc, set(required_fields)) for ioc in iocs)
    else:
        iocs_iter = iocs.values(*required_fields).iterator(chunk_size=2000)

    json_list = []
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
    return json_list


def build_feed_dict(iocs, verbose=False, include_sensors=False) -> dict:
    """Wrap the JSON feed rows in the public response envelope, attaching the license when set."""
    resp_data = {"iocs": build_ioc_json_list(iocs, verbose=verbose, include_sensors=include_sensors)}
    if settings.FEEDS_LICENSE:
        resp_data["license"] = settings.FEEDS_LICENSE
    return resp_data


def build_stix_bundle(iocs, request=None) -> str:
    """Serialize a queryset (or list) of IOCs into a STIX 2.1 bundle JSON string."""
    iocs = (ioc_as_dict(ioc, STIX_FIELDS) for ioc in iocs) if isinstance(iocs, list) else iocs.values(*STIX_FIELDS)

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

    return Bundle(objects=stix_objects).serialize()


def _asn_honeypot_lookup(with_asn) -> dict:
    """Per-ASN active-honeypot names.

    Kept separate from the numeric aggregation because it filters on
    honeypots.active, which changes independently of the IOC data.

    Args:
        with_asn (QuerySet): IOC queryset already restricted to rows with an ASN.

    Returns: A dict mapping ASN -> sorted-ready list of active honeypot names.
    """
    rows = with_asn.filter(honeypots__active=True).values(asn=F("autonomous_system__asn")).annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
    return {row["asn"]: row["honeypot_names"] or [] for row in rows}


def aggregate_iocs_by_asn(iocs_qs, ordering: str) -> list[dict]:
    """Aggregate a filtered IOC queryset into per-ASN metric rows.

    Pure data logic: no request/cache concerns. IOCs without an ASN are dropped.

    Args:
        iocs_qs (QuerySet): Filtered IOC queryset from the view's get_queryset;
        ordering (str): Validated aggregate ordering field (e.g. "-ioc_count").

    Returns: A list of dicts with aggregated metrics and honeypot arrays per ASN.
    """
    with_asn = iocs_qs.exclude(autonomous_system__isnull=True)

    numeric_agg = (
        with_asn.values(
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
        .order_by(ordering)
    )

    hp_lookup = _asn_honeypot_lookup(with_asn)

    return [{**row, "honeypots": sorted(hp_lookup.get(row["asn"], []))} for row in numeric_agg]


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


def _bulk_create_raw_events(events_data: list[dict], batch: EventStatus, api_source: APISource) -> int:
    """
    Validates sensor ownership and bulk-inserts raw event payloads into the database.

    This internal utility performs an optimized prefetch lookup of all referenced sensors to
    ensure they exist and belong to the calling `APISource`. It validates the incoming list
    upfront to fail fast on foreign or missing sensor identifiers, securely strips the mapping
    fields to prevent schema mismatch unpacking errors, and stages the data into memory.

    Args:
        events_data (list[dict]): A collection of un-persisted, validated event data dictionaries.
        batch (EventStatus): The tracking batch model instance these events belong to.
        api_source (APISource): The origin provider authority submitting the events.

    Returns:
        int: The aggregate count of total RawEvent rows successfully inserted into the database.

    Raises:
        ValueError: If any entry contains a sensor_id that does not exist or is not owned
                    by the given api_source.

    """
    chunk_size = 1000

    # Prefetch all sensors in one query
    sensor_ids = {e["sensor_id"] for e in events_data if "sensor_id" in e}
    sensors_by_id = {s.id: s for s in Sensor.objects.filter(id__in=sensor_ids, api_source=api_source)}

    raw_events = []

    for e in events_data:
        sensor_id = e.get("sensor_id")
        if sensor_id not in sensors_by_id:
            raise ValueError(f"Invalid or missing sensor_id '{sensor_id}' for api_source {api_source.id}. ")

    for event in events_data:
        sensor_id = event.get("sensor_id")
        sensor = sensors_by_id.get(sensor_id)

        # creating a shallow copy (protects the original data from side effects)
        event_fields = event.copy()

        # safely remove 'sensor_id' so it doesn't break ** unpacking
        if "sensor_id" in event_fields:
            del event_fields["sensor_id"]

        raw_events.append(RawEvent(sensor=sensor, batch=batch, **event_fields))

    total = 0
    for i in range(0, len(raw_events), chunk_size):
        chunk = raw_events[i : i + chunk_size]
        RawEvent.objects.bulk_create(chunk)
        total += len(chunk)
    return total


def create_batch_and_events(events_data: list[dict], api_source: APISource) -> tuple[EventStatus, int]:
    """
    Initializes a tracking batch and executes an atomic bulk-creation of RawEvents.

    Args:
        events_data (list[dict]): A list of validated event data dictionaries to populate.
        api_source (APISource): The authenticated origin provider entity submitting the batch.

    Returns:
        tuple[EventStatus, int]: A tuple containing the created EventStatus tracking model
                                instance and the integer count of successfully stored events.

    Raises:
        Exception: Re-raises any underlying database error encountered during the bulk creation
                  process after writing the crash state metadata.
    """
    tracking_id = uuid.uuid4().hex

    batch = EventStatus.objects.create(
        api_source=api_source,
        task_id=tracking_id,
        status=EventStatusType.PENDING,
    )
    try:
        with transaction.atomic():
            total_created = _bulk_create_raw_events(
                events_data,
                batch,
                api_source,
            )
    except Exception as e:
        logger.exception(f"Database error during bulk-insert for batch {batch.task_id}")

        # updating the batch status here because it's outside the failed atomic block,
        batch.status = EventStatusType.FAILED
        batch.last_error = str(e)
        batch.save(update_fields=["status", "last_error"])
        raise

    return batch, total_created


def increment_and_evaluate_lock(api_source: APISource) -> Response | None:
    """
    Increments the failed batch attempts for an APISource and checks if the safety
    threshold has been reached. If exceeded, it automatically locks the source.

    Returns a 403 Response if locked, otherwise returns None.
    """
    api_source.invalid_event_count = F("invalid_event_count") + 1
    api_source.save(update_fields=["invalid_event_count"])

    api_source.refresh_from_db()

    if api_source.invalid_event_count >= APISOURCE_LOCKED_THRESHOLD:
        api_source.is_active = False
        api_source.save(update_fields=["is_active"])
        return Response({"error": "Your APISource has been automatically locked due to excessive invalid batch submissions."}, status=status.HTTP_403_FORBIDDEN)

    return None
