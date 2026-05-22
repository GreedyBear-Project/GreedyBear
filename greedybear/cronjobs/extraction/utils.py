from collections import defaultdict
from ipaddress import ip_address, ip_network
from logging import Logger
from urllib.parse import urlparse

import requests
from django.conf import settings

from greedybear.cronjobs.repositories import ASRepository
from greedybear.enums import IpReputation
from greedybear.models import IOC, FireHolList, MassScanner
from greedybear.utils import get_ioc_type, is_non_global_ip, parse_timestamp


def normalize_credential_field(value: object, max_length: int = 256) -> str:
    """
    Normalize a credential field from untrusted input.

    Args:
        value: Raw field value.
        max_length: Maximum length allowed by the model field.

    Returns:
        Sanitized credential field string.
    """
    text = "" if value is None else str(value)
    return text.replace("\x00", "[NUL]")[:max_length]


def is_whatsmyip_domain(domain: str, whatsmyip_domains: set) -> bool:
    """
    Check if a domain is a known "what's my IP" service.

    Args:
        domain: Domain name to check.
        whatsmyip_domains: Set of known whats-my-ip domains.

    Returns:
        True if the domain is in the WhatsMyIP list, False otherwise.
    """
    return domain in whatsmyip_domains


def correct_ip_reputation(ip: str, ip_reputation: str, mass_scanner_ips: set) -> str:
    """
    Correct IP reputation based on mass scanner database.
    Overrides reputation to MASS_SCANNER if the IP is found in the MassScanners table.
    This is necessary because we have seen mass scanners incorrectly flagged.

    Args:
        ip: IP address to check.
        ip_reputation: Current reputation string.
        mass_scanner_ips: A set of known mass scanner IPs.

    Returns:
        Corrected reputation string.
    """
    if (not ip_reputation or ip_reputation == IpReputation.KNOWN_ATTACKER) and ip in mass_scanner_ips:
        ip_reputation = IpReputation.MASS_SCANNER
    return ip_reputation


def get_firehol_categories(ip: str, extracted_ip, firehol_exact_map: dict, cidr_entries: list) -> list[str]:
    """
    Get FireHol categories for an IP address.
    Checks both exact IP matches (for .ipset files) and network range
    membership (for .netset files with CIDR notation).

    Args:
        ip: IP address string.
        extracted_ip: Parsed IP address object from ipaddress library.
        firehol_exact_map: Dict mapping IPs to lists of FireHol sources.
        cidr_entries: List of tuples (ip_network, source) for CIDR entries.

    Returns:
        List of FireHol source categories.
    """
    firehol_categories = list(firehol_exact_map.get(ip, []))

    for network, source in cidr_entries:
        if source and extracted_ip in network and source not in firehol_categories:
            firehol_categories.append(source)

    return firehol_categories


def iocs_from_hits(hits: list[dict]) -> list[IOC]:
    """
    Convert Elasticsearch hits into IOC objects with associated sensors.
    Groups hits by source IP, filters out non-global addresses, and
    constructs IOC objects with aggregated data.
    Enriches IOCs with FireHol categories at creation time to ensure
    only fresh data is used.

    Performs bulk prefetching before the main loop to eliminate N+1 queries
    by injecting the bulk data into the helper evaluation functions.

    Args:
        hits: List of Elasticsearch hit dictionaries.

    Returns:
        List of IOC instances, one per unique source IP.
    """
    hits_by_ip = defaultdict(list)
    for hit in hits:
        hits_by_ip[hit["src_ip"]].append(hit)

    all_ips = list(hits_by_ip.keys())

    # --- Bulk prefetch: FireHol exact matches ---
    firehol_exact_map = defaultdict(list)
    for entry_ip, source in FireHolList.objects.filter(
        ip_address__in=all_ips,
    ).values_list("ip_address", "source"):
        if source:
            firehol_exact_map[entry_ip].append(source)

    # --- Bulk prefetch: FireHol CIDR entries ---
    cidr_entries = []
    for entry in FireHolList.objects.filter(ip_address__contains="/"):
        try:
            cidr_entries.append((ip_network(entry.ip_address, strict=False), entry.source))
        except (ValueError, IndexError):
            continue

    # --- Bulk prefetch: MassScanner IPs ---
    mass_scanner_ips = set(
        MassScanner.objects.filter(
            ip_address__in=all_ips,
        ).values_list("ip_address", flat=True)
    )

    iocs = []
    as_repository = ASRepository()  # single instance for this batch
    for ip, hits in hits_by_ip.items():
        extracted_ip = ip_address(ip)
        if is_non_global_ip(extracted_ip):
            continue

        firehol_categories = get_firehol_categories(ip, extracted_ip, firehol_exact_map, cidr_entries)

        # Single pass over hits to accumulate all derived data
        dest_ports = []
        sensors_map = {}
        timestamps = []
        login_attempts = 0
        for hit in hits:
            if "dest_port" in hit:
                dest_ports.append(hit["dest_port"])
            sensor = hit.get("_sensor")
            if sensor is not None and getattr(sensor, "id", None):
                sensors_map[sensor.id] = sensor
            if "@timestamp" in hit:
                timestamps.append(hit["@timestamp"])
            if hit.get("username") or hit.get("password"):
                login_attempts += 1

        # Sort sensors by ID for consistent processing order
        sensors = sorted(sensors_map.values(), key=lambda s: s.id)

        geoip = next((h.get("geoip") for h in hits if h.get("geoip")), {})
        attacker_country = geoip.get("country_name", "")
        raw_country_code = geoip.get("country_code2", "")
        attacker_country_code = raw_country_code.upper() if len(raw_country_code) == 2 else ""

        asn = geoip.get("asn")
        as_name = geoip.get("as_org", "")
        autonomous_system = as_repository.get_or_create(asn, as_name) if asn else None

        ioc = IOC(
            name=ip,
            type=get_ioc_type(ip),
            interaction_count=len(hits),
            ip_reputation=correct_ip_reputation(ip, next((h.get("ip_rep", "") for h in hits if h.get("ip_rep")), ""), mass_scanner_ips),
            autonomous_system=autonomous_system,
            destination_ports=sorted(set(dest_ports)),
            login_attempts=login_attempts,
            firehol_categories=firehol_categories,
            attacker_country=attacker_country,
            attacker_country_code=attacker_country_code,
        )
        # Attach sensors to temporary attribute for later processing.
        # We cannot use `ioc.sensors.add()` here because the IOC instance is not yet saved
        # to the database, and Django requires an ID for M2M relationships.
        ioc._sensors_to_add = sensors

        if timestamps:
            ioc.first_seen = parse_timestamp(min(timestamps))
            ioc.last_seen = parse_timestamp(max(timestamps))
        iocs.append(ioc)
    return iocs


def threatfox_submission(ioc_record: IOC, related_urls: list, log: Logger) -> None:
    """
    Submit IOC URLs to ThreatFox threat intelligence platform.
    Only submits payload request IOCs with URLs containing paths,
    because they are more reliable than scanners.
    Requires THREATFOX_API_KEY to be configured in settings.

    Args:
        ioc_record: IOC record containing honeypot associations.
        related_urls: List of URLs to potentially submit.
        log: Logger instance for status messages.
    """
    if not ioc_record.payload_request:
        return

    if not settings.THREATFOX_API_KEY:
        log.warning("Threatfox API Key not available")
        return

    urls_to_submit = []
    # submit only URLs with paths to avoid false positives
    for related_url in related_urls:
        parsed_url = urlparse(related_url)
        if parsed_url.path not in ["", "/"]:
            urls_to_submit.append(related_url)
        else:
            log.info(f"skipping export of {related_url} cause has no path")

    if not urls_to_submit:
        log.info("No URLs with paths to submit")
        return

    headers = {"Auth-Key": settings.THREATFOX_API_KEY}
    log.info(f"submitting IOC {urls_to_submit} to Threatfox")

    seen_honeypots = ioc_record._seen_honeypots if hasattr(ioc_record, "_seen_honeypots") else [hp.name for hp in ioc_record.honeypots.all()]

    seen_honeypots_str = ", ".join(seen_honeypots)

    json_data = {
        "query": "submit_ioc",
        "threat_type": "payload_delivery",
        "ioc_type": "url",
        "malware": "unknown",
        "confidence_level": "75",
        "reference": "https://greedybear.honeynet.org",
        "comment": f"Seen requesting a payload from {seen_honeypots_str} honeypot and collected in Greedybear, the Threat Intel Platform for T-POTs.",
        "anonymous": 0,
        "tags": ["honeypot"],
        "iocs": urls_to_submit,
    }
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers=headers,
            json=json_data,
            timeout=5,
        )
    except requests.RequestException:
        log.exception("Threatfox push error")
    else:
        log.info(f"Threatfox submission successful. Received response: {r.text}")
