# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import Any
from urllib.parse import urlparse

from greedybear.consts import DOMAIN, IP, PAYLOAD_REQUEST, SCANNER


def is_ip_address(string: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).

    Uses the ipaddress module to perform validation. This function properly
    handles both IPv4 addresses and IPv6 addresses.

    Args:
        string: The string to validate as an IP address

    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    try:
        ip_address(string)
    except ValueError:
        return False
    return True


def is_non_global_ip(value) -> bool:
    """
    Return True when an IP should be treated as non-global/unroutable.

    Args:
        value: IPv4Address or IPv6Address from ipaddress module.

    Returns:
        bool: True for loopback/private/multicast/link-local/reserved addresses.
    """
    return value.is_loopback or value.is_private or value.is_multicast or value.is_link_local or value.is_reserved


def is_valid_domain(string: str) -> bool:
    """
    Validate if a string is a safe domain name for use in STIX patterns.

    Rejects empty values and values containing characters that could be used
    for STIX pattern injection (quotes, backslashes, newlines).

    Args:
        string: The string to validate as a domain name

    Returns:
        bool: True if the string is a safe domain value, False otherwise
    """
    if not string:
        return False
    return not any(c in string for c in ("'", '"', "\\", "\n", "\r"))


def is_sha256hash(string: str) -> bool:
    """
    Validate if a string is a valid SHA-256 hash.

    A SHA-256 hash is a string of exactly 64 hexadecimal characters
    (0-9, a-f, A-F). This function checks if the input string matches
    this pattern using a regular expression.

    Args:
        string: The string to validate as a SHA-256 hash

    Returns:
        bool: True if the string is a valid SHA-256 hash, False otherwise
    """
    return bool(re.fullmatch(r"^[A-Fa-f0-9]{64}$", string))


def parse_timestamp(timestamp: str) -> datetime:
    """
    Parse an ISO-format timestamp string into a naive datetime.
    Strips timezone info because the project uses USE_TZ=False.

    Args:
        timestamp: ISO-format timestamp string.

    Returns:
        Naive datetime object.
    """
    return datetime.fromisoformat(timestamp).replace(tzinfo=None)


def is_valid_cidr(candidate: str) -> tuple[bool, str | None]:
    """
    Validate if a string is a valid CIDR notation.

    Args:
        candidate: String to validate as CIDR.

    Returns:
        True if valid CIDR, False otherwise.
    """
    try:
        IPv4Network(candidate.strip(), strict=False)
        return True, candidate.strip()
    except ValueError:
        return False, None


def is_valid_ipv4(candidate: str) -> tuple[bool, str | None]:
    """
    Validate if a string is a valid IPv4 address.

    Args:
        candidate: String to validate as IPv4 address.

    Returns:
        Tuple of (is_valid, cleaned_ip). If valid, cleaned_ip is the stripped
        IP address; otherwise, it is None.
    """
    try:
        IPv4Address(candidate.strip())
        return True, candidate.strip()
    except ValueError:
        return False, None


def get_ioc_type(ioc: str) -> str:
    """
    Determine the type of an IOC based on its format.

    Args:
        ioc: IOC name string (IP address or domain).

    Returns:
        IP if the value is a valid IPv4 address, DOMAIN otherwise.
    """
    is_valid, _ = is_valid_ipv4(ioc)
    return IP if is_valid else DOMAIN


def get_attack_type(ip_hits: list[dict]) -> str:
    """
    Determines the attack type based on the raw hits for a specific IP.

    An IOC that has triggered at least one hit containing a valid
    payload download URL is classified as a PAYLOAD_REQUEST attacker.
    Everything else is classified as a SCANNER.
    """
    for hit in ip_hits:
        url = hit.get("_related_url")
        # Ensure the hit has a URL and that it passes our path validation rules
        if url and is_valid_url(url):
            return PAYLOAD_REQUEST

    return SCANNER


def is_valid_url(url: str | None) -> bool:
    allowed_schemes = {"http", "https"}
    try:
        parsed = urlparse(url)

        if parsed.scheme not in allowed_schemes:
            return False

        if not parsed.netloc:
            return False

        if parsed.netloc.strip() == "":
            return False

        return bool(parsed.path and parsed.path.strip("/") != "")

    except Exception:
        return False


def get_nested_value(d: dict, *keys: str) -> Any | None:
    """
    Traverse a nested dictionary along a path of keys without raising.
    Failed traversals yield None instead of an error.

    Args:
        d: Dict to traverse.
        *keys: Key path to follow, e.g. "connection", "protocol".

    Returns:
        Value at the end of the key path, or None if the path is empty,
        a key is missing, or an intermediate value is not a dict.
    """
    if not keys:
        return None
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
