from rest_framework import serializers

from greedybear.models import Honeypot


class PresenceFlagField(serializers.BooleanField):
    """BooleanField for presence-flag query params.
    Makes sure that a valueless query param such as include_mass_scanners
    is treated as truthy.
    """

    TRUE_VALUES = serializers.BooleanField.TRUE_VALUES | {""}


def feed_type_as_list(feed_type_str: str) -> list:
    """Split a comma-separated feed type string into a stripped list of individual feed types.

    Args:
        feed_type_str (str): Comma-separated feed type string (e.g. "cowrie,adbhoney").

    Returns:
        list[str]: List of non-empty, stripped feed type tokens.
    """
    return [ft.strip() for ft in feed_type_str.split(",") if ft.strip()]


def get_valid_feed_types() -> frozenset[str]:
    """
    Retrieve all valid feed types, combining predefined types with active general honeypot names.

    Returns:
        frozenset[str]: An immutable set of valid feed type strings
    """
    honeypots = Honeypot.objects.filter(active=True)
    feed_types = ["all"] + [hp.name.lower() for hp in honeypots]
    return frozenset(feed_types)
