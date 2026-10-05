import logging
from collections.abc import Iterator, MutableMapping
from datetime import datetime
from typing import Any

from greedybear.utils import parse_timestamp

log = logging.getLogger(__name__)


class InvalidHitError(Exception):
    """Raised when a hit lacks a field it cannot be processed without."""


class Hit(MutableMapping):
    """
    Dict-like view over a single Elasticsearch hit with typed accessors.

    Hits come from honeypot logs, so every field is attacker influenced and any
    of them may be missing: the search runs with a `_source` filter, which omits
    fields the document does not have rather than returning them as null.

    The accessors split that into two cases. `require*` is for fields a hit is
    useless without and raises InvalidHitError so the caller can drop just that hit.
    `get_*` is for optional fields and falls back to a default instead.

    Mapping access is kept so a wrapped hit can be passed to code that still
    treats hits as plain dicts.
    """

    def __init__(self, data: dict):
        """
        Wrap a hit dictionary.

        Args:
            data: The hit as returned by ElasticRepository, already converted
                with `to_dict()`.
        """
        self._data = data

    @classmethod
    def wrap(cls, hit) -> "Hit":
        """
        Return a hit as a Hit, leaving one that already is alone.

        Hits reach the extraction helpers from two places: the pipeline, which
        wraps them, and the event collector in process_event, which builds plain
        dicts. Wrapping on the way in lets both use the typed accessors without
        the callers having to agree on a type.

        Args:
            hit: A Hit or a plain hit dictionary.

        Returns:
            The hit as a Hit.
        """
        return hit if isinstance(hit, cls) else cls(hit)

    # --- mapping protocol -------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        del self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"Hit({self._data!r})"

    # --- required fields --------------------------------------------------

    def require(self, key: str) -> Any:
        """
        Return a field the hit cannot be processed without.

        A field is treated as missing when the key is absent, the value is None,
        or the value is a string that is empty once stripped.

        Args:
            key: Name of the field.

        Returns:
            The raw value.

        Raises:
            InvalidHitError: If the field is missing or blank.
        """
        value = self._data.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise InvalidHitError(f"hit is missing required field '{key}'")
        return value

    def require_str(self, key: str) -> str:
        """
        Return a required field as a stripped string.

        Args:
            key: Name of the field.

        Returns:
            The value as a stripped string.

        Raises:
            InvalidHitError: If the field is missing or blank.
        """
        return str(self.require(key)).strip()

    def require_time(self, key: str) -> datetime:
        """
        Return a required timestamp field as a datetime.

        Args:
            key: Name of the field.

        Returns:
            The parsed naive datetime.

        Raises:
            InvalidHitError: If the field is missing, blank, or not a valid timestamp.
        """
        value = self.require(key)
        try:
            return parse_timestamp(value)
        except (TypeError, ValueError) as exc:
            raise InvalidHitError(f"hit has an unparsable '{key}': {value!r}") from exc

    # --- optional fields --------------------------------------------------

    def get_str(self, key: str, default: str = "") -> str:
        """
        Return an optional field as a stripped string.

        Args:
            key: Name of the field.
            default: Value to return when the field is missing or blank.

        Returns:
            The value as a stripped string, or the default.
        """
        value = self._data.get(key)
        if value is None:
            return default
        text = str(value).strip()
        return text or default

    def get_int(self, key: str, default: int | None = None) -> int | None:
        """
        Return an optional field as an int.

        Args:
            key: Name of the field.
            default: Value to return when the field is missing or not numeric.

        Returns:
            The value as an int, or the default.
        """
        value = self._data.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            log.debug(f"field '{key}' is not an int: {value!r}")
            return default

    def get_float(self, key: str, default: float | None = None) -> float | None:
        """
        Return an optional field as a float.

        Kept separate from get_int because truncating a duration to a whole
        second would silently lose data rather than fall back to the default.

        Args:
            key: Name of the field.
            default: Value to return when the field is missing or not numeric.

        Returns:
            The value as a float, or the default.
        """
        value = self._data.get(key)
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            log.debug(f"field '{key}' is not a float: {value!r}")
            return default

    def get_time(self, key: str, default: datetime | None = None) -> datetime | None:
        """
        Return an optional timestamp field as a datetime.

        Args:
            key: Name of the field.
            default: Value to return when the field is missing or unparsable.

        Returns:
            The parsed naive datetime, or the default.
        """
        value = self._data.get(key)
        if value is None:
            return default
        try:
            return parse_timestamp(value)
        except (TypeError, ValueError):
            log.debug(f"field '{key}' is not a timestamp: {value!r}")
            return default

    def get_dict(self, key: str) -> dict:
        """
        Return an optional field as a dict.

        Nested objects such as `geoip` are read with `.get()` chains, which break
        when the field is present but not an object.

        Args:
            key: Name of the field.

        Returns:
            The value when it is a dict, otherwise an empty dict.
        """
        value = self._data.get(key)
        return value if isinstance(value, dict) else {}
