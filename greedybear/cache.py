import hashlib
from typing import Any

from django.core.cache import caches
from django.core.cache.backends.base import BaseCache


def build_versioned_key(namespace: str, version: int, material: str) -> str:
    """Build a collision-resistant cache key from
    namespace, version and the request-identifying material."""
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{namespace}_v{version}_{digest}"


class Cache:
    """Thin wrapper around a named Django cache backend that adds data versioning."""

    def __init__(self, cache_alias: str) -> None:
        """Bind the wrapper to the cache backend registered under cache_alias."""
        self._cache_alias = cache_alias

    def _get_cache(self) -> BaseCache:
        """Return the dedicated DB-backed cache."""
        return caches[self._cache_alias]

    def get(self, cache_key: str) -> Any:
        """Return the cached value for cache_key, or None when absent."""
        return self._get_cache().get(cache_key)

    def set(self, cache_key: str, value: Any, timeout: int | None = None) -> None:
        """Store value under cache_key, expiring after timeout seconds (None = no expiry)."""
        self._get_cache().set(cache_key, value, timeout=timeout)

    def clear(self) -> None:
        """Clear the cache."""
        self._get_cache().clear()

    def get_data_version(self, version_key: str) -> int:
        """Current data version for version_key (defaults to 1 when unset)."""
        return self._get_cache().get(version_key, 1)

    def bump_data_version(self, version_key: str) -> None:
        """Invalidate every cache entry keyed off version_key by incrementing it."""
        cache = self._get_cache()
        try:
            cache.incr(version_key)
        except ValueError:
            cache.set(version_key, 2, timeout=None)
