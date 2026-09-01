import logging
import urllib.parse
from functools import cached_property

from django.http import HttpResponse
from rest_framework.request import Request
from rest_framework.response import Response

from greedybear.cache import Cache, build_versioned_key
from greedybear.consts import API_CACHE_ALIAS, API_CACHE_TIMEOUT_SECONDS, IOC_DATA_VERSION_KEY

logger = logging.getLogger(__name__)


class CachedResponseMixin:
    """Adds versioned response caching to an APIView.
    Subclasses opt in by setting cache_namespace."""

    cache = Cache(API_CACHE_ALIAS)
    cache_namespace: str | None = None
    cache_version_key: str = IOC_DATA_VERSION_KEY
    cache_timeout: int = API_CACHE_TIMEOUT_SECONDS

    @cached_property
    def cache_key(self) -> str | None:
        """Versioned cache key for this request, or None when caching is disabled.
        Computed once on first access (during the read)
        and memoized on the per-request view instance."""
        if not self._cache_enabled():
            return None
        version = self.cache.get_data_version(self.cache_version_key)
        sorted_params = sorted(self.request.query_params.lists())
        params_string = urllib.parse.urlencode(sorted_params, doseq=True)
        key_material = f"{self.__class__.__name__}|{self.request.path}|{params_string}"
        return build_versioned_key(self.cache_namespace, version, key_material)

    def get_cached_response(self) -> HttpResponse | None:
        """Return a hit, or None when caching is disabled or on a miss."""
        if self.cache_key is None:
            return None
        cached = self.cache.get(self.cache_key)
        if cached is None:
            return None
        return HttpResponse(cached["content"], content_type=cached["content_type"], status=cached["status"])

    def finalize_response(self, request, response, *args, **kwargs):
        """Cache the rendered response under the key captured during the read.
        Runs after DRF has attached the renderer to the response."""
        response = super().finalize_response(request, response, *args, **kwargs)
        self._store_api_response(response)
        return response

    def _cache_enabled(self) -> bool:
        """Determines if cache was enabled
        by checking if cache_namespace is set."""
        return self.cache_namespace is not None

    def _store_api_response(self, response: Response) -> bool:
        """Store a successful (200) and rendered DRF Response under cache_key."""
        if self.cache_key is None:
            return False
        if not isinstance(response, Response):
            return False
        if response.status_code != 200:
            return False
        if not response.is_rendered:
            response.render()
        self.cache.set(
            self.cache_key,
            {
                "content": response.rendered_content,
                "content_type": response["content-type"],
                "status": response.status_code,
            },
            timeout=self.cache_timeout,
        )
        return True


class RequestLoggingMixin:
    """Emit a access-log line per request for any APIView/ViewSet it is mixed into."""

    EXCLUDED_LOG_PARAMS = frozenset({"reason"})

    def initial(self, request: Request, *args, **kwargs):
        route = getattr(getattr(request, "resolver_match", None), "route", None) or request.path.lstrip("/")
        params = {k: v for k, v in request.query_params.items() if k not in self.EXCLUDED_LOG_PARAMS}
        logger.info(f"request {request.method} /{route} params: {params}")
        super().initial(request, *args, **kwargs)
