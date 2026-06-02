# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import logging
from abc import ABCMeta

from certego_saas.apps.auth.backend import CookieTokenAuthentication  # ty:ignore[unresolved-import]
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.contrib.postgres.aggregates import ArrayAgg
from django.core import signing
from django.db.models import Count, F, Q, Value
from django.db.models.functions import JSONObject
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from api.filters import FeedsFilterSet
from api.serializers import AdvancedFeedRequestSerializer, ASNFeedOrderingSerializer, SimpleFeedRequestSerializer
from api.throttles import FeedsAdvancedThrottle, FeedsThrottle, SharedFeedRateThrottle
from api.views.utils import (
    asn_aggregated_queryset,
    feeds_response,
    save_request_source,
)
from greedybear.models import IOC, ShareToken

logger = logging.getLogger(__name__)

ALLOWED_UNAUTHENTICATED_QUERY_PARAMS = [
    "feed_type",
    "attack_type",
    "ioc_type",
    "ordering",
    "include_mass_scanners",
    "include_tor_exit_nodes",
    "prioritize",
]

_TOKEN_LIST_FIELDS = (
    "token_hash",
    "reason",
    "created_at",
    "revoked",
    "revoked_at",
)


class BaseFeedView(APIView, metaclass=ABCMeta):
    """Shared GET flow: validate request params via ``serializer_class``, build
    the IOC queryset, and render with ``feeds_response`` (paginating when asked).

    Subclasses are typically attribute-only. They set ``serializer_class`` (and
    the usual DRF class attributes: ``throttle_classes``,
    ``authentication_classes``, ``permission_classes``) plus the feed-specific
    toggles below, and may override ``get_request_data`` to merge path
    parameters or token-derived data into the serializer input.
    """

    throttle_classes = [FeedsThrottle]
    serializer_class = None
    pagination_class = None
    include_sensors = False
    include_credential_count = False
    # ASN feed disables slicing + model-level ordering (needs all rows to aggregate).
    is_aggregated = False
    # validated request params, set by get() before get_queryset() runs.
    feed_params = None

    def get_request_data(self, request, **kwargs):
        """Raw input mapping handed to the serializer. Defaults to the query
        params; override to merge path parameters or token data."""
        return request.query_params.dict()

    def validate_request(self, request, **kwargs):
        serializer = self.serializer_class(data=self.get_request_data(request, **kwargs))
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def should_paginate(self, request_data):
        """Whether to paginate this response. Requires a ``pagination_class`` and,
        by default, the validated ``paginate`` flag. Override to always paginate."""
        return self.pagination_class is not None and request_data.get("paginate", False)

    def get_queryset(self):
        """Build the IOC queryset from the validated params (``self.feed_params``)
        and ``self.request``. Replaces the module-level
        ``api.views.utils.get_queryset`` (API_refactor.md 2.2).

        Field → ORM filtering is delegated to ``FeedsFilterSet`` (2.3); this
        method owns what isn't a plain field lookup.
        """
        iocs = IOC.objects.annotate(value=F("name"))
        iocs = FeedsFilterSet(self.feed_params, queryset=iocs, request=self.request).qs

        # exclude specific reputations
        iocs = iocs.exclude(ip_reputation__in=self.feed_params.get("exclude_reputation", [])).distinct()

        # apply feed type filter
        if "all" not in self.feed_params["feed_type"]:
            type_filter = Q()
            for ft in self.feed_params["feed_type"]:
                type_filter |= Q(honeypots__name__iexact=ft)
            iocs = iocs.filter(type_filter)

        if self.is_aggregated:
            return iocs

        iocs = iocs.filter(honeypots__active=True)
        iocs = iocs.annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
        # Only annotate tags metadata when the response format needs it (e.g. JSON),
        # to avoid unnecessary joins and aggregation work for txt/csv feeds.
        if self.feed_params["format"] == "json":
            iocs = iocs.annotate(
                tags_json=ArrayAgg(
                    JSONObject(key=F("tags__key"), value=F("tags__value"), source=F("tags__source")),
                    filter=Q(tags__isnull=False),
                    default=Value([]),
                    distinct=True,
                )
            )
        return iocs

    def sort_and_slice_queryset(self, qs):
        if self.is_aggregated:
            return qs
        return qs.order_by(self.feed_params["ordering"])[: self.feed_params["feed_size"]]

    def get(self, request, *args, **kwargs):
        self.feed_params = self.validate_request(request, **kwargs)
        iocs_queryset = self.get_queryset()
        iocs_queryset = self.sort_and_slice_queryset(iocs_queryset)
        save_request_source(request)
        verbose = self.feed_params.get("verbose", False)
        if self.should_paginate(self.feed_params):
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(iocs_queryset, request)
            resp_data = feeds_response(request, page, self.feed_params["format"], dict_only=True, verbose=verbose, include_sensors=self.include_sensors)
            return paginator.get_paginated_response(resp_data)
        return feeds_response(request, iocs_queryset, self.feed_params["format"], verbose=verbose, include_sensors=self.include_sensors)


class SimpleFeedView(BaseFeedView):
    """Public feed endpoint with path parameters:
    ``feeds/<feed_type>/<attack_type>/<prioritize>.<format_>``."""

    throttle_classes = [FeedsThrottle]
    serializer_class = SimpleFeedRequestSerializer
    pagination_class = None

    def get_request_data(self, request, **kwargs):
        return request.query_params.dict() | {
            "feed_type": kwargs["feed_type"],
            "attack_type": kwargs["attack_type"],
            "prioritize": kwargs["prioritize"],
            "format": kwargs["format_"],
        }


class PaginatedFeedView(BaseFeedView):
    """Public paginated feed endpoint (query params only). Forces JSON output."""

    throttle_classes = [FeedsThrottle]
    serializer_class = SimpleFeedRequestSerializer
    pagination_class = CustomPageNumberPagination

    def should_paginate(self, request_data):
        # this endpoint always paginates
        return True

    def get_request_data(self, request, **kwargs):
        # pagination requires JSON response
        return request.query_params.dict() | {"format": "json"}


class AdvancedFeedView(BaseFeedView):
    """Authenticated advanced feed endpoint with full filtering and optional pagination."""

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]
    serializer_class = AdvancedFeedRequestSerializer
    pagination_class = CustomPageNumberPagination
    include_sensors = True

    def get_queryset(self):
        iocs = super().get_queryset()

        # annotate and filter credential count
        iocs = iocs.annotate(credential_count=Count("credentials", distinct=True))
        if "min_credential_count" in self.feed_params:
            iocs = iocs.filter(credential_count__gte=self.feed_params["min_credential_count"])
        if "max_credential_count" in self.feed_params:
            iocs = iocs.filter(credential_count__lte=self.feed_params["max_credential_count"])

        if self.is_aggregated:
            return iocs

        if self.feed_params["format"] == "json":
            iocs = iocs.annotate(
                sensors_json=ArrayAgg(
                    JSONObject(address=F("sensors__address"), label=F("sensors__label")),
                    filter=Q(sensors__isnull=False),
                    default=Value([]),
                    distinct=True,
                )
            )

        return iocs


class AsnFeedView(BaseFeedView):
    """Authenticated feed endpoint aggregated by ASN. Uses its own render path."""

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]
    serializer_class = ASNFeedOrderingSerializer
    pagination_class = None
    is_aggregated = True

    def get(self, request, *args, **kwargs):
        self.feed_params = self.validate_request(request, **kwargs)
        iocs_qs = self.get_queryset()
        asn_aggregates = asn_aggregated_queryset(iocs_qs, request, self.feed_params)
        return Response(list(asn_aggregates))


class TokenError(Exception):
    """Raised when a share token is missing, revoked, or has an invalid signature.

    Caught by ``ConsumeFeedView.get`` to produce the ``{"error": <message>}`` 400
    response shape the share/consume API contract expects (matching the sibling
    ``ShareTokenViewSet.revoke``); a plain DRF ``ValidationError`` would instead
    render as ``{"errors": [...]}``.
    """


class ConsumeFeedView(BaseFeedView):
    """Public, rate-limited endpoint that consumes a signed share token.

    The token replaces the query string: ``get_request_data`` decodes it into
    the serializer input, so the shared base flow renders it like any feed.
    """

    authentication_classes = []
    permission_classes = []
    throttle_classes = [SharedFeedRateThrottle]
    serializer_class = AdvancedFeedRequestSerializer

    def get_request_data(self, request, **kwargs):
        token = kwargs["token"]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            share_token = ShareToken.objects.get(token_hash=token_hash)
        except ShareToken.DoesNotExist as exc:
            raise TokenError("Invalid or expired token") from exc
        if share_token.revoked:
            raise TokenError("Token has been revoked")
        try:
            return signing.loads(token, salt="greedybear-feeds", max_age=86400 * 30)  # 30 days validity
        except signing.BadSignature as exc:
            raise TokenError("Invalid or expired token") from exc

    def get(self, request, *args, **kwargs):
        try:
            return super().get(request, *args, **kwargs)
        except TokenError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class ShareTokenViewSet(ViewSet):
    """Create, list and revoke shareable feed tokens.

    Share/revoke are intentionally GET-able so the links can be opened directly
    in a browser. ``share`` stores the raw query params in the signed token so
    ``FeedsConsumeView`` can replay them through ``AdvancedFeedRequestSerializer``.
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def share(self, request):
        safe_params = {k: v for k, v in request.query_params.items() if k != "reason"}
        logger.info(f"request /api/feeds/share with params: {safe_params}")
        data = request.query_params.dict()
        data.pop("reason", None)
        reason = request.query_params.get("reason", "").strip()[:256]

        token = signing.dumps(data, salt="greedybear-feeds")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        ShareToken.objects.get_or_create(
            token_hash=token_hash,
            defaults={"user": request.user, "reason": reason},
        )
        host = request.build_absolute_uri("/")
        return Response(
            {
                "url": f"{host}api/feeds/consume/{token}",
                "revoke_url": f"{host}api/feeds/revoke/{token}",
            }
        )

    def revoke(self, request, token):
        logger.info("request /api/feeds/revoke")
        try:
            signing.loads(token, salt="greedybear-feeds", max_age=86400 * 30)
        except signing.BadSignature:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            share_token = ShareToken.objects.get(token_hash=token_hash)
        except ShareToken.DoesNotExist:
            return Response({"error": "Token not found. Only the creator can revoke a token."}, status=status.HTTP_403_FORBIDDEN)

        if share_token.user != request.user and not request.user.is_staff:
            return Response({"error": "You do not have permission to revoke this token."}, status=status.HTTP_403_FORBIDDEN)

        if share_token.revoked:
            return Response({"detail": "Token was already revoked."}, status=status.HTTP_200_OK)
        share_token.revoked = True
        share_token.revoked_at = timezone.now()
        share_token.save(update_fields=["revoked", "revoked_at"])
        return Response({"detail": "Token revoked successfully."}, status=status.HTTP_200_OK)

    def list_tokens(self, request):
        logger.info("request /api/feeds/tokens/")
        tokens = ShareToken.objects.filter(user=request.user).order_by("-created_at").values(*_TOKEN_LIST_FIELDS)
        results = [
            {
                "hash_prefix": t["token_hash"][:12],
                "reason": t["reason"],
                "created_at": t["created_at"],
                "revoked": t["revoked"],
                "revoked_at": t["revoked_at"],
            }
            for t in tokens
        ]
        return Response(results)
