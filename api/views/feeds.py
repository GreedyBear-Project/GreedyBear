# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication  # ty:ignore[unresolved-import]
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.contrib.postgres.aggregates import ArrayAgg
from django.core import signing
from django.db.models import Count, F, Q, QuerySet, Value
from django.db.models.functions import JSONObject
from django.http import HttpResponseBase
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from api.filters import FeedsFilterSet
from api.renderers import FeedCSVRenderer, FeedJSONRenderer, FeedTextRenderer, Stix21Renderer
from api.serializers import AdvancedFeedRequestSerializer, ASNFeedOrderingSerializer, SimpleFeedRequestSerializer
from api.throttles import FeedsAdvancedThrottle, FeedsThrottle, SharedFeedRateThrottle
from api.views.utils import (
    aggregate_iocs_by_asn,
    build_feed_dict,
    save_request_source,
)
from greedybear.models import IOC, ShareToken

logger = logging.getLogger(__name__)

RENDERERS_BY_FORMAT = {
    "json": FeedJSONRenderer,
    "txt": FeedTextRenderer,
    "csv": FeedCSVRenderer,
    "stix21": Stix21Renderer,
}

TOKEN_LIST_FIELDS = (
    "token_hash",
    "reason",
    "created_at",
    "revoked",
    "revoked_at",
)


class BaseFeedView(APIView):
    """Shared GET flow:
    validate request params, build the IOC queryset and render (paginating when asked).

    Subclasses represent the actual endpoints and are typically attribute-only.
    They set the usual DRF class attributes and the feed-specific toggles
    overriding the defaults below.
    """

    # ACCESS CONTROL
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [AllowAny]
    throttle_classes = [FeedsThrottle]
    renderer_classes = [FeedJSONRenderer, FeedTextRenderer, FeedCSVRenderer, Stix21Renderer]

    # REQUEST HANDLING
    serializer_class = None
    pagination_class = None

    # QUERYSET SHAPE
    include_sensors = False
    is_aggregated = False

    # VALIDATED REQUEST PARAMETERS - populated in get()
    request_params = None

    # OUTPUT SHAPE - set dynamically, depending on the requested format
    build_feed_envelope = False

    def get_request_data(self, request, **kwargs) -> dict:
        """Raw input mapping handed to the serializer.
        Defaults to the query params.
        Override to merge path parameters or token data."""
        return request.query_params.dict()

    def validate_request(self, request: Request, **kwargs) -> dict:
        """Run the request data through a serializer and return the validated params,
        raising ValidationError (HTTP 400) on bad input."""
        serializer = self.serializer_class(data=self.get_request_data(request, **kwargs))
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def should_paginate(self, request_data: dict) -> bool:
        """Whether to paginate this response.
        Requires a pagination_class and the validated paginate flag."""
        return self.pagination_class is not None and request_data.get("paginate", False)

    def get_renderer_context(self) -> dict:
        """Publish the render-time flags the feed renderers need, so they read
        explicit context keys instead of reaching into view internals."""
        context = super().get_renderer_context()
        context["verbose"] = (self.request_params or {}).get("verbose", False)
        context["include_sensors"] = self.include_sensors
        context["build_feed_envelope"] = self.build_feed_envelope
        return context

    def get_queryset(self) -> QuerySet:
        """Build the IOC queryset from the validated request parameters."""
        iocs = IOC.objects.annotate(value=F("name"))
        iocs = FeedsFilterSet(self.request_params, queryset=iocs, request=self.request).qs

        iocs = iocs.exclude(ip_reputation__in=self.request_params.get("exclude_reputation", [])).distinct()

        if "all" not in self.request_params["feed_type"]:
            type_filter = Q()
            for ft in self.request_params["feed_type"]:
                type_filter |= Q(honeypots__name__iexact=ft)
            iocs = iocs.filter(type_filter)

        if self.is_aggregated:
            return iocs

        iocs = iocs.filter(honeypots__active=True)
        iocs = iocs.annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
        if self.request_params["format"] == "json":
            iocs = iocs.annotate(
                tags_json=ArrayAgg(
                    JSONObject(key=F("tags__key"), value=F("tags__value"), source=F("tags__source")),
                    filter=Q(tags__isnull=False),
                    default=Value([]),
                    distinct=True,
                )
            )
        return iocs

    def sort_and_slice_queryset(self, qs: QuerySet) -> QuerySet:
        """Apply the requested ordering and cap the result at feed_size.
        Aggregated views are returned untouched."""
        if self.is_aggregated:
            return qs
        return qs.order_by(self.request_params["ordering"])[: self.request_params["feed_size"]]

    def render_response(self, request: Request, iocs_queryset: QuerySet) -> HttpResponseBase:
        """Select the renderer for the validated format and hand it the prepared data."""
        if self.should_paginate(self.request_params):
            verbose = self.request_params.get("verbose", False)
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(iocs_queryset, request)
            resp_data = build_feed_dict(page, verbose=verbose, include_sensors=self.include_sensors)
            request.accepted_renderer = FeedJSONRenderer()
            request.accepted_media_type = FeedJSONRenderer.media_type
            return paginator.get_paginated_response(resp_data)

        # Hand the raw queryset to the renderer and flag it for envelope shaping.
        # Set only here so error/exception responses (which bypass render_response)
        # and the pre-built paginated/ASN payloads are left as plain JSON.
        renderer = RENDERERS_BY_FORMAT[self.request_params["format"]]()
        request.accepted_renderer = renderer
        request.accepted_media_type = renderer.media_type
        self.build_feed_envelope = True
        return Response(iocs_queryset)

    def get(self, request: Request, *args, **kwargs) -> HttpResponseBase:
        """Validate the request, build and sort the IOC queryset,
        render it in the requested format, and optionally paginate."""
        self.request_params = self.validate_request(request, **kwargs)
        iocs_queryset = self.get_queryset()
        iocs_queryset = self.sort_and_slice_queryset(iocs_queryset)
        save_request_source(request)
        return self.render_response(request, iocs_queryset)


class SimpleFeedView(BaseFeedView):
    """Public feed endpoint with path parameters:
    /feeds/<feed_type>/<attack_type>/<prioritize>.<format_>"""

    serializer_class = SimpleFeedRequestSerializer

    def get_request_data(self, request: Request, **kwargs) -> dict:
        return request.query_params.dict() | {
            "feed_type": kwargs["feed_type"],
            "attack_type": kwargs["attack_type"],
            "prioritize": kwargs["prioritize"],
            "format": kwargs["format_"],
        }


class PaginatedFeedView(BaseFeedView):
    """Public paginated feed endpoint (query params only). Forces JSON output."""

    serializer_class = SimpleFeedRequestSerializer
    pagination_class = CustomPageNumberPagination

    def should_paginate(self, request_data: dict) -> bool:
        """This endpoint always paginates."""
        return True

    def get_request_data(self, request: Request, **kwargs) -> dict:
        """Pagination requires JSON response."""
        return request.query_params.dict() | {"format": "json"}


class AdvancedFeedView(BaseFeedView):
    """Authenticated advanced feed endpoint with full filtering and optional pagination."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]
    serializer_class = AdvancedFeedRequestSerializer
    pagination_class = CustomPageNumberPagination
    include_sensors = True

    def get_queryset(self) -> QuerySet:
        """Overrides base class to include credential count
        and sensor information."""
        iocs = super().get_queryset()

        iocs = iocs.annotate(credential_count=Count("credentials", distinct=True))
        if "min_credential_count" in self.request_params:
            iocs = iocs.filter(credential_count__gte=self.request_params["min_credential_count"])
        if "max_credential_count" in self.request_params:
            iocs = iocs.filter(credential_count__lte=self.request_params["max_credential_count"])

        if self.is_aggregated:
            return iocs

        if self.request_params["format"] == "json":
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
    """Authenticated feed endpoint aggregated by ASN.

    Reuses the shared base flow (validation, queryset building, statistics
    recording) and only swaps the render step for the ASN aggregation.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]
    serializer_class = ASNFeedOrderingSerializer
    is_aggregated = True

    def get_queryset(self) -> QuerySet:
        """Filter the base IOC queryset by the validated ASN, when provided."""
        iocs = super().get_queryset()
        asn = self.request_params.get("asn")
        if asn:
            iocs = iocs.filter(autonomous_system__asn=asn)
        return iocs

    def render_response(self, request: Request, iocs_queryset: QuerySet) -> Response:
        return Response(aggregate_iocs_by_asn(iocs_queryset, self.request_params["ordering"]))


class TokenError(Exception):
    """Raised when a share token is missing, revoked, or has an invalid signature.

    Caught by ``ConsumeFeedView.get`` to produce the ``{"error": <message>}`` 400
    response shape the share/consume API contract expects (matching the sibling
    ``ShareTokenViewSet.revoke``); a plain DRF ``ValidationError`` would instead
    render as ``{"errors": [...]}``.
    """


class ConsumeFeedView(BaseFeedView):
    """Public, rate-limited endpoint that consumes a signed share token.

    The token replaces the query string: get_request_data decodes it into
    the serializer input, so the shared base flow renders it like any feed.
    """

    authentication_classes = []
    throttle_classes = [SharedFeedRateThrottle]
    serializer_class = AdvancedFeedRequestSerializer

    def get_request_data(self, request: Request, **kwargs) -> dict:
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

    def get(self, request: Request, *args, **kwargs) -> HttpResponseBase:
        try:
            return super().get(request, *args, **kwargs)
        except TokenError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class ShareTokenViewSet(ViewSet):
    """Create, list and revoke shareable feed tokens.

    Share/revoke are intentionally GET-able so the links can be opened directly
    in a browser. Share stores the raw query params in the signed token so
    FeedsConsumeView can replay them through AdvancedFeedRequestSerializer.
    """

    permission_classes = [IsAuthenticated]

    def share(self, request: Request) -> Response:
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

    def revoke(self, request: Request, token: str) -> Response:
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

    def list_tokens(self, request: Request) -> Response:
        logger.info("request /api/feeds/tokens/")
        tokens = ShareToken.objects.filter(user=request.user).order_by("-created_at").values(*TOKEN_LIST_FIELDS)
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
