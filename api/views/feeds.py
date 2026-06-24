# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
from datetime import timedelta

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.contrib.postgres.aggregates import ArrayAgg
from django.core import signing
from django.db.models import Count, F, Q, QuerySet, Value
from django.db.models.functions import JSONObject
from django.http import HttpResponseBase
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet

from api.filters import FeedsFilterSet
from api.mixins import CachedResponseMixin, RequestLoggingMixin
from api.renderers import FeedCSVRenderer, FeedJSONRenderer, FeedTextRenderer, Stix21Renderer
from api.serializers import (
    AdvancedFeedEnvelopeSerializer,
    AdvancedFeedRequestSerializer,
    ASNFeedRequestSerializer,
    ASNFeedSerializer,
    PaginatedSimpleFeedSerializer,
    ShareFeedRequestSerializer,
    ShareTokenListItemSerializer,
    ShareTokenResponseSerializer,
    SimpleFeedEnvelopeSerializer,
    SimpleFeedRequestSerializer,
    TokenConsumeRequestSerializer,
    TokenRequestSerializer,
    TrendingFeedRequestSerializer,
    TrendingFeedResponseSerializer,
)
from api.throttles import FeedsAdvancedThrottle, FeedsThrottle, SharedFeedRateThrottle
from api.views.utils import (
    aggregate_iocs_by_asn,
    build_feed_dict,
    save_request_source,
)
from greedybear.consts import SHARE_TOKEN_SALT, TRENDING_FEEDS_DATA_VERSION_KEY
from greedybear.cronjobs.repositories import TrendingBucketRepository
from greedybear.cronjobs.trending import build_ranked_attackers
from greedybear.models import IOC, ShareToken

RENDERERS_BY_FORMAT = {
    "json": FeedJSONRenderer,
    "txt": FeedTextRenderer,
    "csv": FeedCSVRenderer,
    "stix21": Stix21Renderer,
}

RESPONSES = {
    400: OpenApiResponse(description="Invalid feed parameters."),
    401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
    429: OpenApiResponse(description="Rate limit exceeded."),
}

PAGE_PARAMETER = OpenApiParameter(
    "page",
    OpenApiTypes.INT,
    OpenApiParameter.QUERY,
    description="1-based page number. Only meaningful when the response is paginated.",
)


class BaseFeedView(RequestLoggingMixin, CachedResponseMixin, APIView):
    """Shared GET flow:
    validate request params, build the IOC queryset and render (paginating when asked).

    Subclasses represent the actual endpoints and are typically attribute-only.
    They set the usual DRF class attributes and the feed-specific toggles
    overriding the defaults below.

    Responses are cached via CachedResponseMixin
    The extraction pipeline invalidates them on every run.
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

    # RESPONSE CACHING - do not override in subclasses
    cache_namespace = "feeds"

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
        save_request_source(request)
        cached_response = self.get_cached_response()
        if cached_response is not None:
            return cached_response
        iocs_queryset = self.get_queryset()
        iocs_queryset = self.sort_and_slice_queryset(iocs_queryset)
        return self.render_response(request, iocs_queryset)


@extend_schema_view(
    get=extend_schema(
        tags=["Feeds"],
        summary="Public feed (path-parameter form)",
        description="Public threat feed addressed through the URL path.",
        auth=[],
        parameters=[
            SimpleFeedRequestSerializer,
            # drop the URL path params the serializer would otherwise generate
            OpenApiParameter("feed_type", exclude=True),
            OpenApiParameter("attack_type", exclude=True),
            OpenApiParameter("prioritize", exclude=True),
            OpenApiParameter("format", exclude=True),
        ],
        responses={
            200: SimpleFeedEnvelopeSerializer,
            400: RESPONSES[400],
            429: RESPONSES[429],
        },
    )
)
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


@extend_schema_view(
    get=extend_schema(
        tags=["Feeds"],
        summary="Public paginated feed",
        description="Public query-parameter feed, always paginated and always JSON.",
        # Public endpoint: suppress the optional token scheme so it renders without a lock.
        auth=[],
        parameters=[SimpleFeedRequestSerializer, PAGE_PARAMETER],
        responses={
            200: PaginatedSimpleFeedSerializer,
            400: RESPONSES[400],
            429: RESPONSES[429],
        },
    )
)
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


@extend_schema_view(
    get=extend_schema(
        tags=["Feeds"],
        summary="Authenticated advanced feed",
        description=("Authenticated feed with the full set of filtering, scoring and credential parameters and optional pagination."),
        parameters=[AdvancedFeedRequestSerializer, PAGE_PARAMETER],
        responses={
            200: AdvancedFeedEnvelopeSerializer,
            400: RESPONSES[400],
            401: RESPONSES[401],
            429: RESPONSES[429],
        },
    )
)
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


@extend_schema_view(
    get=extend_schema(
        tags=["Feeds"],
        summary="Authenticated feed aggregated by ASN",
        description=(
            "Authenticated feed that aggregates the filtered IOCs into per-ASN metric rows. "
            "Accepts the same filters as the advanced feed, but `ordering` is restricted to the aggregate fields."
        ),
        parameters=[ASNFeedRequestSerializer],
        responses={
            200: ASNFeedSerializer(many=True),
            400: RESPONSES[400],
            401: RESPONSES[401],
            429: RESPONSES[429],
        },
    )
)
class AsnFeedView(BaseFeedView):
    """Authenticated feed endpoint aggregated by ASN.

    Reuses the shared base flow (validation, queryset building, statistics
    recording) and only swaps the render step for the ASN aggregation.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]
    serializer_class = ASNFeedRequestSerializer
    is_aggregated = True

    def render_response(self, request: Request, iocs_queryset: QuerySet) -> Response:
        rows = aggregate_iocs_by_asn(iocs_queryset, self.request_params["ordering"])
        return Response(ASNFeedSerializer(rows, many=True).data)


@extend_schema_view(
    get=extend_schema(
        tags=["Feeds"],
        summary="Public trending feed",
        description=("Public endpoint that compares two consecutive completed windows of attacker activity and returns the top-ranked trending attackers."),
        auth=[],
        parameters=[TrendingFeedRequestSerializer],
        responses={
            200: TrendingFeedResponseSerializer,
            400: RESPONSES[400],
            429: RESPONSES[429],
        },
    )
)
class TrendingFeedView(RequestLoggingMixin, CachedResponseMixin, APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [FeedsThrottle]
    cache_namespace = "trending_feeds"
    cache_version_key = TRENDING_FEEDS_DATA_VERSION_KEY

    def get(self, request: Request) -> Response:
        serializer = TrendingFeedRequestSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        cached_response = self.get_cached_response()
        if cached_response is not None:
            return cached_response

        current_window_end = timezone.now().replace(minute=0, second=0, microsecond=0)
        current_window_start = current_window_end - timedelta(minutes=validated["window_minutes"])
        previous_window_end = current_window_start
        previous_window_start = previous_window_end - timedelta(minutes=validated["window_minutes"])

        bucket_repo = TrendingBucketRepository()
        current_counts = bucket_repo.get_counts_in_window(current_window_start, current_window_end, validated["feed_type"])
        previous_counts = bucket_repo.get_counts_in_window(previous_window_start, previous_window_end, validated["feed_type"])
        attackers = build_ranked_attackers(current_counts, previous_counts, validated["limit"])
        response_payload = {
            "window_minutes": validated["window_minutes"],
            "feed_type": validated["feed_type"],
            "current_window": {
                "start": current_window_start,
                "end": current_window_end,
            },
            "previous_window": {
                "start": previous_window_start,
                "end": previous_window_end,
            },
            "count": len(attackers),
            "data_source": "aggregated",
            "attackers": attackers,
        }
        return Response(TrendingFeedResponseSerializer(instance=response_payload).data)


@extend_schema_view(
    get=extend_schema(
        tags=["Feed Sharing"],
        summary="Consume a shared feed token",
        description=(
            "Public, rate-limited endpoint that replays the advanced-feed request encoded in a signed "
            "share token (`token` path param), so no query string is needed."
        ),
        responses={
            200: AdvancedFeedEnvelopeSerializer,
            400: OpenApiResponse(description="Token is missing/revoked/badly signed, or its decoded feed parameters are invalid."),
            429: RESPONSES[429],
        },
    )
)
class ConsumeFeedView(AdvancedFeedView):
    """Public, rate-limited endpoint that consumes a signed share token.

    Inherits AdvancedFeedView's queryset shaping (credential counts, sensors,
    pagination) so a consumed token produces the same response as the advanced
    feed. Only access control and the input source differ: it is public and
    decodes the request from the token instead of the query string.
    """

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [SharedFeedRateThrottle]

    def get_request_data(self, request: Request, **kwargs) -> dict:
        serializer = TokenConsumeRequestSerializer(data={"token": kwargs["token"]})
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data["feed_params"]


@extend_schema(tags=["Feed Sharing"])
class ShareTokenViewSet(RequestLoggingMixin, ViewSet):
    """Create, list and revoke shareable feed tokens.

    Share/revoke are intentionally GET-able so the links can be opened directly
    in a browser. Share stores the raw query params in the signed token so
    FeedsConsumeView can replay them through AdvancedFeedRequestSerializer.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [FeedsAdvancedThrottle]

    @extend_schema(
        summary="Create a shareable feed link",
        description=(
            "Encode the supplied advanced-feed query parameters into a signed share token and "
            "return its public consume/revoke URLs. The optional `reason` is stored for auditing only."
        ),
        parameters=[ShareFeedRequestSerializer],
        responses={
            200: ShareTokenResponseSerializer,
            400: RESPONSES[400],
            401: RESPONSES[401],
            429: RESPONSES[429],
        },
    )
    def share(self, request: Request) -> Response:
        request_serializer = ShareFeedRequestSerializer(data=request.query_params)
        request_serializer.is_valid(raise_exception=True)
        reason = request_serializer.validated_data["reason"]

        # The raw params (not the typed validated_data) are signed,
        # so the token format and consume-time replay stay unchanged.
        data = request.query_params.dict()
        data.pop("reason", None)
        token = signing.dumps(data, salt=SHARE_TOKEN_SALT)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        ShareToken.objects.get_or_create(
            token_hash=token_hash,
            defaults={"user": request.user, "reason": reason},
        )
        host = request.build_absolute_uri("/")
        response_serializer = ShareTokenResponseSerializer(
            {
                "url": f"{host}api/feeds/consume/{token}",
                "revoke_url": f"{host}api/feeds/revoke/{token}",
            }
        )
        return Response(response_serializer.data)

    @extend_schema(
        summary="Revoke a shared feed token",
        description="Revoke a previously shared token (`token` path param). Only the creator or a staff user may revoke it.",
        responses={
            200: OpenApiResponse(description="Confirmation that the token was revoked."),
            400: OpenApiResponse(description="Token is missing or has an invalid signature."),
            401: RESPONSES[401],
            403: OpenApiResponse(description="The caller is not the token's creator."),
            429: RESPONSES[429],
        },
    )
    def revoke(self, request: Request, token: str) -> Response:
        serializer = TokenRequestSerializer(data={"token": token})
        serializer.is_valid(raise_exception=True)
        share_token = serializer.validated_data["share_token"]
        if share_token.user != request.user and not request.user.is_staff:
            return Response(
                {"errors": {"non_field_errors": ["You do not have permission to revoke this token."]}},
                status=status.HTTP_403_FORBIDDEN,
            )
        if share_token.revoked:
            return Response({"detail": "Token was already revoked."}, status=status.HTTP_200_OK)
        share_token.revoked = True
        share_token.revoked_at = timezone.now()
        share_token.save(update_fields=["revoked", "revoked_at"])
        return Response({"detail": "Token revoked successfully."}, status=status.HTTP_200_OK)

    @extend_schema(
        summary="List the caller's share tokens",
        description="Return the share tokens created by the authenticated user, most recent first.",
        responses={
            200: ShareTokenListItemSerializer(many=True),
            401: RESPONSES[401],
            429: RESPONSES[429],
        },
    )
    def list_tokens(self, request: Request) -> Response:
        tokens = ShareToken.objects.filter(user=request.user).order_by("-created_at").values()
        return Response(ShareTokenListItemSerializer(tokens, many=True).data)
