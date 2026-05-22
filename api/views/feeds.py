# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.pagination import CustomPageNumberPagination
from django.core import signing
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import ASNFeedsOrderingSerializer
from api.throttles import FeedsAdvancedThrottle, FeedsThrottle, SharedFeedRateThrottle
from api.views.utils import (
    FeedRequestParams,
    asn_aggregated_queryset,
    feeds_response,
    get_queryset,
    get_valid_feed_types,
)
from greedybear.consts import GET
from greedybear.models import ShareToken

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


@api_view([GET])
@throttle_classes([FeedsThrottle])
def feeds(request, feed_type, attack_type, prioritize, format_):
    """
    Handle requests for IOC feeds with specific parameters and format the response accordingly.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed (e.g. cowrie, honeytrap, etc.).
        attack_type (str): Type of attack (e.g., all, specific attack types).
        prioritize (str): Prioritization mechanism to use (e.g., recent, persistent).
        format_ (str): Desired format of the response (e.g., json, csv, txt).
        include_mass_scanners (bool): query parameter flag to include IOCs that are known mass scanners.
        include_tor_exit_nodes (bool): query parameter flag to include IOCs that are known tor exit nodes.

    Returns:
        Response: The HTTP response with formatted IOC data.
    """
    logger.info(f"request /api/feeds with params: feed type: {feed_type}, attack_type: {attack_type}, prioritization: {prioritize}, format: {format_}")

    filtered_query_params = {key: request.query_params.get(key) for key in ALLOWED_UNAUTHENTICATED_QUERY_PARAMS if key in request.query_params}

    feed_params_data = filtered_query_params.copy()
    feed_params_data.update({"feed_type": feed_type, "attack_type": attack_type, "format": format_})
    feed_params = FeedRequestParams(feed_params_data)
    feed_params.apply_default_filters(filtered_query_params)
    feed_params.set_prioritization(prioritize)

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types)


@api_view([GET])
@throttle_classes([FeedsThrottle])
def feeds_pagination(request):
    """
    Handle requests for paginated IOC feeds based on query parameters.

    Args:
        request: The incoming request object.

    Returns:
        Response: The paginated HTTP response with IOC data.
    """

    logger.info(f"request /api/feeds with params: {request.query_params}")

    filtered_query_params = {key: request.query_params.get(key) for key in ALLOWED_UNAUTHENTICATED_QUERY_PARAMS if key in request.query_params}

    feed_params = FeedRequestParams(filtered_query_params)
    feed_params.format = "json"
    feed_params.apply_default_filters(filtered_query_params)
    feed_params.set_prioritization(filtered_query_params.get("prioritize"))

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    paginator = CustomPageNumberPagination()
    iocs = paginator.paginate_queryset(iocs_queryset, request)
    resp_data = feeds_response(request, iocs, feed_params, valid_feed_types, dict_only=True)
    return paginator.get_paginated_response(resp_data)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([FeedsAdvancedThrottle])
def feeds_advanced(request):
    """
    Handle requests for IOC feeds based on query parameters and format the response accordingly.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed to retrieve. (supported: `cowrie`, `honeytrap`, etc.; default: `all`)
        attack_type (str): Type of attack to filter. (supported: `scanner`, `payload_request`, `all`; default: `all`)
        max_age (int): Maximum number of days since last occurrence. E.g. an IOC that was last seen 4 days ago is excluded by default. (default: 3)
        min_days_seen (int): Minimum number of days on which an IOC must have been seen. (default: 1)
        min_credential_count (int, optional): Filter IOCs with at least this many distinct credentials. (default: no filter)
        max_credential_count (int, optional): Filter IOCs with at most this many distinct credentials. (default: no filter)
        include_reputation (str): `;`-separated list of reputation values to include, e.g. `known attacker` or `known attacker;` to include IOCs without reputation. (default: include all)
        exclude_reputation (str): `;`-separated list of reputation values to exclude, e.g. `mass scanner` or `mass scanner;bot, crawler`. (default: exclude none)
        feed_size (int): Number of IOC items to return. (default: 5000)
        ordering (str): Field to order results by, with optional `-` prefix for descending. (default: `-last_seen`)
        verbose (bool): `true` to include IOC properties that contain a lot of data, e.g. the list of days it was seen. (default: `false`)
        paginate (bool): `true` to paginate results. This forces the json format. (default: `false`)
        format (str): Response format type. Besides `json`, `txt` and `csv` are supported but the response will only contain IOC values (e.g. IP addresses) without further information. (default: `json`)
        tag_key (str, optional): Filter IOCs by tag key, e.g. `malware` or `confidence_of_abuse`. Only IOCs with at least one matching tag are returned.
        tag_value (str, optional): Filter IOCs by tag value (case-insensitive substring match), e.g. `mirai`. Can be used alone or combined with `tag_key`.

    Returns:
        Response: The HTTP response with formatted IOC data.
    """
    logger.info(f"request /api/feeds/advanced/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    verbose = feed_params.verbose == "true"
    paginate = feed_params.paginate == "true"
    if paginate:
        feed_params.format = "json"
    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(
        request,
        feed_params,
        valid_feed_types,
        tag_key=request.query_params.get("tag_key", "").strip(),
        tag_value=request.query_params.get("tag_value", "").strip(),
        include_sensors=True,
        include_credential_count=True,
    )
    if paginate:
        paginator = CustomPageNumberPagination()
        iocs = paginator.paginate_queryset(iocs_queryset, request)
        resp_data = feeds_response(request, iocs, feed_params, valid_feed_types, dict_only=True, verbose=verbose, include_sensors=True)
        return paginator.get_paginated_response(resp_data)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types, verbose=verbose, include_sensors=True)


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([FeedsAdvancedThrottle])
def feeds_asn(request):
    """
    Retrieve aggregated IOC feed data grouped by ASN (Autonomous System Number).

    Args:
        request: The HTTP request object.
        feed_type (str): Filter by feed type (e.g. 'cowrie', 'honeytrap'). Default: 'all'.
        attack_type (str): Filter by attack type (e.g., 'scanner', 'payload_request'). Default: 'all'.
        max_age (int): Maximum age of IOCs in days. Default: 3.
        min_days_seen (int): Minimum days an IOC must have been observed. Default: 1.
        exclude_reputation (str): ';'-separated reputations to exclude (e.g., 'mass scanner'). Default: none.
        ordering (str): Aggregation ordering field (e.g., 'total_attack_count', 'asn'). Default: '-ioc_count'.
        asn (str, optional): Filter results to a single ASN.

    Returns:
     Response: HTTP response with a JSON list of ASN aggregation objects.
     Each object contains:
            asn (int): ASN number.
            ioc_count (int): Number of IOCs for this ASN.
            total_attack_count (int): Sum of attack_count for all IOCs.
            total_interaction_count (int): Sum of interaction_count for all IOCs.
            total_login_attempts (int): Sum of login_attempts for all IOCs.
            honeypots (List[str]): Sorted list of unique honeypots that observed these IOCs.
            expected_ioc_count (float): Sum of recurrence_probability for all IOCs, rounded to 4 decimals.
            expected_interactions (float): Sum of expected_interactions for all IOCs, rounded to 4 decimals.
            first_seen (DateTime): Earliest first_seen timestamp among IOCs.
            last_seen (DateTime): Latest last_seen timestamp among IOCs.
    """
    logger.info(f"request /api/feeds/asn/ with params: {request.query_params}")
    feed_params = FeedRequestParams(request.query_params)
    valid_feed_types = get_valid_feed_types()

    iocs_qs = get_queryset(request, feed_params, valid_feed_types, is_aggregated=True, serializer_class=ASNFeedsOrderingSerializer)

    asn_aggregates = asn_aggregated_queryset(iocs_qs, request, feed_params)
    data = list(asn_aggregates)
    return Response(data)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_share(request):
    """
    Generate a shareable link for the current feed configuration.

    Args:
        request: The incoming request object.
        feed_type (str): Type of feed to retrieve.
        attack_type (str): Type of attack to filter.
        max_age (int): Maximum number of days since last occurrence.
        min_days_seen (int): Minimum number of days on which an IOC must have been seen.
        include_reputation (str): `;`-separated list of reputation values to include.
        exclude_reputation (str): `;`-separated list of reputation values to exclude.
        ordering (str): Field to order results by.
        verbose (bool): `true` to include IOC properties that contain a lot of data.
        asn (int): Filter by ASN.
        min_score (float): Filter by minimum recurrence_probability (0-1).
        port (int): Filter by destination port.
        start_date (str): Filter by start date (YYYY-MM-DD).
        end_date (str): Filter by end date (YYYY-MM-DD).
        reason (str): Optional human-readable label for this share token (max 256 chars).

    Returns:
        Response: A JSON object containing the signed shareable URL.
    """
    safe_params = {k: v for k, v in request.query_params.items() if k != "reason"}
    logger.info(f"request /api/feeds/share with params: {safe_params}")
    feed_params = FeedRequestParams(request.query_params)
    data = vars(feed_params)
    # Remove internal or non-serializable objects if any
    data.pop("feed_type_sorting", None)

    reason = request.query_params.get("reason", "").strip()[:256]

    # Generate signed token and persist a ShareToken record
    token = signing.dumps(data, salt="greedybear-feeds")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ShareToken.objects.get_or_create(
        token_hash=token_hash,
        defaults={"user": request.user, "reason": reason},
    )

    host = request.build_absolute_uri("/")
    share_url = f"{host}api/feeds/consume/{token}"
    revoke_url = f"{host}api/feeds/revoke/{token}"
    return Response({"url": share_url, "revoke_url": revoke_url})


@api_view([GET])
@authentication_classes([])
@permission_classes([])
@throttle_classes([SharedFeedRateThrottle])
def feeds_consume(request, token):
    """
    Consume a shared feed using a signed token.
    This endpoint is publicly accessible but strictly rate-limited.

    Args:
        request: The incoming request object.
        token (str): The signed token containing feed configuration.

    Returns:
        Response: The HTTP response with formatted IOC data in JSON/CSV/TXT/STIX2.1.
    """
    logger.info("request /api/feeds/consume with token")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        share_token = ShareToken.objects.get(token_hash=token_hash)
    except ShareToken.DoesNotExist:
        return Response(
            {"error": "Invalid or expired token"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if share_token.revoked:
        return Response(
            {"error": "Token has been revoked"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        data = signing.loads(token, salt="greedybear-feeds", max_age=86400 * 30)  # 30 days validity
    except signing.BadSignature:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    # Reconstruct params
    feed_params = FeedRequestParams(data)

    valid_feed_types = get_valid_feed_types()
    iocs_queryset = get_queryset(request, feed_params, valid_feed_types)
    return feeds_response(request, iocs_queryset, feed_params, valid_feed_types)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_revoke(request, token):
    """
    Revoke a previously generated shareable feed token.

    Once revoked, any attempt to consume the feed via that token will return a 400 error.
    This is intentionally a GET endpoint so the revoke link can be opened directly in a browser.
    Only the user who created the token (or staff) can revoke it.

    Args:
        request: The incoming request object.
        token (str): The raw signed token to revoke.

    Returns:
        Response: 200 on successful revocation, 400/403 if invalid, expired, or not authorized.
    """
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


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def feeds_tokens(request):
    """
    List the calling user's share tokens with safe metadata.

    Returns only non-sensitive fields: a truncated hash prefix (first 12 hex
    chars), the reason label, creation timestamp, and revocation status.
    The raw token is never stored and therefore cannot be returned.

    Returns:
        Response: A JSON list of token metadata objects.
    """
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
