# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django.conf import settings
from django.http import Http404, HttpResponseBadRequest
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.views.utils import UnableToExtractSourceIPError, get_request_source_ip
from greedybear.consts import GET
from greedybear.models import IOC, CommandSequence, CowrieSession, Statistics, ViewType
from greedybear.utils import is_ip_address, is_sha256hash

logger = logging.getLogger(__name__)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def command_sequence_view(request):
    """
    Legacy endpoint — succeeded by the cowrie_session API, which covers the same use cases.
    Do not extend or modify this view; direct new development to cowrie_session_view instead.

    View function that handles command sequence queries based on IP addresses or SHA-256 hashes.

    Retrieves and returns command sequences and related IOCs based on the query parameter.
    If IP address is given, returns all command sequences executed from this IP.
    If SHA-256 hash is given, returns details about the specific command sequence.
    Can include similar command sequences if requested.

    Args:
        request: The HTTP request object containing query parameters
        query (str): The search term, can be either an IP address or a SHA-256 hash.
        include_similar (bool): When parameter is present, returns related command sequences based on clustering.

    Returns:
        Response object with command sequence data or an error response

    Raises:
        Http404: If the requested resource is not found
    """
    observable = request.query_params.get("query")
    include_similar = request.query_params.get("include_similar") is not None
    logger.info(f"Command Sequence view requested by {request.user} for {observable}")

    if not observable:
        return HttpResponseBadRequest("Missing required 'query' parameter")

    try:
        source_ip = get_request_source_ip(request)
        request_source = Statistics(source=source_ip, view=ViewType.COMMAND_SEQUENCE_VIEW.value)
        request_source.save()
    except UnableToExtractSourceIPError:
        logger.warning("Skipping statistics recording due to unable to extract source IP")

    if is_ip_address(observable):
        sessions = CowrieSession.objects.filter(source__name=observable, start_time__isnull=False, commands__isnull=False)
        sequences = {s.commands for s in sessions}
        seqs = [
            {
                "time": s.start_time,
                "command_sequence": "\n".join(s.commands.commands),
                "command_sequence_hash": s.commands.commands_hash,
            }
            for s in sessions
        ]
        related_iocs = IOC.objects.filter(cowriesession__commands__in=sequences).distinct().only("name")
        if include_similar:
            related_clusters = {s.cluster for s in sequences if s.cluster is not None}
            if related_clusters:
                cluster_iocs = IOC.objects.filter(cowriesession__commands__cluster__in=related_clusters).distinct().only("name")
                related_iocs = related_iocs.union(cluster_iocs)
        if not seqs:
            raise Http404(f"No command sequences found for IP: {observable}")
        data = {
            "executed_commands": seqs,
            "executed_by": sorted([ioc.name for ioc in related_iocs]),
        }
        if settings.FEEDS_LICENSE:
            data["license"] = settings.FEEDS_LICENSE
        return Response(data, status=status.HTTP_200_OK)

    if is_sha256hash(observable):
        try:
            seq = CommandSequence.objects.get(commands_hash=observable)
            seqs = CommandSequence.objects.filter(cluster=seq.cluster) if include_similar and seq.cluster is not None else [seq]
            commands = ["\n".join(seq.commands) for seq in seqs]
            sessions = CowrieSession.objects.filter(commands__in=seqs, start_time__isnull=False)
            iocs = [
                {
                    "time": s.start_time,
                    "ip": s.source.name,
                }
                for s in sessions
            ]
            data = {
                "commands": commands,
                "iocs": sorted(iocs, key=lambda d: d["time"], reverse=True),
            }
            if settings.FEEDS_LICENSE:
                data["license"] = settings.FEEDS_LICENSE
            return Response(data, status=status.HTTP_200_OK)
        except CommandSequence.DoesNotExist as exc:
            raise Http404(f"No command sequences found with hash: {observable}") from exc

    return HttpResponseBadRequest("Query must be a valid IP address or SHA-256 hash")
