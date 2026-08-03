# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import ipaddress
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django.conf import settings
from django.http import Http404, HttpResponseBadRequest
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.mixins import RequestLoggingMixin
from api.serializers import CowrieSessionRequestSerializer, CowrieSessionSerializer
from api.views.utils import save_request_source
from greedybear.models import CommandSequence, CowrieSession, ViewType
from greedybear.utils import is_ip_address, is_sha256hash

logger = logging.getLogger(__name__)


@extend_schema_view(
    get=extend_schema(
        tags=["Cowrie Session"],
        summary="Session data from the Cowrie honeypot",
        description=(
            "Retrieve Cowrie honeypot session data including command sequences, credentials, and session details. "
            "Queries can be performed using an IP address to find all sessions from that source, "
            "a SHA-256 hash to find sessions containing a specific command sequence, "
            "or a password to find all sessions where that password was used."
        ),
        parameters=[CowrieSessionRequestSerializer],
        responses={
            200: CowrieSessionSerializer,
            400: OpenApiResponse(description="Missing or invalid `query` parameter."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            404: OpenApiResponse(description="No matching sessions found."),
        },
    )
)
class CowrieSessionView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, *args, **kwargs):
        request_serializer = CowrieSessionRequestSerializer(data=request.query_params.dict())
        request_serializer.is_valid(raise_exception=True)
        save_request_source(request, view=ViewType.ENRICHMENT_VIEW.value)
        observable = request_serializer.validated_data["query"]
        if is_ip_address(observable):
            sessions = CowrieSession.objects.filter(source__name=observable, duration__gt=0).prefetch_related("source", "commands", "credentials")
            if not sessions.exists():
                raise Http404(f"No information found for IP: {observable}")

        elif is_sha256hash(observable):
            try:
                commands = CommandSequence.objects.get(commands_hash=observable.lower())
            except CommandSequence.DoesNotExist as exc:
                raise Http404(f"No command sequences found with hash: {observable}") from exc
            sessions = CowrieSession.objects.filter(commands=commands, duration__gt=0).prefetch_related("source", "commands", "credentials")
        else:
            if len(observable) > 256:  # max_length of Credential.password field
                return HttpResponseBadRequest("Query exceeds maximum password length")
            sessions = CowrieSession.objects.filter(credentials__password=observable, duration__gt=0).prefetch_related("source", "commands", "credentials")
            if not sessions.exists():
                raise Http404(f"No information found for password: {observable}")

        if request_serializer.validated_data["include_similar"]:
            commands = {s.commands for s in sessions if s.commands}
            clusters = {cmd.cluster for cmd in commands if cmd.cluster is not None}
            related_sessions = CowrieSession.objects.filter(commands__cluster__in=clusters, duration__gt=0).prefetch_related(
                "source", "commands", "credentials"
            )
            sessions = sessions.union(related_sessions)

        data = {
            "query": observable,
        }
        if settings.FEEDS_LICENSE:
            data["license"] = settings.FEEDS_LICENSE

        unique_commands = {s.commands for s in sessions if s.commands}
        data["commands"] = sorted("\n".join(cmd.commands) for cmd in unique_commands)
        data["sources"] = sorted({s.source.name for s in sessions}, key=lambda ip: ipaddress.ip_address(ip))
        if request_serializer.validated_data["include_credentials"]:
            data["credentials"] = sorted({str(c) for s in sessions for c in s.credentials.all()})
        if request_serializer.validated_data["include_session_data"]:
            data["sessions"] = [
                {
                    "time": s.start_time,
                    "duration": s.duration,
                    "source": s.source.name,
                    "interactions": s.interaction_count,
                    "credentials": [str(c) for c in s.credentials.all()],
                    "commands": "\n".join(s.commands.commands) if s.commands else "",
                }
                for s in sessions
            ]

        response_serializer = CowrieSessionSerializer(data)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
