# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.http import FileResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.permissions import IsThreatResearcherOrAdmin
from api.serializers.payloads import HoneypotPayloadSerializer
from greedybear.models import HoneypotPayload

logger = logging.getLogger(__name__)


@extend_schema_view(
    list=extend_schema(
        summary="List payload metadata",
        description="Returns paginated metadata (hashes, MIME type, source honeypot, size) for all captured honeypot payloads. Does not return raw files.",
        tags=["Payloads"],
        responses={
            200: HoneypotPayloadSerializer(many=True),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
        },
    ),
    retrieve=extend_schema(
        summary="Retrieve payload metadata",
        description="Returns metadata for a single payload identified by its SHA256 hash.",
        tags=["Payloads"],
        responses={
            200: HoneypotPayloadSerializer,
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            404: OpenApiResponse(description="No payload found with the given SHA256 hash."),
        },
    ),
)
class HoneypotPayloadViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only viewset for honeypot-captured payloads.

    ``list`` / ``retrieve`` — metadata only (hashes, MIME type, source
    honeypot, size).  Available to any authenticated user.

    ``download`` — streams the raw ``.vir`` quarantine file.  Restricted
    to staff or users in the ``threat_researcher`` group via
    :class:`~api.permissions.IsThreatResearcherOrAdmin`.
    """

    queryset = HoneypotPayload.objects.prefetch_related("source_honeypots").order_by("-id")
    serializer_class = HoneypotPayloadSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "sha256"

    @extend_schema(
        summary="Download payload binary",
        description="Streams the raw `.vir` quarantine file as an attachment. Restricted to staff or users in the `threat_researcher` group.",
        tags=["Payloads"],
        responses={
            200: OpenApiResponse(
                description="Raw binary file streamed as `application/octet-stream`.",
                response=OpenApiTypes.BINARY,
            ),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Permission denied — requires staff or `threat_researcher` group membership."),
            404: OpenApiResponse(description="Payload record not found, or the file has been removed from the quarantine directory."),
        },
    )
    @action(
        detail=True,
        methods=["get"],
        permission_classes=[IsAuthenticated, IsThreatResearcherOrAdmin],
        url_path="download",
    )
    def download(self, request, sha256=None):
        payload = self.get_object()

        if not payload.payload_file:
            return Response(
                {"detail": "Payload file is not available for download."},
                status=status.HTTP_404_NOT_FOUND,
            )

        logger.info("user=%s downloaded payload sha256=%s", request.user.username, payload.sha256)

        try:
            file_handle = payload.payload_file.open("rb")
        except FileNotFoundError:
            return Response(
                {"detail": "Payload file is not available for download."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return FileResponse(
            file_handle,
            as_attachment=True,
            filename=f"{payload.sha256}.vir",
            content_type="application/octet-stream",
        )
