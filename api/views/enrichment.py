# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.mixins import RequestLoggingMixin
from api.serializers import EnrichmentRequestSerializer, EnrichmentSerializer
from api.views.utils import save_request_source
from greedybear.models import IOC, ViewType


@extend_schema_view(
    get=extend_schema(
        tags=["Enrichment"],
        summary="Enrich a single observable",
        description=(
            "Look up an IP address or domain in the IOC database. "
            "A well-formed observable always returns 200: `found` states whether GreedyBear knows it and `ioc` carries the full record when it does."
        ),
        parameters=[EnrichmentRequestSerializer],
        responses={
            200: EnrichmentSerializer,
            400: OpenApiResponse(description="The `query` parameter is missing or is not a valid IP address or domain."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
        },
    )
)
class EnrichmentView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, *args, **kwargs):
        request_serializer = EnrichmentRequestSerializer(data=request.query_params.dict())
        request_serializer.is_valid(raise_exception=True)
        save_request_source(request, view=ViewType.ENRICHMENT_VIEW.value)
        query = request_serializer.validated_data["query"]
        try:
            data = {
                "found": True,
                "ioc": IOC.objects.prefetch_related("tags", "sensors").get(name=query),
                "query": query,
            }
        except IOC.DoesNotExist:
            data = {
                "found": False,
                "ioc": None,
                "query": query,
            }
        response_serializer = EnrichmentSerializer(data)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
