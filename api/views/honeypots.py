# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.mixins import RequestLoggingMixin
from api.serializers import HoneypotRequestSerializer
from greedybear.models import Honeypot


class HoneypotView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Honeypots"],
        summary="Retrieve a list of all honeypots",
        description=("Retrieve a list of all honeypots, optionally filtering by active status."),
        auth=[],
        parameters=[HoneypotRequestSerializer],
        responses={
            200: OpenApiResponse(
                response={"type": "array", "items": {"type": "string"}},
                description="A JSON response containing the names of the honeypots.",
            )
        },
    )
    def get(self, request: Request, *args, **kwargs):
        request_serializer = HoneypotRequestSerializer(data=request.query_params.dict())
        request_serializer.is_valid(raise_exception=True)
        honeypots = Honeypot.objects.all()
        if request_serializer.validated_data["only_active"]:
            honeypots = honeypots.filter(active=True)
        return Response(list(honeypots.values_list("name", flat=True)))
