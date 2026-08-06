# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsSuperuserOrReadOnly
from greedybear.models import DashboardConfig

logger = logging.getLogger(__name__)


class DashboardLayoutSerializer(serializers.Serializer):
    layout = serializers.DictField(
        help_text=(
            "Saved dashboard layout containing 'widgetConfigs' (list) and 'layouts' (react-grid-layout breakpoint map). Null when no config has been saved yet."
        ),
    )

    def validate_layout(self, value):
        if "widgetConfigs" not in value or "layouts" not in value:
            raise serializers.ValidationError("'layout' must contain 'widgetConfigs' and 'layouts' keys.")
        if not isinstance(value["widgetConfigs"], list):
            raise serializers.ValidationError("'widgetConfigs' must be a list.")
        if not isinstance(value["layouts"], dict):
            raise serializers.ValidationError("'layouts' must be an object.")
        return value


@extend_schema_view(
    get=extend_schema(
        tags=["Dashboard"],
        summary="Retrieve the global dashboard layout",
        description=(
            "Returns the dashboard layout saved by a superuser. "
            "When no configuration has been saved yet, `layout` is `null` and the "
            "frontend falls back to the built-in default layout. "
            "Open to all users including anonymous visitors."
        ),
        responses={
            200: DashboardLayoutSerializer,
        },
    ),
    put=extend_schema(
        tags=["Dashboard"],
        summary="Save the global dashboard layout",
        description=(
            "Replaces the globally shared dashboard layout. "
            "The saved configuration is immediately visible to all users on their next page load. "
            "Restricted to superusers."
        ),
        request=DashboardLayoutSerializer,
        responses={
            200: DashboardLayoutSerializer,
            400: OpenApiResponse(description="Invalid request body - missing or malformed 'layout' key."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Permission denied - requires superuser privileges."),
        },
    ),
    delete=extend_schema(
        tags=["Dashboard"],
        summary="Reset the global dashboard layout to defaults",
        description=(
            "Deletes the saved dashboard configuration. "
            "All users will fall back to the built-in default layout on their next page load. "
            "Restricted to superusers."
        ),
        responses={
            204: OpenApiResponse(description="Configuration deleted successfully."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Permission denied - requires superuser privileges."),
        },
    ),
)
class DashboardConfigView(APIView):
    authentication_classes = [CookieTokenAuthentication, SessionAuthentication]
    permission_classes = [IsSuperuserOrReadOnly]

    def get(self, request: Request) -> Response:
        record = DashboardConfig.objects.first()
        if record is None:
            return Response({"layout": None}, status=status.HTTP_200_OK)
        return Response({"layout": record.layout}, status=status.HTTP_200_OK)

    def put(self, request: Request) -> Response:
        serializer = DashboardLayoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        layout = serializer.validated_data["layout"]

        record = DashboardConfig.objects.first()
        if record is None:
            record = DashboardConfig(layout=layout, updated_by=request.user)
        else:
            record.layout = layout
            record.updated_by = request.user
        record.save()

        logger.info(
            "DashboardConfig saved by superuser=%s (record id=%s)",
            request.user,
            record.pk,
        )
        return Response({"layout": record.layout}, status=status.HTTP_200_OK)

    def delete(self, request: Request) -> Response:
        deleted_count, _ = DashboardConfig.objects.all().delete()
        logger.info(
            "DashboardConfig deleted by superuser=%s (rows removed: %s)",
            request.user,
            deleted_count,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
