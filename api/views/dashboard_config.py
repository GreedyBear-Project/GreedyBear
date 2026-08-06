# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsSuperuserOrReadOnly
from greedybear.models import DashboardConfig

logger = logging.getLogger(__name__)


class DashboardLayoutSerializer(serializers.Serializer):
    layout = serializers.DictField()

    def validate_layout(self, value):
        if "widgetConfigs" not in value or "layouts" not in value:
            raise serializers.ValidationError("'layout' must contain 'widgetConfigs' and 'layouts' keys.")
        if not isinstance(value["widgetConfigs"], list):
            raise serializers.ValidationError("'widgetConfigs' must be a list.")
        if not isinstance(value["layouts"], dict):
            raise serializers.ValidationError("'layouts' must be an object.")
        return value


class DashboardConfigView(APIView):
    """
    GET  /api/dashboard-config/
        Returns the globally saved dashboard layout, or null when no record
        exists yet (frontend falls back to defaultDashboardConfig.js).
        Open to all users including anonymous visitors.

    PUT  /api/dashboard-config/
        Replaces the global layout. Restricted to superusers.
        Expects JSON body: { "widgetConfigs": [...], "layouts": {...} }

    DELETE  /api/dashboard-config/
        Removes the saved config so all users fall back to built-in defaults.
        Restricted to superusers.
    """

    authentication_classes = [CookieTokenAuthentication, SessionAuthentication]
    permission_classes = [IsSuperuserOrReadOnly]

    # ------------------------------------------------------------------ GET --

    def get(self, request: Request) -> Response:
        record = DashboardConfig.objects.first()
        if record is None:
            return Response({"layout": None}, status=status.HTTP_200_OK)
        return Response({"layout": record.layout}, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------ PUT --

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

    # ---------------------------------------------------------------- DELETE --

    def delete(self, request: Request) -> Response:
        deleted_count, _ = DashboardConfig.objects.all().delete()
        logger.info(
            "DashboardConfig deleted by superuser=%s (rows removed: %s)",
            request.user,
            deleted_count,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
