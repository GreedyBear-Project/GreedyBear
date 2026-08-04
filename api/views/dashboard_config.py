import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from greedybear.models import DashboardConfig

logger = logging.getLogger(__name__)


class DashboardConfigView(APIView):
    """
    GET  /api/dashboard-config/
        Returns the globally saved dashboard layout, or null when no record
        exists yet (frontend falls back to defaultDashboardConfig.js).
        Requires authentication so anonymous scraping is not possible.

    PUT  /api/dashboard-config/
        Replaces the global layout.  Restricted to superusers.
        Expects JSON body: { "widgetConfigs": [...], "layouts": {...} }
    """

    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    # ------------------------------------------------------------------ GET --

    def get(self, request: Request) -> Response:
        logger.info(
            "DashboardConfig GET requested by user=%s superuser=%s",
            request.user,
            request.user.is_superuser,
        )
        record = DashboardConfig.objects.first()
        if record is None:
            # No config saved yet – signal the frontend to use built-in defaults.
            return Response({"layout": None}, status=status.HTTP_200_OK)

        return Response({"layout": record.layout}, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------ PUT --

    def put(self, request: Request) -> Response:
        if not request.user.is_superuser:
            logger.warning(
                "DashboardConfig PUT rejected: user=%s is not a superuser",
                request.user,
            )
            return Response(
                {"detail": "Only superusers may modify the dashboard configuration."},
                status=status.HTTP_403_FORBIDDEN,
            )

        layout = request.data.get("layout")
        if layout is None:
            return Response(
                {"detail": "Request body must contain a 'layout' key."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not isinstance(layout, dict) or "widgetConfigs" not in layout or "layouts" not in layout:
            return Response(
                {
                    "detail": (
                        "'layout' must be an object with 'widgetConfigs' "
                        "and 'layouts' keys."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # keep at most one global record.
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
        """
        DELETE /api/dashboard-config/
        Removes the saved config so the frontend falls back to built-in
        defaults on the next load.  Restricted to superusers.
        """
        if not request.user.is_superuser:
            return Response(
                {"detail": "Only superusers may reset the dashboard configuration."},
                status=status.HTTP_403_FORBIDDEN,
            )

        deleted_count, _ = DashboardConfig.objects.all().delete()
        logger.info(
            "DashboardConfig deleted by superuser=%s (rows removed: %s)",
            request.user,
            deleted_count,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
