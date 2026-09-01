from certego_saas.apps.auth.backend import CookieTokenAuthentication
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.mixins import RequestLoggingMixin
from api.serializers import SensorCreateResponseSerializer, SensorCreateSerializer
from api.views.utils import create_or_get_sensor, resolve_active_api_source


class SensorCreateView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Event Injection"],
        summary="Sensor creation",
        description=(
            "This endpoint allows authenticated users to create or fetch a sensor using an IP address as the unique identifier. "
            "Each request is tied to the user's APISource, which is pre-created by an administrator. "
            "If no APISource is linked to the user, the request is rejected."
        ),
        request=SensorCreateSerializer,
        responses={
            200: OpenApiResponse(response=SensorCreateResponseSerializer, description="An existing sensor is fetched."),
            201: OpenApiResponse(response=SensorCreateResponseSerializer, description="A new sensor is created."),
            400: OpenApiResponse(description="Invalid input data (e.g. malformed IP, invalid country code)."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Missing `APISource` or locked account state."),
        },
    )
    def post(self, request: Request, *args, **kwargs):
        api_source, error_response = resolve_active_api_source(request)
        if error_response:
            return error_response

        serializer = SensorCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        sensor, created = create_or_get_sensor(
            api_source=api_source,
            validated_data=serializer.validated_data.copy(),
        )

        response_serializer = SensorCreateResponseSerializer(
            {
                "id": sensor.id,
                "message": ("Sensor created successfully" if created else "Sensor already existed"),
            }
        )

        return Response(
            response_serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )
