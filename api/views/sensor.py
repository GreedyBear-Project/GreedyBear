from certego_saas.apps.auth.backend import CookieTokenAuthentication
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import SensorCreateSerializer
from api.views.utils import create_or_get_sensor
from greedybear.models import APISource


@api_view(["POST"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def sensor_create_view(request):
    """
    Sensor Create API

    This endpoint allows authenticated users to create or fetch a sensor
    using an IP address as the unique identifier.

    Each request is tied to the user's APISource, which is pre-created by
    an administrator. If no APISource is linked to the user,the request is
    rejected.

    Behavior:
    - If the sensor does not exist, it will be created.
    - If the sensor already exists, the existing id is returned.
    - Autonomous System (ASN) is optionally resolved and linked via AutonomousSystem model.

    Authentication:
    This API requires authentication via CookieTokenAuthentication.
    Each user must have an associated APISource to use this endpoint.

    Request:
    POST /api/sensor/

    Args:
        address (str, required): IPv4 or IPv6 address of the sensor.
        honeypot_type (str, optional): Type of honeypot.
        honeypot_software (str, optional): Honeypot software name.
        honeypot_description (str, optional): Description of the sensor.
        sensor_label (str, optional): Human-readable label.
        group_label (str, optional): Group classification label.
        country_code (str, optional): 2-letter ISO country code.
        asn (int, optional): Autonomous System Number.

    Responses:
        201 Created:
            Returned when a new sensor is created.

        200 OK:
            Returned when an existing sensor is fetched.

        400 Bad Request:
            Invalid input data (e.g. malformed IP, invalid country code).

        403 Forbidden:
            User is not authenticated or has no APISource linked.
    """
    try:
        api_source = request.user.api_source
    except APISource.DoesNotExist:
        return Response({"error": "No APISource linked to your account"}, status=status.HTTP_403_FORBIDDEN)

    serializer = SensorCreateSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    sensor, created = create_or_get_sensor(
        api_source=api_source,
        validated_data=serializer.validated_data.copy(),
    )

    return Response(
        {
            "id": sensor.id,
            "message": ("Sensor created successfully" if created else "Sensor already existed"),
        },
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )
