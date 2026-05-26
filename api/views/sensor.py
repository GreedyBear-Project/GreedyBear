from certego_saas.apps.auth.backend import CookieTokenAuthentication
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import SensorCreateSerializer
from greedybear.models import APISource, Sensor, SourceType


@api_view(["POST"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def sensor_create_view(request):
    try:
        api_source = request.user.api_source
    except APISource.DoesNotExist:
        return Response({"error": "No APISource linked to your account"}, status=status.HTTP_403_FORBIDDEN)

    serializer = SensorCreateSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    validated_data = serializer.attach_autonomous_system(serializer.validated_data)

    address = validated_data["address"]

    sensor, created = Sensor.objects.get_or_create(
        address=address,
        defaults={
            **validated_data,
            "api_source": api_source,
            "source_type": SourceType.EXTERNAL,
        },
    )

    return Response(
        {
            "id": sensor.id,
            "message": ("Sensor created successfully" if created else "Sensor already existed"),
        },
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )
