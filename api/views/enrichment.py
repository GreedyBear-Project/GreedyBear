# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import EnrichmentSerializer
from api.views.utils import UnableToExtractSourceIPError, get_request_source_ip
from greedybear.consts import GET
from greedybear.models import Statistics, ViewType

logger = logging.getLogger(__name__)


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def enrichment_view(request):
    """
    Handle enrichment requests for a specific observable (domain or IP address).

    Args:
        request: The incoming request object containing query parameters.

    Returns:
        Response: A JSON response indicating whether the observable was found,
        and if so, the corresponding IOC.
    """
    observable_name = request.query_params.get("query")
    logger.info(f"Enrichment view requested for: {observable_name}")
    serializer = EnrichmentSerializer(data=request.query_params, context={"request": request})
    serializer.is_valid(raise_exception=True)

    try:
        source_ip = get_request_source_ip(request)
        request_source = Statistics(source=source_ip, view=ViewType.ENRICHMENT_VIEW.value)
        request_source.save()
    except UnableToExtractSourceIPError:
        logger.warning("Skipping statistics recording due to unable to extract source IP")

    return Response(serializer.data, status=status.HTTP_200_OK)
