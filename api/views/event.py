import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django_q.tasks import async_task
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.serializers import InjectionSerializer
from api.views.utils import create_batch_and_events, increment_and_evaluate_lock
from greedybear.models import APISource, EventStatus, EventStatusType

logger = logging.getLogger(__name__)


@api_view(["POST"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def events_create_view(request):
    """
    Ingest a batch of raw security events, persist them, and hand off processing to a background task.

    This endpoint validates the payload structure, maps events to a tracking batch, saves
    them bulk-style to the database to minimize I/O overhead, and offloads heavy parsing
    (extracting IOCs, usernames, commands, etc.) asynchronously via Django-Q.

    **Authentication:**
        - Required: CookieTokenAuthentication
        - User must have an active and valid associated `APISource`.

    **Payload Requirements:**
        - Content-Type: application/json
        - Structure: {"events": [ {...event_1...}, {...event_2...} ]}
        - Batch constraints: Min 1 event, Max 10,000 events per request.

    **Responses:**
        - `202 Accepted`: Payload verified and successfully queued for background extraction.
        - `400 Bad Request`: Validation failure or empty event set creation.
        - `403 Forbidden`: Unauthenticated, missing `APISource`, or locked account state.
    """
    try:
        api_source = request.user.api_source
    except APISource.DoesNotExist:
        return Response(
            {"error": "No APISource linked to your account"},
            status=status.HTTP_403_FORBIDDEN,
        )

    if not api_source.is_active:
        return Response(
            {"error": "APISource is locked"},
            status=status.HTTP_403_FORBIDDEN,
        )

    serializer = InjectionSerializer(data=request.data)
    if not serializer.is_valid():
        if lock_response := increment_and_evaluate_lock(api_source):
            return lock_response
        return Response({"error": "Invalid data", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    events_data = serializer.validated_data["events"]

    try:
        batch, total_created = create_batch_and_events(
            events_data,
            api_source,
        )
    except ValueError as e:
        if lock_response := increment_and_evaluate_lock(api_source):
            return lock_response
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    except Exception:
        logger.exception("Failed while creating batch & events")
        return Response({"error": "An internal database error occurred while staging events"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    try:
        # enqueue background task
        async_task(
            "greedybear.process_event.process_incoming_event",
            api_source.id,
            batch.task_id,
        )
    except Exception as e:
        logger.exception(f"Failed to enqueue background task for batch {batch.task_id}")

        # marking the batch as failed so it doesn't get orphaned in a 'PENDING' state
        batch.status = EventStatusType.FAILED
        batch.last_error = f"Background task dispatch failed: {e!s}"
        batch.save(update_fields=["status", "last_error"])

        return Response({"error": "An internal error occurred while queueing events for processing"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    logger.info(f"[task={batch.task_id}] Accepted {total_created} events — source={api_source.name}")

    return Response(
        {
            "message": f"{total_created} events accepted for processing",
            "task_id": batch.task_id,
            "status_url": f"/api/events/status/{batch.task_id}/",
        },
        status=status.HTTP_202_ACCEPTED,
    )


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def event_status_view(request, task_id: str):
    """
    Retrieve the execution and processing status of a specific event batch using its task ID.

    This endpoint safely exposes the processing lifecycle phase (e.g., pending, processing, completed, failed)
    of an asynchronous background extraction task triggered by Django-Q.

    **Authentication:**
        - Required: CookieTokenAuthentication
        - User must have an active, valid associated `APISource`.

    **Path Parameters:**
        - `task_id` (str): The unique string identifier assigned to the background processing job.

    **Responses:**
        - `200 OK`: Success payload detailing batch metrics, failure reasons (if any), and state.
        - `403 Forbidden`: Unauthenticated, missing `APISource`, or locked account state.
        - `404 Not Found`: No event batch matching the provided `task_id` exists for this account.
    """
    try:
        api_source = request.user.api_source
    except APISource.DoesNotExist:
        return Response({"error": "No APISource linked to your account"}, status=status.HTTP_403_FORBIDDEN)

    if not api_source.is_active:
        return Response(
            {"error": "APISource is locked"},
            status=status.HTTP_403_FORBIDDEN,
        )

    try:
        batch = EventStatus.objects.get(task_id=task_id, api_source=api_source)
    except EventStatus.DoesNotExist:
        return Response({"error": f"No batch found for task_id={task_id}"}, status=status.HTTP_404_NOT_FOUND)

    return Response(
        {
            "task_id": batch.task_id,
            "batch_id": batch.id,
            "status": batch.status,
            "ioc_count": batch.ioc_count,
            "last_error": batch.last_error or None,
            "processed_at": batch.processed_at,
            "created_at": batch.created_at,
        },
        status=status.HTTP_200_OK,
    )
