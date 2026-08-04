import logging

from certego_saas.apps.auth.backend import CookieTokenAuthentication
from django_q.tasks import async_task
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from api.mixins import RequestLoggingMixin
from api.serializers import BatchStatusRequestSerializer, BatchStatusSerializer, InjectionResponseSerializer, InjectionSerializer
from api.views.utils import create_batch_and_events, increment_and_evaluate_lock, resolve_active_api_source
from greedybear.models import EventStatus, EventStatusType

logger = logging.getLogger(__name__)


class EventsCreateView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Event Injection"],
        summary="Ingest a batch of events.",
        description=(
            "Ingest a batch of raw security events, persist them, and hand off processing to a background task. "
            "This endpoint validates the payload structure, maps events to a tracking batch, saves them bulk-style to the database to minimize I/O overhead, "
            "and offloads heavy parsing (extracting IOCs, usernames, commands, etc.) asynchronously via Django-Q. "
            "Note: Users calling this endpoint must have an active, associated `APISource`."
        ),
        request=InjectionSerializer,
        responses={
            202: OpenApiResponse(response=InjectionResponseSerializer, description="Payload verified and successfully queued for background extraction."),
            400: OpenApiResponse(description="Validation failure or empty event set creation."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Missing `APISource` or locked account state."),
            500: OpenApiResponse(description="An internal error occurred during early event processing."),
        },
    )
    def post(self, request: Request, *args, **kwargs):
        api_source, error_response = resolve_active_api_source(request)
        if error_response:
            return error_response

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

        response_serializer = InjectionResponseSerializer(
            {
                "message": f"{total_created} events accepted for processing",
                "task_id": batch.task_id,
                "status_url": f"/api/events/status/{batch.task_id}/",
            }
        )

        return Response(
            response_serializer.data,
            status=status.HTTP_202_ACCEPTED,
        )


class BatchStatusView(RequestLoggingMixin, APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Event Injection"],
        summary="Retrieve the status of a specific event batch",
        description=(
            "Retrieve the execution and processing status of a specific event batch using its task ID. "
            "This endpoint safely exposes the processing lifecycle phase (e.g., pending, processing, completed, failed) "
            "of an asynchronous background extraction task triggered by Django-Q. "
            "Note: Users calling this endpoint must have an active, associated `APISource`."
        ),
        parameters=[
            OpenApiParameter(
                name="task_id",
                type=str,
                pattern=r"^[0-9a-f]{32}$",
                location=OpenApiParameter.PATH,
                description="The unique string identifier assigned to the background processing job.",
            )
        ],
        responses={
            200: OpenApiResponse(response=BatchStatusSerializer, description="Success payload detailing batch metrics, failure reasons (if any), and state."),
            400: OpenApiResponse(description="`task_id` is not a well-formed batch identifier."),
            401: OpenApiResponse(description="Authentication credentials were not provided or are invalid."),
            403: OpenApiResponse(description="Missing `APISource` or locked account state."),
            404: OpenApiResponse(description="No event batch matching the provided `task_id` exists for this account."),
        },
    )
    def get(self, request: Request, task_id: str, *args, **kwargs):
        api_source, error_response = resolve_active_api_source(request)
        if error_response:
            return error_response

        # task_id arrives as a path segment, so it is wrapped into a mapping to be validated.
        request_serializer = BatchStatusRequestSerializer(data={"task_id": task_id})
        request_serializer.is_valid(raise_exception=True)

        try:
            batch = EventStatus.objects.get(task_id=task_id, api_source=api_source)
        except EventStatus.DoesNotExist:
            return Response({"error": f"No batch found for task_id={task_id}"}, status=status.HTTP_404_NOT_FOUND)

        return Response(
            BatchStatusSerializer(batch).data,
            status=status.HTTP_200_OK,
        )
