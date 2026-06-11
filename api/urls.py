# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework import routers

from api.views import (
    AdvancedFeedView,
    AsnFeedView,
    ConsumeFeedView,
    PaginatedFeedView,
    ShareTokenViewSet,
    SimpleFeedView,
    StatisticsViewSet,
    command_sequence_view,
    cowrie_session_view,
    enrichment_view,
    event_status_view,
    events_create_view,
    general_honeypot_list,
    health_view,
    news_view,
    sensor_create_view,
)

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")

# These come after /api/
# and will appear in the generated schema
documented_urlpatterns = [
    # Feeds
    path("feeds/<str:feed_type>/<str:attack_type>/<str:prioritize>.<str:format_>", SimpleFeedView.as_view()),
    path("feeds/", PaginatedFeedView.as_view()),
    path("feeds/advanced/", AdvancedFeedView.as_view()),
    path("feeds/asn/", AsnFeedView.as_view()),
    path("feeds/share", ShareTokenViewSet.as_view({"get": "share"})),
    path("feeds/consume/<str:token>", ConsumeFeedView.as_view()),
    path("feeds/revoke/<str:token>", ShareTokenViewSet.as_view({"get": "revoke"})),
    path("feeds/tokens/", ShareTokenViewSet.as_view({"get": "list_tokens"})),
]
schema_urlconf = [path("api/", include(documented_urlpatterns))]

# These come after /api/
# but won't appear in the generated schema
urlpatterns = [
    # OpenAPI schema and interactive docs
    path("schema/", SpectacularAPIView.as_view(urlconf=schema_urlconf), name="schema"),
    path("schema/swagger-ui/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("enrichment", enrichment_view),
    path("cowrie_session", cowrie_session_view),
    path("command_sequence", command_sequence_view),
    path("general_honeypot", general_honeypot_list),
    path("news/", news_view),
    path("health/", health_view),
    path("sensor/", sensor_create_view),
    path("events/add/", events_create_view),
    path("events/status/<str:task_id>/", event_status_view),
    # router viewsets
    path("", include(router.urls)),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # auth
    path("auth/", include("authentication.urls")),
    *documented_urlpatterns,
]
