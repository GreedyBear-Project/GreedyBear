# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework import routers

from api.views import (
    AdvancedFeedView,
    AsnFeedView,
    BatchStatusView,
    ConsumeFeedView,
    CowrieSessionView,
    DashboardConfigView,
    EnrichmentView,
    EventsCreateView,
    HealthView,
    HoneypotPayloadViewSet,
    HoneypotView,
    PaginatedFeedView,
    SensorCreateView,
    ShareTokenViewSet,
    SimpleFeedView,
    StatisticsViewSet,
    TrendingFeedView,
    command_sequence_view,
    news_view,
)

# Routers provide an easy way of automatically determining the URL conf.
# These will appear in the generated schema
documented_router = routers.DefaultRouter(trailing_slash=False)
documented_router.register(r"payloads", HoneypotPayloadViewSet, basename="payloads")

# These will NOT appear in the generated schema
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")
router.register(r"payloads", HoneypotPayloadViewSet, basename="payloads")

# These come after /api/
# and will appear in the generated schema
documented_urlpatterns = [
    # Feeds
    path("feeds/<str:feed_type>/<str:attack_type>/<str:prioritize>.<str:format_>", SimpleFeedView.as_view()),
    path("feeds/", PaginatedFeedView.as_view()),
    path("feeds/advanced/", AdvancedFeedView.as_view()),
    path("feeds/asn/", AsnFeedView.as_view()),
    path("feeds/trending/", TrendingFeedView.as_view()),
    path("feeds/share", ShareTokenViewSet.as_view({"get": "share"})),
    path("feeds/consume/<str:token>", ConsumeFeedView.as_view()),
    path("feeds/revoke/<str:token>", ShareTokenViewSet.as_view({"get": "revoke"})),
    path("feeds/tokens/", ShareTokenViewSet.as_view({"get": "list_tokens"})),
    path("enrichment", EnrichmentView.as_view()),
    path("cowrie_session", CowrieSessionView.as_view()),
    path("honeypot/", HoneypotView.as_view()),
    path("sensor/", SensorCreateView.as_view()),
    path("events/add/", EventsCreateView.as_view()),
    path("events/status/<str:task_id>/", BatchStatusView.as_view()),
    path("health/", HealthView.as_view()),
]
schema_urlconf = [path("api/", include(documented_urlpatterns + documented_router.urls))]

# These come after /api/
# but won't appear in the generated schema
urlpatterns = [
    # OpenAPI schema and interactive docs
    path("schema/", SpectacularAPIView.as_view(urlconf=schema_urlconf), name="schema"),
    path("schema/swagger-ui/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("command_sequence", command_sequence_view),
    path("general_honeypot", HoneypotView.as_view()),
    path("news/", news_view),
    path("dashboard-config/", DashboardConfigView.as_view()),
    # router viewsets
    path("", include(router.urls)),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # auth
    path("auth/", include("authentication.urls")),
    *documented_urlpatterns,
]
