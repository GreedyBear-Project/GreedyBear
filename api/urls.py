# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.urls import include, path
from rest_framework import routers

from api.views import (
    StatisticsViewSet,
    command_sequence_view,
    cowrie_session_view,
    enrichment_view,
    event_status_view,
    events_create_view,
    feeds,
    feeds_advanced,
    feeds_asn,
    feeds_consume,
    feeds_pagination,
    feeds_revoke,
    feeds_share,
    feeds_tokens,
    general_honeypot_list,
    health_view,
    news_view,
    sensor_create_view,
)

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"statistics", StatisticsViewSet, basename="statistics")

# These come after /api/..
urlpatterns = [
    path("feeds/", feeds_pagination),
    path("feeds/share", feeds_share),
    path("feeds/consume/<str:token>", feeds_consume),
    path("feeds/revoke/<str:token>", feeds_revoke),
    path("feeds/tokens/", feeds_tokens),
    path("feeds/advanced/", feeds_advanced),
    path("feeds/asn/", feeds_asn),
    path("feeds/<str:feed_type>/<str:attack_type>/<str:prioritize>.<str:format_>", feeds),
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
]
