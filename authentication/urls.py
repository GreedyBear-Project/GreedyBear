# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    APIAccessTokenView,
    ChangePasswordView,
    EmailVerificationView,
    LoginView,
    PasswordResetRequestView,
    PasswordResetView,
    RegistrationView,
    ResendVerificationView,
    TokenSessionsViewSet,
    check_authentication,
    check_configuration,
)

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"sessions", TokenSessionsViewSet, basename="auth_tokensessions")

urlpatterns = [
    # django-rest-email-auth
    path(
        "verify-email",
        EmailVerificationView.as_view(),
        name="auth_verify-email",
    ),
    path(
        "resend-verification",
        ResendVerificationView.as_view(),
        name="auth_resend-verification",
    ),
    path(
        "register",
        RegistrationView.as_view(),
        name="auth_register",
    ),
    path(
        "request-password-reset",
        PasswordResetRequestView.as_view(),
        name="auth_request-password-reset",
    ),
    path("reset-password", PasswordResetView.as_view(), name="auth_reset-password"),
    path("login", LoginView.as_view(), name="auth_login"),
    path("change-password", ChangePasswordView.as_view(), name="auth_change-password"),
    path("configuration", check_configuration),
    # auth
    path("", include("certego_saas.apps.auth.urls")),
    path("apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
    path("authentication", check_authentication),
    path("", include(router.urls)),
]
