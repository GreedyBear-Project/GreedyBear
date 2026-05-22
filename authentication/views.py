import logging

import rest_email_auth.views
from certego_saas.apps.auth import views as certego_views
from certego_saas.apps.auth.backend import CookieTokenAuthentication
from certego_saas.ext.throttling import POSTUserRateThrottle
from django.conf import settings
from django.contrib.auth import get_user_model, login
from durin import views as durin_views
from durin.models import AuthToken
from rest_framework import status
from rest_framework.decorators import (
    action,
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from greedybear.consts import GET
from greedybear.enums import FrontendPage
from greedybear.settings import AUTH_USER_MODEL

from .serializers import (
    ChangePasswordSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    RegistrationSerializer,
)

logger = logging.getLogger(__name__)

""" Auth API endpoints """

User: AUTH_USER_MODEL = get_user_model()


def revoke_other_tokens(user, current_token=None):
    # Keep only the provided token for this user; revoke all when current_token is null.
    if current_token:
        AuthToken.objects.filter(user=user).exclude(pk=current_token.pk).delete()
    else:
        AuthToken.objects.filter(user=user).delete()


class PasswordResetRequestView(rest_email_auth.views.PasswordResetRequestView):
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = [POSTUserRateThrottle]


class PasswordResetView(rest_email_auth.views.PasswordResetView):
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = [POSTUserRateThrottle]


class EmailVerificationView(rest_email_auth.views.EmailVerificationView):
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = [POSTUserRateThrottle]
    serializer_class = EmailVerificationSerializer


class RegistrationView(rest_email_auth.views.RegistrationView):
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = [POSTUserRateThrottle]
    serializer_class = RegistrationSerializer


class ResendVerificationView(rest_email_auth.views.ResendVerificationView):
    authentication_classes: list = []
    permission_classes: list = []
    throttle_classes: list = [POSTUserRateThrottle]


@api_view([GET])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def check_authentication(request):
    logger.info(f"User: {request.user}, Administrator: {request.user.is_superuser}")
    return Response({"is_superuser": request.user.is_superuser}, status=status.HTTP_200_OK)


@api_view([GET])
def check_configuration(request):
    logger.info(f"Requested checking configuration from {request.user}.")
    page = request.query_params.get("page")
    errors = {}

    if page == FrontendPage.REGISTER.value:
        # email setup
        if not settings.DEFAULT_FROM_EMAIL:
            errors["DEFAULT_FROM_EMAIL"] = "required"
        if not settings.DEFAULT_EMAIL:
            errors["DEFAULT_EMAIL"] = "required"

        # if you are in production environment
        if settings.STAGE_PRODUCTION:
            # SES backend
            if settings.AWS_SES:
                if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
                    errors["AWS SES backend"] = "configuration required"
            else:
                # SMTP backend
                required_variables = [
                    settings.EMAIL_HOST,
                    settings.EMAIL_HOST_USER,
                    settings.EMAIL_HOST_PASSWORD,
                    settings.EMAIL_PORT,
                ]
                for variable in required_variables:
                    if not variable:
                        errors["SMTP backend"] = "configuration required"

    logger.info(f"Configuration errors: {errors}")
    if errors:
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
    return Response(status=status.HTTP_200_OK)


class LoginView(certego_views.LoginView):
    @staticmethod
    def validate_and_return_user(request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data["user"]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        uname = request.user.username
        logger.info(f"LoginView: received request from '{uname}'.")
        if request.user.is_superuser:
            try:
                # pass admin user's session
                login(request, request.user)
                logger.info(f"administrator:'{uname}' was logged in.")
            except Exception:
                logger.exception(f"administrator:'{uname}' login failed.")
        return response


class ChangePasswordView(APIView):
    """
    Handles changing user password.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [POSTUserRateThrottle]

    @staticmethod
    def post(request: Request) -> Response:
        """
        Handles POST request for changing user password.

        Args:
            request (Request): The request object containing old and new passwords.

        Returns:
            Response: The response object.
        """
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        new_password = serializer.validated_data["new_password"]

        # Set the new password for the user
        user.set_password(new_password)
        user.save()

        revoke_other_tokens(user=user, current_token=request.auth)

        # Return a success response
        return Response({"message": "Password changed successfully"})


class TokenSessionsViewSet(durin_views.TokenSessionsViewSet):
    @action(
        detail=False,
        methods=["delete"],
        url_path="others",
        authentication_classes=[CookieTokenAuthentication],
        permission_classes=[IsAuthenticated],
    )
    def revoke_others(self, request: Request) -> Response:
        revoke_other_tokens(user=request.user, current_token=request.auth)
        return Response(status=status.HTTP_204_NO_CONTENT)


APIAccessTokenView = durin_views.APIAccessTokenView
