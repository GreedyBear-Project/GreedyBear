# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.apps import AppConfig
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class CookieTokenAuthScheme(OpenApiAuthenticationExtension):
    """Tell drf-spectacular how to represent GreedyBear's CSRF-aware
    CookieTokenAuthentication subclass as an OpenAPI security scheme, so
    authenticated endpoints document the Token header (and get an
    "Authorize" entry in Swagger UI)."""

    # Keep this in sync if api.authentication.CSRFProtectedCookieTokenAuthentication is ever renamed or replaced.
    target_class = "api.authentication.CSRFProtectedCookieTokenAuthentication"
    name = "tokenAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Durin token auth. Use header `Authorization: Token <key>`.",
        }


class ApiConfig(AppConfig):
    name = "api"
