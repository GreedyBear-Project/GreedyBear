# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.apps import AppConfig
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class CookieTokenAuthScheme(OpenApiAuthenticationExtension):
    """Tell drf-spectacular how to represent certego-saas' CookieTokenAuthentication
    as an OpenAPI security scheme, so authenticated endpoints document the Token
    header (and get an "Authorize" entry in Swagger UI)."""

    target_class = "certego_saas.apps.auth.backend.CookieTokenAuthentication"
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
