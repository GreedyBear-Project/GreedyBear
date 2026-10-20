# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from certego_saas.apps.auth.backend import TOKEN_COOKIE_NAME, CookieTokenAuthentication
from rest_framework import exceptions
from rest_framework.authentication import CSRFCheck
from rest_framework.permissions import SAFE_METHODS
from rest_framework.request import Request


class CSRFProtectedCookieTokenAuthentication(CookieTokenAuthentication):
    """CookieTokenAuthentication, plus Django's CSRF check — but only when the
    token actually came from the cookie, and only for unsafe methods.

    API-token clients (Authorization: Token ...) are unaffected: the cookie
    and the header are mutually exclusive request shapes, so a token client's
    request never carries TOKEN_COOKIE_NAME in request.COOKIES.
    """

    def authenticate(self, request: Request):
        authenticated_via_cookie = TOKEN_COOKIE_NAME in request.COOKIES
        result = super().authenticate(request)
        if result is not None and authenticated_via_cookie and request.method not in SAFE_METHODS:
            self._enforce_csrf(request)
        return result

    @staticmethod
    def _enforce_csrf(request: Request) -> None:
        # Mirrors DRF's own SessionAuthentication.enforce_csrf: CSRFCheck's get_response
        # callback is required by CsrfViewMiddleware's constructor but never actually
        # invoked here, since only process_request()/process_view() are called directly.
        check = CSRFCheck(lambda r: None)  # ty: ignore[invalid-argument-type]
        check.process_request(request)
        reason = check.process_view(request, None, (), {})  # ty: ignore[invalid-argument-type]
        if reason:
            raise exceptions.PermissionDenied(f"CSRF Failed: {reason}")
