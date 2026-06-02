from rest_framework.throttling import SimpleRateThrottle


class LoginIPThrottle(SimpleRateThrottle):
    """Rate-limit login attempts from the same IP address."""

    scope = "login"

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class LoginIdentifierThrottle(SimpleRateThrottle):
    """Rate-limit login attempts against the same username or email."""

    scope = "login"

    def get_cache_key(self, request, view):
        identifier = request.data.get("username") or request.data.get("email")
        if not isinstance(identifier, str):
            return None

        normalized = identifier.strip().lower()
        if not normalized:
            return None

        return self.cache_format % {
            "scope": self.scope,
            "ident": normalized,
        }
