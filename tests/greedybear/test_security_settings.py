# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import importlib
import os
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase


class SecuritySettingsTests(SimpleTestCase):
    def test_content_type_nosniff_enabled(self):
        """SECURE_CONTENT_TYPE_NOSNIFF should always be True."""
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_x_frame_options_deny(self):
        """X_FRAME_OPTIONS should be DENY to block all framing."""
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")

    def test_ssl_redirect_not_set(self):
        """SECURE_SSL_REDIRECT must not be enabled (TLS terminates at nginx)."""
        self.assertFalse(getattr(settings, "SECURE_SSL_REDIRECT", False))

    def test_cookie_security_matches_environment(self):
        """Cookies should only be marked secure when HTTPS is enabled."""
        https_enabled = getattr(settings, "HTTPS_ENABLED", False)

        # Test SESSION_COOKIE_SECURE
        session_secure = getattr(settings, "SESSION_COOKIE_SECURE", False)
        self.assertEqual(session_secure, https_enabled)

        # Test CSRF_COOKIE_SECURE
        csrf_secure = getattr(settings, "CSRF_COOKIE_SECURE", False)
        self.assertEqual(csrf_secure, https_enabled)


class HttpsEnabledGatingTests(SimpleTestCase):
    @classmethod
    def tearDownClass(cls):
        # Restore the settings module
        import greedybear.settings

        importlib.reload(greedybear.settings)
        super().tearDownClass()

    @staticmethod
    def _reload_with(https_enabled):
        import greedybear.settings

        for attr in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE"):
            if hasattr(greedybear.settings, attr):
                delattr(greedybear.settings, attr)
        with mock.patch.dict(os.environ):
            if https_enabled is None:
                os.environ.pop("HTTPS_ENABLED", None)
            else:
                os.environ["HTTPS_ENABLED"] = https_enabled
            importlib.reload(greedybear.settings)
            return greedybear.settings

    def test_http_deployment_leaves_secure_cookies_off(self):
        """HTTPS_ENABLED=False must NOT set Secure flag."""
        mod = self._reload_with(https_enabled="False")
        self.assertFalse(mod.HTTPS_ENABLED)
        self.assertFalse(getattr(mod, "SESSION_COOKIE_SECURE", False))
        self.assertFalse(getattr(mod, "CSRF_COOKIE_SECURE", False))

    def test_https_deployment_sets_secure_cookies(self):
        """HTTPS_ENABLED=True must mark session and CSRF cookies as Secure."""
        mod = self._reload_with(https_enabled="True")
        self.assertTrue(mod.HTTPS_ENABLED)
        self.assertTrue(mod.SESSION_COOKIE_SECURE)
        self.assertTrue(mod.CSRF_COOKIE_SECURE)

    def test_https_enabled_defaults_to_off(self):
        """An unset HTTPS_ENABLED env var defaults to HTTP-only behaviour."""
        mod = self._reload_with(https_enabled=None)
        self.assertFalse(mod.HTTPS_ENABLED)
        self.assertFalse(getattr(mod, "SESSION_COOKIE_SECURE", False))
        self.assertFalse(getattr(mod, "CSRF_COOKIE_SECURE", False))
