# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import importlib
import os
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

SHA256_FINGERPRINT = ":".join(["AB"] * 32)


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


class SettingsWithoutElasticsearchTestCase(SimpleTestCase):
    """Settings must load without Elasticsearch, even in production mode."""

    def test_settings_load_without_elastic_endpoint(self):
        """Missing ELASTIC_ENDPOINT must only warn, never exit the application."""
        import io
        from contextlib import redirect_stdout

        import greedybear.settings as greedybear_settings

        # restore the original module state after the test
        self.addCleanup(importlib.reload, greedybear_settings)

        with mock.patch.dict("os.environ", {"ELASTIC_ENDPOINT": "", "DEBUG": "False"}):
            captured = io.StringIO()
            with redirect_stdout(captured):
                # raises SystemExit if the settings module still calls exit()
                reloaded = importlib.reload(greedybear_settings)

        self.assertIsNone(reloaded.ELASTIC_CLIENT)
        self.assertIn("WARNING", captured.getvalue())

    def test_settings_load_with_elastic_endpoint_keeps_client(self):
        """A configured ELASTIC_ENDPOINT must still create the Elasticsearch client."""
        import greedybear.settings as greedybear_settings

        self.addCleanup(importlib.reload, greedybear_settings)

        with mock.patch.dict("os.environ", {"ELASTIC_ENDPOINT": "http://localhost:9200", "ENVIRONMENT": "local"}):
            reloaded = importlib.reload(greedybear_settings)

        self.assertIsNotNone(reloaded.ELASTIC_CLIENT)

    def test_cert_fingerprint_pins_https_elastic_endpoint(self):
        """TPOT_CERT_FINGERPRINT must be pinned for an HTTPS Elasticsearch endpoint."""
        import greedybear.settings as greedybear_settings

        self.addCleanup(importlib.reload, greedybear_settings)

        env = {"ELASTIC_ENDPOINT": "https://tpot-host:64297/es/", "ENVIRONMENT": "local", "TPOT_CERT_FINGERPRINT": SHA256_FINGERPRINT}
        with mock.patch.dict("os.environ", env):
            reloaded = importlib.reload(greedybear_settings)

        node = reloaded.ELASTIC_CLIENT.transport.node_pool.all()[0]
        self.assertEqual(node.config.ssl_assert_fingerprint, SHA256_FINGERPRINT)

    def test_cert_fingerprint_ignored_for_http_elastic_endpoint(self):
        """A plain HTTP endpoint has no certificate to pin, so the fingerprint must not break the client."""
        import greedybear.settings as greedybear_settings

        self.addCleanup(importlib.reload, greedybear_settings)

        # The fingerprint may still be set for the payload server.
        env = {"ELASTIC_ENDPOINT": "http://tpot-host:64298", "ENVIRONMENT": "local", "TPOT_CERT_FINGERPRINT": SHA256_FINGERPRINT}
        with mock.patch.dict("os.environ", env):
            # the client raises ValueError if TLS options are set for an HTTP endpoint
            reloaded = importlib.reload(greedybear_settings)

        node = reloaded.ELASTIC_CLIENT.transport.node_pool.all()[0]
        self.assertIsNone(node.config.ssl_assert_fingerprint)
