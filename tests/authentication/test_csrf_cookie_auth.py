# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from durin.models import AuthToken, Client
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APITestCase

User = get_user_model()

login_uri = reverse("auth_login")
logout_uri = "/api/auth/logout"
check_authentication_uri = "/api/auth/authentication"
dashboard_config_uri = "/api/dashboard-config/"
share_uri = "/api/feeds/share"

VALID_LAYOUT = {"layout": {"widgetConfigs": [], "layouts": {}}}


class CSRFCookieAuthTestCase(APITestCase):
    """Covers CSRFProtectedCookieTokenAuthentication end to end: cookie-origin
    requests must carry a matching X-CSRFToken on unsafe methods, Authorization-header
    (API token) clients are unaffected, and safe methods are never checked.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.superuser = User.objects.create_superuser("csrf_test_superuser", "csrf_test_superuser@example.com", "hunter2")
        cls.regular_user = User.objects.create_user("csrf_test_user", "csrf_test_user@example.com", "hunter2")

    @classmethod
    def tearDownClass(cls):
        cls.superuser.delete()
        cls.regular_user.delete()
        super().tearDownClass()

    def setUp(self):
        # The default APIClient silently bypasses CSRF validation (it marks every
        # request as already-checked). enforce_csrf_checks=True is required for these
        # tests to actually exercise CsrfViewMiddleware/CSRFCheck, the same way a real
        # browser request would be validated.
        self.client = APIClient(enforce_csrf_checks=True)

    def tearDown(self):
        cache.clear()

    def _login_with_cookie(self, username="csrf_test_superuser", password="hunter2"):
        """Log in with real credentials so the client carries the real auth cookie,
        the same way a browser does - not via force_authenticate()."""
        response = self.client.post(login_uri, {"username": username, "password": password})
        assert response.status_code == 200, response.content
        return response

    def test_cookie_post_without_csrf_token_returns_403(self):
        self._login_with_cookie()
        # mirrors the frontend's startup call, which sets the csrftoken cookie
        self.client.get(check_authentication_uri)

        response = self.client.put(dashboard_config_uri, VALID_LAYOUT, format="json")

        self.assertEqual(response.status_code, 403, msg=response.content)
        self.assertIn("CSRF Failed", response.json()["detail"])

    def test_cookie_post_with_csrf_token_header_succeeds(self):
        self._login_with_cookie()
        self.client.get(check_authentication_uri)
        csrf_token = self.client.cookies["csrftoken"].value

        response = self.client.put(dashboard_config_uri, VALID_LAYOUT, format="json", HTTP_X_CSRFTOKEN=csrf_token)

        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_authorization_token_post_without_csrf_succeeds(self):
        token = AuthToken.objects.create(user=self.superuser, client=Client.objects.create(name="csrf-test-api-client"))
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.token}")

        response = self.client.post(share_uri)

        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_cookie_get_is_unaffected_by_csrf(self):
        self._login_with_cookie()
        # deliberately not calling check_authentication: no csrftoken cookie exists,
        # and a safe method must not require one anyway

        response = self.client.get(dashboard_config_uri)

        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_non_superuser_login_sets_csrftoken_cookie(self):
        response = self._login_with_cookie("csrf_test_user", "hunter2")

        self.assertIn("csrftoken", response.cookies)

    def test_non_superuser_logout_with_csrf_token_succeeds(self):
        self._login_with_cookie("csrf_test_user", "hunter2")
        csrf_token = self.client.cookies["csrftoken"].value

        response = self.client.post(logout_uri, HTTP_X_CSRFTOKEN=csrf_token)

        self.assertEqual(response.status_code, 204, msg=response.content)

    def test_non_superuser_logout_without_csrf_token_returns_403(self):
        self._login_with_cookie("csrf_test_user", "hunter2")

        response = self.client.post(logout_uri)

        self.assertEqual(response.status_code, 403, msg=response.content)

    def test_frontend_route_sets_csrftoken_cookie(self):
        # index.html is a frontend build artifact and is not present in the test
        # environment, so a temp template dir stands in for it rather than adding
        # a real one to the repo.
        with tempfile.TemporaryDirectory() as tmp_dir:
            Path(tmp_dir, "index.html").write_text("<html></html>")
            template_settings = [{**settings.TEMPLATES[0], "DIRS": [tmp_dir, *settings.TEMPLATES[0]["DIRS"]]}]
            with override_settings(TEMPLATES=template_settings):
                response = self.client.get("/")

        self.assertEqual(response.status_code, 200, msg=response.content)
        self.assertIn("csrftoken", response.cookies)
