# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from certego_saas.apps.auth.backend import TOKEN_COOKIE_NAME
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APITestCase

User = get_user_model()

login_uri = reverse("auth_login")
sessions_uri = "/api/auth/sessions"
apiaccess_uri = "/api/auth/apiaccess"
logout_uri = "/api/auth/logout"

# every endpoint+method that used to answer an anonymous request with a 500 or a 404
ANONYMOUS_REQUESTS = [
    ("get", sessions_uri),
    ("delete", f"{sessions_uri}/1"),
    ("delete", f"{sessions_uri}/others"),
    ("get", apiaccess_uri),
    ("post", apiaccess_uri),
    ("delete", apiaccess_uri),
    ("post", logout_uri),
]


class AnonymousAuthEndpointsTestCase(APITestCase):
    """Anonymous requests to the auth endpoints must get exactly 401, and the
    authenticated path must keep working with a real login cookie."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = User.objects.create_user("anon_auth_test_user", "anon_auth_test_user@example.com", "hunter2")

    @classmethod
    def tearDownClass(cls):
        cls.user.delete()
        super().tearDownClass()

    def setUp(self):
        # enforce_csrf_checks=True: unsafe cookie requests must carry X-CSRFToken, like a browser's
        self.client = APIClient(enforce_csrf_checks=True)

    def tearDown(self):
        cache.clear()

    def _login(self):
        """Real login, so the client carries the auth cookie. Returns the CSRF token."""
        response = self.client.post(login_uri, {"username": "anon_auth_test_user", "password": "hunter2"})
        assert response.status_code == 200, response.content
        return self.client.cookies["csrftoken"].value

    def test_anonymous_requests_return_401(self):
        for method, uri in ANONYMOUS_REQUESTS:
            with self.subTest(method=method, uri=uri):
                response = getattr(self.client, method)(uri)

                self.assertEqual(response.status_code, 401, msg=response.content)

    def test_sessions_list_authenticated_returns_200(self):
        self._login()

        response = self.client.get(sessions_uri)

        self.assertEqual(response.status_code, 200, msg=response.content)

    def test_apiaccess_create_get_delete_authenticated(self):
        csrf_token = self._login()

        created = self.client.post(apiaccess_uri, HTTP_X_CSRFTOKEN=csrf_token)
        fetched = self.client.get(apiaccess_uri)
        deleted = self.client.delete(apiaccess_uri, HTTP_X_CSRFTOKEN=csrf_token)

        self.assertEqual(created.status_code, 201, msg=created.content)
        self.assertEqual(fetched.status_code, 200, msg=fetched.content)
        self.assertEqual(deleted.status_code, 204, msg=deleted.content)

    def test_logout_authenticated_returns_204_and_clears_auth_cookie(self):
        csrf_token = self._login()

        response = self.client.post(logout_uri, HTTP_X_CSRFTOKEN=csrf_token)

        self.assertEqual(response.status_code, 204, msg=response.content)
        # only certego_saas' LogoutView deletes the cookie; durin's does not
        cookie = response.cookies[TOKEN_COOKIE_NAME]
        self.assertEqual(cookie.value, "")
        self.assertEqual(cookie["max-age"], 0)
