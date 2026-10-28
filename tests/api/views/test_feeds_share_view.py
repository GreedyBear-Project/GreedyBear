from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import ShareToken
from tests import CustomTestCase


class FeedsShareReasonTestCase(CustomTestCase):
    """Tests for the optional ?reason= parameter on POST /api/feeds/share."""

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_share_without_reason(self):
        """When no reason is supplied, ShareToken.reason defaults to empty string."""
        response = self.client.post("/api/feeds/share")
        self.assertEqual(response.status_code, 200)

        token_hash = self._hash_from_url(response.json()["url"])
        share_token = ShareToken.objects.get(token_hash=token_hash)
        self.assertEqual(share_token.reason, "")

    def test_share_with_reason(self):
        """When ?reason=... is supplied, it is persisted on the ShareToken."""
        response = self.client.post("/api/feeds/share?reason=monthly+report")
        self.assertEqual(response.status_code, 200)

        token_hash = self._hash_from_url(response.json()["url"])
        share_token = ShareToken.objects.get(token_hash=token_hash)
        self.assertEqual(share_token.reason, "monthly report")

    def test_share_reason_truncated_at_256_chars(self):
        """A reason longer than 256 characters is silently truncated."""
        long_reason = "x" * 300
        response = self.client.post(f"/api/feeds/share?reason={long_reason}")
        self.assertEqual(response.status_code, 200)

        token_hash = self._hash_from_url(response.json()["url"])
        share_token = ShareToken.objects.get(token_hash=token_hash)
        self.assertEqual(len(share_token.reason), 256)

    def test_share_reason_only_set_on_create(self):
        """get_or_create: when the same token already exists, reason is NOT overwritten."""
        r1 = self.client.post("/api/feeds/share?reason=first")
        self.assertEqual(r1.status_code, 200)

        # Same feed params → same signed token → get_or_create returns existing record
        r2 = self.client.post("/api/feeds/share?reason=second")
        self.assertEqual(r2.status_code, 200)

        # Both calls must have produced the exact same token/URL
        self.assertEqual(r1.json()["url"], r2.json()["url"])

        # Only one ShareToken should exist (not two)
        token_hash = self._hash_from_url(r1.json()["url"])
        self.assertEqual(ShareToken.objects.filter(token_hash=token_hash).count(), 1)

        share_token = ShareToken.objects.get(token_hash=token_hash)
        self.assertEqual(share_token.reason, "first")

    def test_get_method_not_allowed(self):
        """GET is no longer accepted on the share endpoint; it must be POSTed."""
        response = self.client.get("/api/feeds/share")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    # ── helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_from_url(url):
        import hashlib

        raw_token = url.split("/api/feeds/consume/")[1]
        return hashlib.sha256(raw_token.encode()).hexdigest()


class FeedsTokensListTestCase(CustomTestCase):
    """Tests for GET /api/feeds/tokens/ — lists the calling user's share tokens."""

    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_empty_list(self):
        """A user with no tokens gets an empty JSON list."""
        response = self.client.get("/api/feeds/tokens/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_list_rejects_query_params(self):
        """The token list takes no query params, so any query param is rejected."""
        response = self.client.get("/api/feeds/tokens/?reason=x")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"], {"reason": ["Unknown query parameter."]})

    def test_list_returns_own_tokens(self):
        """After creating two tokens, the list endpoint returns both."""
        self.client.post("/api/feeds/share?reason=alpha")
        self.client.post("/api/feeds/share?reason=beta&asn=11111")
        response = self.client.get("/api/feeds/tokens/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)

        reasons = {t["reason"] for t in data}
        self.assertEqual(reasons, {"alpha", "beta"})

    def test_list_returns_only_own_tokens(self):
        """Tokens created by another user are NOT visible."""
        self.client.post("/api/feeds/share?reason=superuser-token")

        other_client = APIClient()
        other_client.force_authenticate(user=self.regular_user)
        other_client.post("/api/feeds/share?reason=regular-token&asn=22222")

        # superuser sees only their own
        response = self.client.get("/api/feeds/tokens/")
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["reason"], "superuser-token")

        # regular_user sees only their own
        response = other_client.get("/api/feeds/tokens/")
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["reason"], "regular-token")

    def test_hash_prefix_not_full_hash(self):
        """The response exposes only the first 12 chars of the hash."""
        self.client.post("/api/feeds/share?reason=test")
        response = self.client.get("/api/feeds/tokens/")
        data = response.json()
        self.assertEqual(len(data[0]["hash_prefix"]), 12)

    def test_token_metadata_fields(self):
        """Each token entry contains the expected metadata keys."""
        self.client.post("/api/feeds/share?reason=check-fields")
        response = self.client.get("/api/feeds/tokens/")
        token = response.json()[0]
        expected_keys = {"hash_prefix", "reason", "created_at", "revoked", "revoked_at"}
        self.assertEqual(set(token.keys()), expected_keys)
        self.assertFalse(token["revoked"])
        self.assertIsNone(token["revoked_at"])

    def test_revoked_token_shows_status(self):
        """After revocation, the token list reflects revoked=True."""
        share = self.client.post("/api/feeds/share?reason=to-revoke")
        raw_token = share.json()["url"].split("/api/feeds/consume/")[1]
        self.client.post(f"/api/feeds/revoke/{raw_token}")

        response = self.client.get("/api/feeds/tokens/")
        token = response.json()[0]
        self.assertTrue(token["revoked"])
        self.assertIsNotNone(token["revoked_at"])

    def test_unauthenticated_returns_401_or_403(self):
        """Unauthenticated requests are rejected."""
        anon = APIClient()
        response = anon.get("/api/feeds/tokens/")
        self.assertIn(response.status_code, [401, 403])

    def test_list_ordering_newest_first(self):
        """Tokens are returned newest-first (descending created_at)."""
        self.client.post("/api/feeds/share?reason=first")
        self.client.post("/api/feeds/share?reason=second&asn=22222")
        response = self.client.get("/api/feeds/tokens/")
        data = response.json()
        self.assertEqual(data[0]["reason"], "second")
        self.assertEqual(data[1]["reason"], "first")

    def test_revoke_get_method_not_allowed(self):
        """GET is no longer accepted on the revoke endpoint; it must be POSTed."""
        share = self.client.post("/api/feeds/share?reason=to-revoke")
        raw_token = share.json()["url"].split("/api/feeds/consume/")[1]
        response = self.client.get(f"/api/feeds/revoke/{raw_token}")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
