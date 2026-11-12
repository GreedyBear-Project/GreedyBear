from tests import CustomTestCase


class QueryParamValidationMixinTestCase(CustomTestCase):
    """Tests for the shared QueryParamValidationMixin as wired into the honeypot and feed endpoints."""

    def test_rejects_unknown_param_and_names_it(self):
        response = self.client.get("/api/honeypot/?foo=bar")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"], {"foo": ["Unknown query parameter."]})

    def test_names_every_unknown_param(self):
        response = self.client.get("/api/honeypot/?foo=1&bar=2")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(set(response.json()["errors"]), {"foo", "bar"})

    def test_known_param_does_not_hide_unknown_one(self):
        response = self.client.get("/api/honeypot/?only_active=true&foo=bar")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"], {"foo": ["Unknown query parameter."]})

    def test_accepts_page_params_when_view_paginates(self):
        response = self.client.get("/api/feeds/?page=1&page_size=5")
        self.assertEqual(response.status_code, 200)

    def test_rejects_page_params_when_view_does_not_paginate(self):
        response = self.client.get("/api/feeds/all/all/recent.json?page=2")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"], {"page": ["Unknown query parameter."]})

    def test_unsupported_method_gets_405_instead_of_param_error(self):
        response = self.client.post("/api/honeypot/?foo=bar")
        self.assertEqual(response.status_code, 405)

    def test_auth_check_runs_before_param_check(self):
        response = self.client.get("/api/feeds/advanced/?foo=bar")
        self.assertEqual(response.status_code, 401)
