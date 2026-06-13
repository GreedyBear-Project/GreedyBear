from tests import CustomTestCase


class RequestLoggingMixinTestCase(CustomTestCase):
    """Tests for the shared RequestLoggingMixin as wired into the feed endpoints."""

    LOGGER = "api.mixins"

    def test_logs_method_route_pattern_and_params(self):
        with self.assertLogs(self.LOGGER, level="INFO") as logs:
            self.client.get("/api/feeds/all/all/recent.json?ioc_type=ip")
        self.assertEqual(len(logs.output), 1)
        line = logs.output[0]
        self.assertIn("request GET", line)
        self.assertIn("api/feeds/<str:feed_type>/<str:attack_type>/<str:prioritize>.<str:format_>", line)
        self.assertIn("'ioc_type': 'ip'", line)

    def test_excludes_reason_param_from_log(self):
        with self.assertLogs(self.LOGGER, level="INFO") as logs:
            response = self.client.get("/api/feeds/share?reason=super-secret-note&ioc_type=ip")
        self.assertIn(response.status_code, (401, 403))
        line = logs.output[0]
        self.assertNotIn("super-secret-note", line)
        self.assertNotIn("reason", line)
        self.assertIn("'ioc_type': 'ip'", line)

    def test_does_not_leak_share_token_carried_in_path(self):
        secret_token = "extremely-secret-token-value"
        with self.assertLogs(self.LOGGER, level="INFO") as logs:
            self.client.get(f"/api/feeds/consume/{secret_token}")
        line = logs.output[0]
        self.assertNotIn(secret_token, line)
        self.assertIn("api/feeds/consume/<str:token>", line)
