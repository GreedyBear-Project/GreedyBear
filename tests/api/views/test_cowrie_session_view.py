from django.test import override_settings
from rest_framework.test import APIClient

from greedybear.models import CowrieSession
from tests import CustomTestCase


class CowrieSessionViewTestCase(CustomTestCase):
    """Test cases for the cowrie_session_view."""

    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    # # # # # Basic IP Query Test # # # # #
    def test_ip_address_query(self):
        """Test view with a valid IP address query."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_ip_address_query_with_similar(self):
        """Test view with a valid IP address query including similar sequences."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    def test_include_similar_excludes_non_positive_duration_sessions(self):
        """Test that include_similar only returns sessions with duration > 0."""
        CowrieSession.objects.create(
            session_id=int("dddddddddddd", 16),
            start_time=self.current_time,
            duration=0,
            login_attempt=True,
            command_execution=True,
            interaction_count=1,
            source=self.ioc_3,
            commands=self.command_sequence_2,
        )

        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true&include_session_data=true")

        self.assertEqual(response.status_code, 200)
        self.assertIn("99.99.99.99", response.data["sources"])
        self.assertNotIn("100.100.100.100", response.data["sources"])
        self.assertTrue(any(session["duration"] > 0 for session in response.data["sessions"]))
        self.assertFalse(any(session["source"] == "100.100.100.100" for session in response.data["sessions"]))

    def test_ip_address_query_with_credentials(self):
        """Test view with a valid IP address query including credentials."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)
        self.assertEqual(len(response.data["credentials"]), 1)
        self.assertEqual(response.data["credentials"][0], "root | root")

    def test_ip_address_query_with_sessions(self):
        """Test view with a valid IP address query including session data."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sessions"]), 1)
        self.assertIn("time", response.data["sessions"][0])
        self.assertEqual(response.data["sessions"][0]["duration"], 1.234)
        self.assertEqual(response.data["sessions"][0]["source"], "140.246.171.141")
        self.assertEqual(response.data["sessions"][0]["interactions"], 5)
        self.assertEqual(response.data["sessions"][0]["credentials"][0], "root | root")
        self.assertEqual(response.data["sessions"][0]["commands"], "cd foo\nls -la")

    def test_ip_address_query_with_all(self):
        """Test view with a valid IP address query including everything."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)

    # # # # # Basic Hash Query Test # # # # #
    def test_hash_query(self):
        """Test view with a valid hash query."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_hash_query_with_all(self):
        """Test view with a valid hash query including everything."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}&include_similar=true&include_credentials=true&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertIn("credentials", response.data)
        self.assertIn("sessions", response.data)
        self.assertEqual(len(response.data["sources"]), 2)

    # # # # # IP Address Validation Tests # # # # #
    def test_nonexistent_ip_address(self):
        """Test that view returns 404 for IP with no sequences."""
        response = self.client.get("/api/cowrie_session?query=10.0.0.1")
        self.assertEqual(response.status_code, 404)

    def test_ipv6_address_query(self):
        """Test view with a valid IPv6 address query."""
        response = self.client.get("/api/cowrie_session?query=2001:db8::1")
        self.assertEqual(response.status_code, 404)

    def test_invalid_ip_format(self):
        """Test that malformed IP addresses are treated as password lookups."""
        response = self.client.get("/api/cowrie_session?query=999.999.999.999")
        self.assertEqual(response.status_code, 404)

    def test_ip_with_cidr_notation(self):
        """Test that CIDR notation is treated as a password lookup."""
        response = self.client.get("/api/cowrie_session?query=192.168.1.0/24")
        self.assertEqual(response.status_code, 404)

    # # # # # Parameter Validation Tests # # # # #
    def test_missing_query_parameter(self):
        """Test that view returns BadRequest when query parameter is missing."""
        response = self.client.get("/api/cowrie_session")
        self.assertEqual(response.status_code, 400)

    def test_invalid_query_parameter(self):
        """Test that non-IP, non-hash queries are treated as password lookups."""
        response = self.client.get("/api/cowrie_session?query=invalid-input}")
        self.assertEqual(response.status_code, 404)

    def test_include_credentials_invalid_value(self):
        """Test that invalid boolean values raise validation error."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=maybe")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("credentials", response.data)

    def test_case_insensitive_boolean_parameters(self):
        """Test that boolean parameters accept various case formats."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=TRUE")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

        response = self.client.get("/api/cowrie_session?query=140.246.171.141&include_credentials=True")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)

    # # # # # Hash Validation Tests # # # # #
    def test_nonexistent_hash(self):
        """Test that view returns 404 for nonexistent hash."""
        response = self.client.get(f"/api/cowrie_session?query={'f' * 64}")
        self.assertEqual(response.status_code, 404)

    def test_hash_wrong_length(self):
        """Test that strings with incorrect hash length are treated as password lookups."""
        response = self.client.get("/api/cowrie_session?query=" + "a" * 32)  # 32 chars instead of 64
        self.assertEqual(response.status_code, 404)

    def test_hash_invalid_characters(self):
        """Test that strings with invalid hash characters are treated as password lookups."""
        invalid_hash = "g" * 64  # 'g' is not a valid hex character
        response = self.client.get(f"/api/cowrie_session?query={invalid_hash}")
        self.assertEqual(response.status_code, 404)

    def test_hash_case_insensitive(self):
        """Test that hash queries are case-insensitive."""
        response_lower = self.client.get(f"/api/cowrie_session?query={self.hash.lower()}")
        response_upper = self.client.get(f"/api/cowrie_session?query={self.hash.upper()}")
        self.assertEqual(response_lower.status_code, response_upper.status_code)

    # # # # # Special Characters & Encoding Tests # # # # #
    def test_query_with_url_encoding(self):
        """Test that URL-encoded queries work correctly."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141%20")
        # Should either work or return 400, not crash
        self.assertIn(response.status_code, [200, 400, 404])

    # # # # # License Tests # # # # #
    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_ip_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_ip_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_hash_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_hash_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get(f"/api/cowrie_session?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    def test_query_with_special_characters(self):
        """Test that queries with special characters are treated as password lookups."""
        response = self.client.get("/api/cowrie_session?query=<script>alert('xss')</script>")
        self.assertEqual(response.status_code, 404)

    # # # # # Authentication & Authorization Tests # # # # #
    def test_unauthenticated_request(self):
        """Test that unauthenticated requests are rejected."""
        client = APIClient()  # No authentication
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 401)

    def test_regular_user_access(self):
        """Test that regular (non-superuser) authenticated users can access."""
        client = APIClient()
        client.force_authenticate(user=self.regular_user)
        response = client.get("/api/cowrie_session?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)

    # # # # # Password Query Tests # # # # #
    def test_password_query(self):
        """Test view with a valid password query."""
        response = self.client.get("/api/cowrie_session?query=root")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)
        self.assertNotIn("credentials", response.data)
        self.assertNotIn("sessions", response.data)

    def test_password_query_with_credentials(self):
        """Test password query including credentials."""
        response = self.client.get("/api/cowrie_session?query=root&include_credentials=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("credentials", response.data)
        self.assertEqual(response.data["credentials"][0], "root | root")

    def test_nonexistent_password(self):
        """Test that view returns 404 for password with no matching sessions."""
        response = self.client.get("/api/cowrie_session?query=nonexistentpassword123")
        self.assertEqual(response.status_code, 404)

    def test_password_query_with_similar(self):
        """Test password query including similar sessions."""
        response = self.client.get("/api/cowrie_session?query=root&include_similar=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("query", response.data)
        self.assertIn("commands", response.data)
        self.assertIn("sources", response.data)

    def test_password_query_with_session_data(self):
        """Test password query including session data."""
        response = self.client.get("/api/cowrie_session?query=root&include_session_data=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sessions", response.data)
        self.assertEqual(response.data["sessions"][0]["source"], "140.246.171.141")
        self.assertEqual(response.data["sessions"][0]["credentials"][0], "root | root")

    def test_password_too_long(self):
        """Test that passwords exceeding max length return 400."""
        response = self.client.get(f"/api/cowrie_session?query={'a' * 257}")
        self.assertEqual(response.status_code, 400)
