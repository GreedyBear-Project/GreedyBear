from django.test import override_settings
from rest_framework.test import APIClient

from tests import CustomTestCase


class CommandSequenceViewTestCase(CustomTestCase):
    """Test cases for the command_sequence_view."""

    def setUp(self):
        # setup client
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_missing_query_parameter(self):
        """Test that view returns BadRequest when query parameter is missing."""
        response = self.client.get("/api/command_sequence")
        self.assertEqual(response.status_code, 400)

    def test_invalid_query_parameter(self):
        """Test that view returns BadRequest when query parameter is invalid."""
        response = self.client.get("/api/command_sequence?query=invalid-input}")
        self.assertEqual(response.status_code, 400)

    def test_ip_address_query(self):
        """Test view with a valid IP address query."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("executed_commands", response.data)
        self.assertIn("executed_by", response.data)

    def test_ip_address_query_with_similar(self):
        """Test view with a valid IP address query including similar sequences."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141&include_similar")
        self.assertEqual(response.status_code, 200)
        self.assertIn("executed_commands", response.data)
        self.assertIn("executed_by", response.data)

    def test_include_similar_preserves_base_results(self):
        """Test that include_similar extends executed_by instead of replacing it."""
        # Get base results without include_similar
        base_response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(base_response.status_code, 200)
        base_executed_by = set(base_response.data["executed_by"])

        # Get results with include_similar
        similar_response = self.client.get("/api/command_sequence?query=140.246.171.141&include_similar")
        self.assertEqual(similar_response.status_code, 200)
        similar_executed_by = set(similar_response.data["executed_by"])

        # include_similar should be a superset of base results, never lose them
        self.assertTrue(
            base_executed_by.issubset(similar_executed_by),
            f"include_similar lost base results: {base_executed_by - similar_executed_by}",
        )

    def test_include_similar_with_unclustered_sequences(self):
        """Test that include_similar still returns results when sequences have no cluster."""
        # Remove cluster from the command sequence
        self.command_sequence.cluster = None
        self.command_sequence.save()

        base_response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(base_response.status_code, 200)

        similar_response = self.client.get("/api/command_sequence?query=140.246.171.141&include_similar")
        self.assertEqual(similar_response.status_code, 200)

        # When no clusters exist, include_similar should still return the base results
        self.assertEqual(
            base_response.data["executed_by"],
            similar_response.data["executed_by"],
        )

    def test_nonexistent_ip_address(self):
        """Test that view returns 404 for IP with no sequences."""
        response = self.client.get("/api/command_sequence?query=10.0.0.1")
        self.assertEqual(response.status_code, 404)

    def test_hash_query(self):
        """Test view with a valid hash query."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("commands", response.data)
        self.assertIn("iocs", response.data)

    def test_uppercase_hash_query(self):
        """Uppercase hash in the query should resolve to the same sequence."""
        response = self.client.get(f"/api/command_sequence?query={self.hash.upper()}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["commands"], ["\n".join(self.cmd_seq)])

    def test_mixed_case_hash_query(self):
        """Mixed case should work too, not just all uppercase."""
        mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(self.hash))
        response = self.client.get(f"/api/command_sequence?query={mixed}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["commands"], ["\n".join(self.cmd_seq)])

    def test_hash_query_with_similar(self):
        """Test view with a valid hash query including similar sequences."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}&include_similar")
        self.assertEqual(response.status_code, 200)
        self.assertIn("commands", response.data)
        self.assertIn("iocs", response.data)

    def test_nonexistent_hash(self):
        """Test that view returns 404 for nonexistent hash."""
        response = self.client.get(f"/api/command_sequence?query={'f' * 64}")
        self.assertEqual(response.status_code, 404)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_ip_address_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_ip_address_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get("/api/command_sequence?query=140.246.171.141")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_hash_query_with_license(self):
        """Test that license is included when FEEDS_LICENSE is populated."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("license", response.data)
        self.assertEqual(response.data["license"], "https://example.com/license")

    @override_settings(FEEDS_LICENSE="")
    def test_hash_query_without_license(self):
        """Test that license is not included when FEEDS_LICENSE is empty."""
        response = self.client.get(f"/api/command_sequence?query={self.hash}")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("license", response.data)
