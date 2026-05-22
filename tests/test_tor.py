from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.repositories.tor import TorRepository
from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron
from greedybear.enums import IpReputation
from tests import CustomTestCase


class TestTorRepository(CustomTestCase):
    """Test cases for TorRepository."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo = TorRepository()

    @patch("greedybear.models.TorExitNode.objects.get_or_create")
    def test_get_or_create_new_tor_node(self, mock_get_or_create):
        """Test creating a new Tor exit node entry."""
        # Arrange
        mock_node = Mock()
        mock_get_or_create.return_value = (mock_node, True)

        # Act
        _, created = self.repo.get_or_create("1.2.3.4")

        # Assert
        self.assertTrue(created)
        mock_get_or_create.assert_called_once_with(ip_address="1.2.3.4", defaults={"reason": IpReputation.TOR_EXIT_NODE})

    @patch("greedybear.models.TorExitNode.objects.get_or_create")
    def test_get_or_create_existing_tor_node(self, mock_get_or_create):
        """Test getting an existing Tor exit node entry."""
        # Arrange
        mock_node = Mock()
        mock_get_or_create.return_value = (mock_node, False)

        # Act
        _, created = self.repo.get_or_create("1.2.3.4")

        # Assert
        self.assertFalse(created)


class TestTorExitNodesCron(CustomTestCase):
    """Test cases for TorExitNodesCron."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_tor_repo = Mock()
        self.mock_ioc_repo = Mock()
        self.cron = TorExitNodesCron(tor_repo=self.mock_tor_repo, ioc_repo=self.mock_ioc_repo)

    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    @patch("greedybear.cronjobs.tor_exit_nodes.is_valid_ipv4")
    def test_run_success(self, mock_is_valid, mock_requests_get):
        """Test successful Tor exit nodes fetching."""
        # Arrange
        mock_response = Mock()
        mock_response.text = "ExitAddress 1.2.3.4\\nExitAddress 5.6.7.8"
        mock_requests_get.return_value = mock_response

        # Mock validation to return valid for both IPs
        mock_is_valid.side_effect = [(True, "1.2.3.4"), (True, "5.6.7.8")]

        # Mock repository to return created=True
        self.mock_tor_repo.get_or_create.side_effect = [(Mock(), True), (Mock(), True)]

        # Act
        self.cron.run()

        # Assert
        mock_requests_get.assert_called_once_with("https://check.torproject.org/exit-addresses", timeout=10)
        self.assertEqual(self.mock_tor_repo.get_or_create.call_count, 2)
        self.assertEqual(self.mock_ioc_repo.update_ioc_reputation.call_count, 2)

    @patch("greedybear.cronjobs.tor_exit_nodes.requests.get")
    def test_run_request_failure(self, mock_requests_get):
        """Test handling of request failures."""
        # Arrange
        mock_requests_get.side_effect = requests.RequestException("Network error")

        # Act & Assert
        with self.assertRaises(requests.RequestException):
            self.cron.run()
