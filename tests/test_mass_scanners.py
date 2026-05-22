from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.mass_scanners import MassScannersCron
from greedybear.models import MassScanner

from . import CustomTestCase


class TestMassScannersCron(CustomTestCase):
    def setUp(self):
        self.cron = MassScannersCron()
        self.cron.log = Mock()

    def _create_mock_response(self, lines):
        """Create a mock response object that iter_lines() can use."""
        mock_response = Mock()
        mock_response.iter_lines.return_value = [line.encode("utf-8") for line in lines]
        return mock_response

    def test_parses_ip_with_comment(self):
        """Test parsing IP address with comment after #"""
        lines = ["192.168.1.100 # normal comment"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # Should create a mass scanner entry
        scanner = MassScanner.objects.get(ip_address="192.168.1.100")
        self.assertEqual(scanner.reason, "normal comment")
        self.cron.log.info.assert_called_once()

    def test_parses_plain_ip_without_comment(self):
        """Test parsing plain IP address without any comment"""
        lines = ["45.83.67.252"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # Should create entry with empty reason
        scanner = MassScanner.objects.get(ip_address="45.83.67.252")
        self.assertEqual(scanner.reason, "")
        self.cron.log.info.assert_called_once()

    def test_parses_ip_with_multiple_hash_signs(self):
        """Test parsing IP with comment containing # symbols"""
        lines = ["1.1.1.1 # comment with # spaces"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        scanner = MassScanner.objects.get(ip_address="1.1.1.1")
        self.assertEqual(scanner.reason, "comment with # spaces")

    def test_parses_ip_without_space_before_comment(self):
        """Test parsing IP with comment but no space before #"""
        lines = ["1.1.1.1#comment_without_space"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        scanner = MassScanner.objects.get(ip_address="1.1.1.1")
        self.assertEqual(scanner.reason, "comment_without_space")

    def test_skips_ipv6_addresses(self):
        """Test that IPv6 addresses are skipped (logged at DEBUG level)"""
        lines = [
            "2001:0db8:85a3::8a2e:0370:7334 # full IPv6",
            "2001:db8::1 # compressed IPv6",
            "fe80::1ff:fe23:4567:890a # link-local",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # Should not create any entries
        self.assertEqual(MassScanner.objects.count(), 0)
        # Should log at DEBUG level
        self.assertEqual(self.cron.log.debug.call_count, 3)

    def test_skips_invalid_strings(self):
        """Test that invalid strings like URLs are skipped (logged at DEBUG)"""
        lines = [
            "/w00tw00t.at.ISC.SANS.DFind:)",
            "<w00tw00t.at.blackhats.romanian.anti-sec:>",
            "abc.def.ghi.jkl",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        self.assertEqual(MassScanner.objects.count(), 0)
        self.assertEqual(self.cron.log.debug.call_count, 3)

    def test_skips_invalid_ip_out_of_range(self):
        """Test that IPs with octets >255 are skipped"""
        lines = ["999.999.999.999 # structurally matches but invalid IP"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        self.assertEqual(MassScanner.objects.count(), 0)
        self.cron.log.debug.assert_called_once()

    def test_skips_comment_only_lines(self):
        """Test that lines starting with # are skipped"""
        lines = [
            "# This is a comment",
            "## Another comment",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        self.assertEqual(MassScanner.objects.count(), 0)
        # Should not log anything (skipped before processing)
        self.cron.log.debug.assert_not_called()

    def test_skips_empty_lines(self):
        """Test that empty lines are skipped"""
        lines = ["", "  ", "\n"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        self.assertEqual(MassScanner.objects.count(), 0)

    def test_handles_mixed_valid_and_invalid_lines(self):
        """Test processing a mix of valid IPs, IPv6, and invalid strings"""
        lines = [
            "# Comment header",
            "192.168.1.100 # normal comment",
            "10.0.0.5#server",
            "2001:db8::1 # IPv6 - should skip",
            "/w00tw00t.at.ISC.SANS.DFind:)",
            "45.83.67.252",
            "999.999.999.999",
            "193.142.146.101",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # Should only create 4 valid entries
        self.assertEqual(MassScanner.objects.count(), 4)

        # Verify the valid IPs were added
        MassScanner.objects.get(ip_address="192.168.1.100")
        MassScanner.objects.get(ip_address="10.0.0.5")
        MassScanner.objects.get(ip_address="45.83.67.252")
        MassScanner.objects.get(ip_address="193.142.146.101")

    def test_does_not_duplicate_existing_entries(self):
        """Test that existing mass scanner entries are not duplicated"""
        # Create existing entry
        MassScanner.objects.create(ip_address="1.2.3.4", reason="existing")

        lines = ["1.2.3.4 # new comment"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # Should still only have one entry with original reason
        self.assertEqual(MassScanner.objects.count(), 1)
        scanner = MassScanner.objects.get(ip_address="1.2.3.4")
        self.assertEqual(scanner.reason, "existing")
        # Should not log "added new mass scanner"
        self.cron.log.info.assert_not_called()

    def test_parses_broadcast_and_special_ips(self):
        """Test parsing special IPs like broadcast, localhost, etc."""
        lines = [
            "255.255.255.255 # broadcast",
            "127.0.0.1 # localhost",
            "0.0.0.0 # all interfaces",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # All are valid IPv4 addresses, so they should be added
        self.assertEqual(MassScanner.objects.count(), 3)
        MassScanner.objects.get(ip_address="255.255.255.255")
        MassScanner.objects.get(ip_address="127.0.0.1")
        MassScanner.objects.get(ip_address="0.0.0.0")

    def test_handles_partial_ips(self):
        """Test that incomplete IP addresses are skipped"""
        lines = [
            "192.168.1",
            "123.456.78",
            "1.2",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        self.assertEqual(MassScanner.objects.count(), 0)
        # All should be logged at DEBUG level
        self.assertEqual(self.cron.log.debug.call_count, 3)

    def test_extracts_ip_from_beginning_of_line(self):
        """Test that IP is correctly extracted when at start of line"""
        lines = ["45.83.67.252"]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        scanner = MassScanner.objects.get(ip_address="45.83.67.252")
        self.assertEqual(scanner.reason, "")

    def test_handles_c_class_network_patterns(self):
        """Test handling of IPs with prefix characters"""
        lines = [
            "C91.196.152.28 # probe.onyphe.net",
            "C91.196.152.38 # probe.onyphe.net",
        ]
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = self._create_mock_response(lines)
            self.cron.run()

        # The regex should extract the valid IP part (91.196.152.28)
        # even though there's a 'C' prefix
        self.assertEqual(MassScanner.objects.count(), 2)
        scanner1 = MassScanner.objects.get(ip_address="91.196.152.28")
        scanner2 = MassScanner.objects.get(ip_address="91.196.152.38")
        self.assertEqual(scanner1.reason, "probe.onyphe.net")
        self.assertEqual(scanner2.reason, "probe.onyphe.net")

    def test_raises_on_http_error(self):
        """Test that HTTP errors (4xx/5xx) are raised instead of silently ignored."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = mock_response
            with self.assertRaises(requests.exceptions.HTTPError):
                self.cron.run()

        self.cron.log.exception.assert_called_once()
        self.assertEqual(MassScanner.objects.count(), 0)

    def test_raises_on_network_error(self):
        """Test that network errors (DNS failure, timeout) are raised."""
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError("DNS resolution failed")
            with self.assertRaises(requests.exceptions.ConnectionError):
                self.cron.run()

        self.cron.log.exception.assert_called_once()
        self.assertEqual(MassScanner.objects.count(), 0)

    def test_raises_on_timeout(self):
        """Test that request timeouts are raised."""
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
            with self.assertRaises(requests.exceptions.Timeout):
                self.cron.run()

        self.cron.log.exception.assert_called_once()
        self.assertEqual(MassScanner.objects.count(), 0)

    def test_execute_sets_success_false_on_http_error(self):
        """Test that base class execute() propagates HTTPError."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        with patch("greedybear.cronjobs.mass_scanners.requests.get") as mock_get:
            mock_get.return_value = mock_response
            # Expect exception to be raised now
            with self.assertRaises(requests.exceptions.HTTPError):
                self.cron.execute()
