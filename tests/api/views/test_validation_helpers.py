from types import SimpleNamespace

from api.views.utils import UnableToExtractSourceIPError, get_request_source_ip
from greedybear.utils import is_ip_address, is_sha256hash
from tests import CustomTestCase


class ValidationHelpersTestCase(CustomTestCase):
    """Test cases for the validation helper functions."""

    def test_is_ip_address_valid_ipv4(self):
        """Test that is_ip_address returns True for valid IPv4 addresses."""
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("10.0.0.1"))
        self.assertTrue(is_ip_address("127.0.0.1"))

    def test_is_ip_address_valid_ipv6(self):
        """Test that is_ip_address returns True for valid IPv6 addresses."""
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("2001:db8::1"))
        self.assertTrue(is_ip_address("fe80::1ff:fe23:4567:890a"))

    def test_is_ip_address_invalid(self):
        """Test that is_ip_address returns False for invalid IP addresses."""
        self.assertFalse(is_ip_address("not-an-ip"))
        self.assertFalse(is_ip_address("256.256.256.256"))
        self.assertFalse(is_ip_address("192.168.0"))
        self.assertFalse(is_ip_address("2001:xyz::1"))

    def test_is_sha256hash_valid(self):
        """Test that is_sha256hash returns True for valid SHA-256 hashes."""
        self.assertTrue(is_sha256hash("a" * 64))
        self.assertTrue(is_sha256hash("1234567890abcdef" * 4))
        self.assertTrue(is_sha256hash("A" * 64))

    def test_is_sha256hash_invalid(self):
        """Test that is_sha256hash returns False for invalid SHA-256 hashes."""
        self.assertFalse(is_sha256hash("a" * 63))  # Too short
        self.assertFalse(is_sha256hash("a" * 65))  # Too long
        self.assertFalse(is_sha256hash("z" * 64))  # Invalid chars
        self.assertFalse(is_sha256hash("not-a-hash"))

    def test_get_request_source_ip(self):
        """The first valid X-Forwarded-For entry should be preferred."""
        request = SimpleNamespace(
            META={
                "HTTP_X_FORWARDED_FOR": "203.0.113.5, 198.51.100.7",
            }
        )
        self.assertEqual(get_request_source_ip(request), "203.0.113.5")

    def test_get_request_source_ip_supports_ipv6(self):
        """IPv6 addresses should be accepted from forwarded header."""
        request = SimpleNamespace(
            META={
                "HTTP_X_FORWARDED_FOR": "2001:db8::1",
            }
        )
        self.assertEqual(get_request_source_ip(request), "2001:db8::1")

    def test_get_request_source_ip_raises_exception_when_invalid(self):
        """Raise UnableToExtractSourceIPError when no valid source IP can be extracted."""
        request = SimpleNamespace(
            META={
                "HTTP_X_FORWARDED_FOR": "unknown, not-an-ip",
            }
        )
        with self.assertRaises(UnableToExtractSourceIPError):
            get_request_source_ip(request)
