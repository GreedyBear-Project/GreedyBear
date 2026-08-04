# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.

from ipaddress import ip_address

from django.test import SimpleTestCase

from greedybear.consts import DOMAIN, IP
from greedybear.utils import (
    PAYLOAD_REQUEST,
    SCANNER,
    get_attack_type,
    get_ioc_type,
    get_nested_value,
    is_ip_address,
    is_non_global_ip,
    is_sha256hash,
    is_valid_cidr,
    is_valid_domain,
    is_valid_ipv4,
    is_valid_url,
)

from . import CustomTestCase


class TestIsValidCIDR(CustomTestCase):
    def test_valid_cidr_returns_true_and_cleaned_cidr(self):
        is_valid, cidr = is_valid_cidr("192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

    def test_valid_cidr_edge_cases(self):
        is_valid, cidr = is_valid_cidr("0.0.0.0/0")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "0.0.0.0/0")

        is_valid, cidr = is_valid_cidr("255.255.255.255/32")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "255.255.255.255/32")

        is_valid, cidr = is_valid_cidr("10.0.0.0/8")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "10.0.0.0/8")

    def test_cidr_with_whitespace_strips_and_validates(self):
        is_valid, cidr = is_valid_cidr("  192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

        is_valid, cidr = is_valid_cidr("192.168.1.0/24  ")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

        is_valid, cidr = is_valid_cidr("  192.168.1.0/24  ")
        self.assertTrue(is_valid)
        self.assertEqual(cidr, "192.168.1.0/24")

    def test_invalid_cidr_out_of_range_octets(self):
        invalid = [
            "256.1.1.0/24",
            "1.256.1.0/24",
            "1.1.256.0/24",
            "999.999.999.999/24",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)

    def test_invalid_cidr_incomplete_format(self):
        invalid = [
            "192.168.1/24",
            "192.168/24",
            "192/24",
            "/24",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)

    def test_invalid_cidr_too_many_octets(self):
        is_valid, cidr = is_valid_cidr("1.2.3.4.5/24")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_domains(self):
        is_valid, cidr = is_valid_cidr("example.com/24")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("sub.example.com/16")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_ipv6_addresses(self):
        is_valid, cidr = is_valid_cidr("2001:db8::/32")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("::1/128")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_random_strings(self):
        is_valid, cidr = is_valid_cidr("/w00tw00t.at.ISC.SANS.DFind:)")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("not a cidr")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_special_characters(self):
        is_valid, cidr = is_valid_cidr("192.168.1.0/24#comment")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("192.168.1.0/24 # comment")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

        is_valid, cidr = is_valid_cidr("10.0.0.0/8 some text")
        self.assertFalse(is_valid)
        self.assertIsNone(cidr)

    def test_invalid_cidr_negative_numbers(self):
        invalid = [
            "-1.1.1.1/24",
            "192.168.1.0/-1",
            "192.168.1.0/33",
        ]

        for value in invalid:
            is_valid, cidr = is_valid_cidr(value)
            self.assertFalse(is_valid)
            self.assertIsNone(cidr)


class TestIsValidIpv4(CustomTestCase):
    def test_valid_ipv4_returns_true_and_cleaned_ip(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

    def test_valid_ipv4_edge_cases(self):
        # Test boundary values
        is_valid, ip = is_valid_ipv4("0.0.0.0")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "0.0.0.0")

        is_valid, ip = is_valid_ipv4("255.255.255.255")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "255.255.255.255")

        is_valid, ip = is_valid_ipv4("192.168.1.1")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "192.168.1.1")

    def test_ipv4_with_whitespace_strips_and_validates(self):
        # Test leading whitespace
        is_valid, ip = is_valid_ipv4("  1.2.3.4")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

        # Test trailing whitespace
        is_valid, ip = is_valid_ipv4("1.2.3.4  ")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

        # Test both
        is_valid, ip = is_valid_ipv4("  1.2.3.4  ")
        self.assertTrue(is_valid)
        self.assertEqual(ip, "1.2.3.4")

    def test_invalid_ipv4_out_of_range_octets(self):
        # Test octets > 255
        is_valid, ip = is_valid_ipv4("256.1.1.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.256.1.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.1.256.1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.1.1.256")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("999.999.999.999")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_incomplete_format(self):
        # Too few octets
        is_valid, ip = is_valid_ipv4("1.2.3")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.2")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_too_many_octets(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4.5")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_domains(self):
        is_valid, ip = is_valid_ipv4("example.com")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("sub.example.com")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_ipv6_addresses(self):
        # IPv6 should not be valid for IPv4 validation
        is_valid, ip = is_valid_ipv4("2001:0db8:85a3::8a2e:0370:7334")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("::1")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_random_strings(self):
        is_valid, ip = is_valid_ipv4("/w00tw00t.at.ISC.SANS.DFind:)")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("not an ip")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_special_characters(self):
        is_valid, ip = is_valid_ipv4("1.2.3.4#comment")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.2.3.4 # comment")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

    def test_invalid_ipv4_negative_numbers(self):
        is_valid, ip = is_valid_ipv4("-1.2.3.4")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)

        is_valid, ip = is_valid_ipv4("1.-2.3.4")
        self.assertFalse(is_valid)
        self.assertIsNone(ip)


class TestGetIocType(CustomTestCase):
    def test_ipv4_returns_ip(self):
        self.assertEqual(get_ioc_type("1.2.3.4"), IP)

    def test_ipv4_edge_cases(self):
        self.assertEqual(get_ioc_type("0.0.0.0"), IP)
        self.assertEqual(get_ioc_type("255.255.255.255"), IP)
        self.assertEqual(get_ioc_type("192.168.1.1"), IP)

    def test_domain_returns_domain(self):
        self.assertEqual(get_ioc_type("example.com"), DOMAIN)

    def test_subdomain_returns_domain(self):
        self.assertEqual(get_ioc_type("sub.example.com"), DOMAIN)

    def test_invalid_ip_returns_domain(self):
        self.assertEqual(get_ioc_type("256.1.1.1"), DOMAIN)
        self.assertEqual(get_ioc_type("1.2.3"), DOMAIN)


class UtilsTestCase(SimpleTestCase):
    def test_is_ip_address(self):
        # Valid IPv4
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("8.8.8.8"))
        # Valid IPv6
        self.assertTrue(is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertTrue(is_ip_address("::1"))
        # Invalid IP
        self.assertFalse(is_ip_address("256.256.256.256"))
        self.assertFalse(is_ip_address("not_an_ip"))
        self.assertFalse(is_ip_address(""))

    def test_is_valid_domain(self):
        # Valid domains
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.co.uk"))
        self.assertTrue(is_valid_domain("valid-domain.org"))

        # Invalid domains (empty)
        self.assertFalse(is_valid_domain(""))

        # Invalid domains (STIX injection characters)
        self.assertFalse(is_valid_domain("example.com'"))
        self.assertFalse(is_valid_domain('example.com"'))
        self.assertFalse(is_valid_domain("example.com\\"))
        self.assertFalse(is_valid_domain("example.com\n"))
        self.assertFalse(is_valid_domain("example.com\r"))

    def test_is_sha256hash(self):
        # Valid SHA-256
        self.assertTrue(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        self.assertTrue(is_sha256hash("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"))
        # Invalid SHA-256
        self.assertFalse(is_sha256hash("not_a_hash"))
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"))  # 63 chars
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555"))  # 65 chars
        self.assertFalse(is_sha256hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4g49b934ca495991b7852b855"))  # Invalid char 'g'
        self.assertFalse(is_sha256hash(""))

    def test_is_non_global_ip(self):
        self.assertTrue(is_non_global_ip(ip_address("127.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("10.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("169.254.1.1")))
        self.assertTrue(is_non_global_ip(ip_address("224.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("240.0.0.1")))
        self.assertTrue(is_non_global_ip(ip_address("::1")))
        self.assertTrue(is_non_global_ip(ip_address("fc00::1")))

        self.assertFalse(is_non_global_ip(ip_address("8.8.8.8")))
        self.assertFalse(is_non_global_ip(ip_address("2001:4860:4860::8888")))

    def test_is_valid_url(self):
        # Valid URLs (Must have http/https, a domain, and a path)
        self.assertTrue(is_valid_url("https://example.com/payload.exe"))
        self.assertTrue(is_valid_url("http://192.168.1.100/malware/sh"))

        # Invalid URLs (Missing path)
        self.assertFalse(is_valid_url("https://example.com"))
        self.assertFalse(is_valid_url("https://example.com/"))

        # Invalid URLs (Bad or missing schemes)
        self.assertFalse(is_valid_url("ftp://example.com/file.zip"))
        self.assertFalse(is_valid_url("example.com/payload.php"))

        # Invalid URLs (Malformatted/empty netloc)
        self.assertFalse(is_valid_url("https:///path/to/file"))
        self.assertFalse(is_valid_url(""))

    def test_get_attack_type(self):
        scanner_hits = [
            {"_related_url": "https://example.com/"},  # Invalid: no path
            {"_related_url": "ftp://badsite.com/payload.exe"},  # Invalid: bad scheme
            {"something_else": "no_url_key_at_all"},
        ]
        self.assertEqual(get_attack_type(scanner_hits), SCANNER)

        payload_hits = [
            {"_related_url": "https://example.com/"},  # Invalid hit
            {"_related_url": "https://example.com/download.exe"},  # Valid hit!
            {"_related_url": "ftp://badsite.com/payload.exe"},  # Invalid hit
        ]
        self.assertEqual(get_attack_type(payload_hits), PAYLOAD_REQUEST)

        self.assertEqual(get_attack_type([]), SCANNER)


class TestGetNestedValue(SimpleTestCase):
    def test_single_key_returns_value(self):
        result = get_nested_value({"protocol": "ssh"}, "protocol")
        self.assertEqual(result, "ssh")

    def test_nested_path_returns_value(self):
        hit = {"connection": {"protocol": "smbd", "transport": "tcp"}}
        result = get_nested_value(hit, "connection", "protocol")
        self.assertEqual(result, "smbd")

    def test_deep_path_returns_value(self):
        hit = {"a": {"b": {"c": "value"}}}
        result = get_nested_value(hit, "a", "b", "c")
        self.assertEqual(result, "value")

    def test_missing_key_returns_none(self):
        # missing at the first level
        result = get_nested_value({"protocol": "ssh"}, "proto")
        self.assertIsNone(result)
        # missing at the last level
        result = get_nested_value({"connection": {"transport": "tcp"}}, "connection", "protocol")
        self.assertIsNone(result)
        # missing in the middle of the path
        result = get_nested_value({"a": {"b": {}}}, "a", "x", "c")
        self.assertIsNone(result)

    def test_non_dict_intermediate_returns_none(self):
        # T-Pot data is messy: nested fields may be null, list, etc
        result = get_nested_value({"alert": None}, "alert", "cve_id")
        self.assertIsNone(result)
        result = get_nested_value({"alert": "CVE-2021-44228"}, "alert", "cve_id")
        self.assertIsNone(result)
        result = get_nested_value({"alert": [{"cve_id": "CVE-2021-44228"}]}, "alert", "cve_id")
        self.assertIsNone(result)
        result = get_nested_value({"connection": 22}, "connection", "protocol")
        self.assertIsNone(result)

    def test_non_dict_input_returns_none(self):
        result = get_nested_value("not a dict", "protocol")
        self.assertIsNone(result)
        result = get_nested_value(None, "protocol")
        self.assertIsNone(result)

    def test_empty_path_returns_none(self):
        # honeypot types without a field mapping must not yield the whole hit
        hit = {"type": "Honeytrap", "src_ip": "1.2.3.4", "protocol": "ssh"}
        self.assertIsNone(get_nested_value(hit))
        self.assertIsNone(get_nested_value(hit, *()))

    def test_falsy_values_returned_verbatim(self):
        result = get_nested_value({"protocol": ""}, "protocol")
        self.assertEqual(result, "")
        result = get_nested_value({"dest_port": 0}, "dest_port")
        self.assertEqual(result, 0)
        result = get_nested_value({"alert": {"cve_id": []}}, "alert", "cve_id")
        self.assertEqual(result, [])
        result = get_nested_value({"protocol": None})
        self.assertIsNone(result, "protocol")

    def test_input_not_mutated(self):
        hit = {"connection": {"protocol": "smbd"}}
        get_nested_value(hit, "connection", "protocol")
        get_nested_value(hit, "connection", "missing")
        self.assertEqual(hit, {"connection": {"protocol": "smbd"}})
