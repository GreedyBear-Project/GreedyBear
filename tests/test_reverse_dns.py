import socket
from datetime import date
from unittest.mock import Mock, patch

from greedybear.cronjobs.enrichment import reverse_dns as reverse_dns_module
from greedybear.cronjobs.enrichment.reverse_dns import ReverseDNSCron
from greedybear.enums import IpReputation
from greedybear.models import IOC, IocType, Tag

from . import CustomTestCase


class TestReverseDNSCron(CustomTestCase):
    """Test cases for ReverseDNSCron.run() — the main orchestrator."""

    def setUp(self):
        self.mock_tag_repo = Mock()
        self.mock_ioc_repo = Mock()
        self.cron = ReverseDNSCron(
            tag_repo=self.mock_tag_repo,
            ioc_repo=self.mock_ioc_repo,
        )
        self.cron.log = Mock()

        # Create an IOC matching all behavioral heuristics:
        # persistent (days_seen > 2), no logins, low interaction ratio
        self.candidate_ioc = IOC.objects.create(
            name="10.20.30.40",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[date(2025, 1, 1), date(2025, 1, 2), date(2025, 1, 3)],
            number_of_days_seen=3,
            attack_count=10,
            interaction_count=5,
            ip_reputation="",
            login_attempts=0,
            destination_ports=[],
            related_urls=[],
        )

    def tearDown(self):
        IOC.objects.filter(name="10.20.30.40").delete()
        Tag.objects.filter(source="rdns").delete()

    def _mock_resolve(self, ptr_value):
        """Return a side_effect for _resolve_batch that maps every IP to ptr_value."""
        return lambda ips: dict.fromkeys(ips, ptr_value)

    def test_eligible_ioc_is_resolved(self):
        """An IOC matching behavioral heuristics should be resolved."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_called_once()
        resolved_ips = mock_resolve.call_args[0][0]
        self.assertIn(self.candidate_ioc.name, resolved_ips)

    def test_skips_already_tagged_ips(self):
        """IPs already tagged by rdns source should not be queried again."""
        Tag.objects.create(ioc=self.candidate_ioc, key="ptr_record", value="scanner.shodan.io", source="rdns")

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()

    def test_skips_ips_with_existing_reputation(self):
        """IPs that already have a reputation should not be checked."""
        IOC.objects.filter(name=self.candidate_ioc.name).update(ip_reputation=IpReputation.MASS_SCANNER)

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()

    def test_skips_domain_type_iocs(self):
        """Domain-type IOCs should not be checked (only IPs)."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        resolved_ips = mock_resolve.call_args[0][0]
        self.assertNotIn("malicious.example.com", resolved_ips)

    def test_skips_ips_with_few_days_seen(self):
        """IPs seen on 2 or fewer days should not be candidates."""
        IOC.objects.filter(name=self.candidate_ioc.name).update(number_of_days_seen=2)

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()

    def test_skips_ips_with_login_attempts(self):
        """IPs with login attempts are not mass scanners and should be skipped."""
        IOC.objects.filter(name=self.candidate_ioc.name).update(login_attempts=1)

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()

    def test_skips_ips_with_high_interaction_ratio(self):
        """IPs with interaction_count >= 2 * attack_count should be skipped."""
        IOC.objects.filter(name=self.candidate_ioc.name).update(attack_count=10, interaction_count=20)

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()

    def test_stores_ptr_as_tag(self):
        """Resolved PTR records should be stored as tags via add_tags."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("scanner.shodan.io")):
            self.cron.run()

        self.mock_tag_repo.add_tags.assert_called_once()
        source, tag_entries = self.mock_tag_repo.add_tags.call_args[0]
        self.assertEqual(source, "rdns")
        self.assertEqual(len(tag_entries), 1)
        self.assertEqual(tag_entries[0]["key"], "ptr_record")
        self.assertEqual(tag_entries[0]["value"], "scanner.shodan.io")
        self.assertEqual(tag_entries[0]["ioc_id"], self.candidate_ioc.id)

    def test_does_not_store_empty_ptr(self):
        """IPs with no PTR record should NOT be tagged, allowing rechecks."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")):
            self.cron.run()

        self.mock_tag_repo.add_tags.assert_called_once()
        tag_entries = self.mock_tag_repo.add_tags.call_args[0][1]
        self.assertEqual(len(tag_entries), 0)

    def test_updates_reputation_on_scanner_match(self):
        """Matching PTR should trigger a reputation update to 'mass scanner'."""
        self.mock_ioc_repo.bulk_update_ioc_reputation.return_value = 1

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("probe.censys.io")):
            self.cron.run()

        self.mock_ioc_repo.bulk_update_ioc_reputation.assert_called_with([self.candidate_ioc.name], IpReputation.MASS_SCANNER)

    def test_no_reputation_update_on_non_scanner_ptr(self):
        """Non-scanner PTR records should not cause reputation updates."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("mail.google.com")):
            self.cron.run()

        self.mock_ioc_repo.bulk_update_ioc_reputation.assert_not_called()

    def test_no_reputation_update_on_empty_ptr(self):
        """Empty PTR results should not cause reputation updates."""
        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")):
            self.cron.run()

        self.mock_ioc_repo.bulk_update_ioc_reputation.assert_not_called()

    def test_candidates_ordered_by_persistence(self):
        """Most persistent IPs should be checked first."""
        more_persistent = IOC.objects.create(
            name="10.20.30.41",
            type=IocType.IP.value,
            first_seen=self.current_time,
            last_seen=self.current_time,
            days_seen=[date(2025, 1, i) for i in range(1, 11)],
            number_of_days_seen=10,
            attack_count=100,
            interaction_count=50,
            ip_reputation="",
            login_attempts=0,
            destination_ports=[],
            related_urls=[],
        )

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        resolved_ips = mock_resolve.call_args[0][0]
        idx_persistent = resolved_ips.index(more_persistent.name)
        idx_candidate = resolved_ips.index(self.candidate_ioc.name)
        self.assertLess(idx_persistent, idx_candidate)

        more_persistent.delete()

    def test_max_candidates_limit(self):
        """No more than MAX_CANDIDATES should be checked per run."""
        max_candidates = 3
        extra_iocs = []
        for i in range(max_candidates + 2):
            ioc = IOC.objects.create(
                name=f"10.0.{i}.1",
                type=IocType.IP.value,
                first_seen=self.current_time,
                last_seen=self.current_time,
                days_seen=[date(2025, 1, 1), date(2025, 1, 2), date(2025, 1, 3)],
                number_of_days_seen=3,
                attack_count=10,
                interaction_count=5,
                ip_reputation="",
                login_attempts=0,
                destination_ports=[],
                related_urls=[],
            )
            extra_iocs.append(ioc)

        with (
            patch.object(reverse_dns_module, "MAX_CANDIDATES", max_candidates),
            patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve,
        ):
            self.cron.run()

        resolved_ips = mock_resolve.call_args[0][0]
        self.assertLessEqual(len(resolved_ips), max_candidates)

        for ioc in extra_iocs:
            ioc.delete()

    def test_fixture_iocs_excluded_by_behavioral_filters(self):
        """Base fixture IOCs should not match (they have login_attempts=1, days_seen=1)."""
        # Delete the candidate so only fixtures remain
        self.candidate_ioc.delete()

        with patch.object(self.cron, "_resolve_batch", side_effect=self._mock_resolve("")) as mock_resolve:
            self.cron.run()

        mock_resolve.assert_not_called()


class TestReverseDNSCronResolveBatch(CustomTestCase):
    """Tests for _resolve_batch — parallel PTR resolution."""

    def setUp(self):
        self.cron = ReverseDNSCron(tag_repo=Mock(), ioc_repo=Mock())

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_batch_returns_results_for_all_ips(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = lambda ip: (f"host-{ip}.example.com", [], [ip])

        results = self.cron._resolve_batch(["1.2.3.4", "5.6.7.8"])

        self.assertEqual(results["1.2.3.4"], "host-1.2.3.4.example.com")
        self.assertEqual(results["5.6.7.8"], "host-5.6.7.8.example.com")

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_batch_handles_mixed_results(self, mock_gethostbyaddr):
        def side_effect(ip):
            if ip == "1.2.3.4":
                return ("scanner.shodan.io", [], [ip])
            raise socket.herror("Host not found")

        mock_gethostbyaddr.side_effect = side_effect

        results = self.cron._resolve_batch(["1.2.3.4", "5.6.7.8"])

        self.assertEqual(results["1.2.3.4"], "scanner.shodan.io")
        self.assertEqual(results["5.6.7.8"], "")

    def test_resolve_batch_handles_unexpected_exception(self):
        """An unexpected exception in one IP should not crash the batch."""
        self.cron.log = Mock()

        def bad_resolve(ip):
            if ip == "1.2.3.4":
                raise RuntimeError("unexpected")
            return "host.example.com"

        with patch.object(self.cron, "_resolve_ptr", side_effect=bad_resolve):
            results = self.cron._resolve_batch(["1.2.3.4", "5.6.7.8"])

        self.assertEqual(results["1.2.3.4"], "")
        self.assertEqual(results["5.6.7.8"], "host.example.com")


class TestReverseDNSCronResolvePTR(CustomTestCase):
    """Tests for _resolve_ptr method."""

    def setUp(self):
        self.cron = ReverseDNSCron(tag_repo=Mock(), ioc_repo=Mock())

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_ptr_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("scanner.shodan.io", [], ["1.2.3.4"])

        result = self.cron._resolve_ptr("1.2.3.4")

        self.assertEqual(result, "scanner.shodan.io")
        mock_gethostbyaddr.assert_called_once_with("1.2.3.4")

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_ptr_herror(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = socket.herror("Host not found")

        result = self.cron._resolve_ptr("1.2.3.4")

        self.assertEqual(result, "")

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_ptr_timeout(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = TimeoutError("timed out")

        result = self.cron._resolve_ptr("1.2.3.4")

        self.assertEqual(result, "")

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_ptr_gaierror(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = socket.gaierror("Name resolution failed")

        result = self.cron._resolve_ptr("1.2.3.4")

        self.assertEqual(result, "")

    @patch("greedybear.cronjobs.enrichment.reverse_dns.socket.gethostbyaddr")
    def test_resolve_ptr_oserror(self, mock_gethostbyaddr):
        mock_gethostbyaddr.side_effect = OSError("Network unreachable")

        result = self.cron._resolve_ptr("1.2.3.4")

        self.assertEqual(result, "")


class TestReverseDNSCronMatchesScannerDomain(CustomTestCase):
    """Tests for _matches_scanner_domain static method."""

    def test_exact_domain_match(self):
        self.assertTrue(ReverseDNSCron._matches_scanner_domain("shodan.io"))

    def test_subdomain_match(self):
        self.assertTrue(ReverseDNSCron._matches_scanner_domain("scanner.shodan.io"))

    def test_deep_subdomain_match(self):
        self.assertTrue(ReverseDNSCron._matches_scanner_domain("a.b.censys.io"))

    def test_case_insensitive_match(self):
        self.assertTrue(ReverseDNSCron._matches_scanner_domain("Scanner.SHODAN.IO"))

    def test_non_scanner_domain(self):
        self.assertFalse(ReverseDNSCron._matches_scanner_domain("mail.google.com"))

    def test_partial_name_no_match(self):
        """A domain ending with a scanner name but not as a subdomain should not match."""
        self.assertFalse(ReverseDNSCron._matches_scanner_domain("notshodan.io"))

    def test_empty_hostname(self):
        self.assertFalse(ReverseDNSCron._matches_scanner_domain(""))

    def test_all_scanner_domains(self):
        """Every domain in MASS_SCANNER_DOMAINS should match."""
        from greedybear.consts import MASS_SCANNER_DOMAINS

        for domain in MASS_SCANNER_DOMAINS:
            self.assertTrue(ReverseDNSCron._matches_scanner_domain(domain), f"{domain} should match")
            self.assertTrue(ReverseDNSCron._matches_scanner_domain(f"probe.{domain}"), f"probe.{domain} should match")
