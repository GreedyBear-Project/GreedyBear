from unittest.mock import patch

from greedybear.cronjobs.credential_reuse import CredentialReuseCron
from greedybear.models import IOC, Credential, IocType, Tag
from tests import CustomTestCase


class TestCredentialReuseCron(CustomTestCase):
    def setUp(self):
        self.cron = CredentialReuseCron()

    def _make_ioc(self, ip, login_attempts=10, days_seen=5, ioc_type=IocType.IP):
        """Helper to create IOC with sensible defaults."""
        return IOC.objects.create(
            name=ip,
            type=ioc_type,
            login_attempts=login_attempts,
            number_of_days_seen=days_seen,
        )

    def _make_credential(self, username="admin", password="admin"):
        """Helper to create a credential."""
        cred, _ = Credential.objects.get_or_create(
            username=username,
            password=password,
        )
        return cred

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_flags_high_reuse_ip(self):
        """IP using widely reused credential gets flagged."""
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        ioc1.refresh_from_db()
        self.assertIs(ioc1.high_credential_reuse, True)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_flags_field_instead_of_writing_tags(self):
        """Flagged IPs get the IOC field set, and no credential_reuse tag is written."""
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        ioc1.refresh_from_db()
        ioc2.refresh_from_db()
        self.assertIs(ioc1.high_credential_reuse, True)
        self.assertIs(ioc2.high_credential_reuse, True)
        self.assertFalse(Tag.objects.filter(source="credential_reuse").exists())

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_below_min_login_attempts_not_flagged(self):
        """IP with too few login attempts is not flagged."""
        ioc1 = self._make_ioc("1.1.1.1", login_attempts=1)
        ioc2 = self._make_ioc("2.2.2.2", login_attempts=1)

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        ioc1.refresh_from_db()
        ioc2.refresh_from_db()
        self.assertIs(ioc1.high_credential_reuse, False)
        self.assertIs(ioc2.high_credential_reuse, False)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_below_min_days_seen_not_flagged(self):
        """IP seen on too few days is not flagged."""
        ioc1 = self._make_ioc("1.1.1.1", days_seen=1)
        ioc2 = self._make_ioc("2.2.2.2", days_seen=1)

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        ioc1.refresh_from_db()
        ioc2.refresh_from_db()
        self.assertIs(ioc1.high_credential_reuse, False)
        self.assertIs(ioc2.high_credential_reuse, False)

    def test_below_min_credential_reuse_not_flagged(self):
        """IP whose credentials are not widely reused is not flagged."""
        ioc = self._make_ioc("1.1.1.1")

        cred = self._make_credential()
        # only one source , below MIN_CREDENTIAL_REUSE=10
        cred.sources.add(ioc)

        self.cron.run()

        ioc.refresh_from_db()
        self.assertIs(ioc.high_credential_reuse, False)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_domain_ioc_not_flagged(self):
        """Domain IOCs are excluded — only IPs are processed."""
        domain_ioc = self._make_ioc("malware.example.com", ioc_type=IocType.DOMAIN)
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(domain_ioc, ioc2)

        self.cron.run()

        domain_ioc.refresh_from_db()
        ioc2.refresh_from_db()
        self.assertIs(domain_ioc.high_credential_reuse, False)
        self.assertIs(ioc2.high_credential_reuse, True)

    # MIN_CREDENTIAL_REUSE=0 so the missing credentials are the only reason not to flag
    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 0)
    def test_no_credentials_not_flagged(self):
        """IP with no credentials is not flagged."""
        ioc = self._make_ioc("3.3.3.3")

        self.cron.run()

        ioc.refresh_from_db()
        self.assertIs(ioc.high_credential_reuse, False)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_excludes_already_flagged(self):
        """IP already flagged is not picked as a candidate again."""
        ioc1 = self._make_ioc("5.5.5.5")
        ioc2 = self._make_ioc("6.6.6.6")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        # already flagged
        ioc1.high_credential_reuse = True
        ioc1.save()

        candidate_ids = [ioc_id for ioc_id, _, _ in self.cron._get_candidates()]

        self.assertNotIn(ioc1.id, candidate_ids)
        self.assertIn(ioc2.id, candidate_ids)

    def test_no_candidates_runs_cleanly(self):
        """No candidates produces no flags and no errors."""
        self.cron.run()

        self.assertFalse(IOC.objects.filter(high_credential_reuse=True).exists())

    @patch("greedybear.cronjobs.credential_reuse.invalidate_ioc_cache")
    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_flags_all_candidates_in_one_update(self, mock_invalidate):
        """All candidates are flagged with a single UPDATE, not one query per IP."""
        ioc1 = self._make_ioc("4.4.4.4")
        ioc2 = self._make_ioc("5.5.5.5")
        ioc3 = self._make_ioc("6.6.6.6")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2, ioc3)

        # one query to find the candidates, one UPDATE to flag them all
        # (cache invalidation is mocked out of the query count and asserted separately)
        with self.assertNumQueries(2):
            self.cron.run()

        self.assertEqual(IOC.objects.filter(high_credential_reuse=True).count(), 3)
        mock_invalidate.assert_called_once()

    @patch("greedybear.cronjobs.credential_reuse.MAX_CANDIDATES", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_max_candidates_respected(self):
        """No more than MAX_CANDIDATES IPs are processed per run."""
        ioc1 = self._make_ioc("7.7.7.7")
        ioc2 = self._make_ioc("8.8.8.8")
        ioc3 = self._make_ioc("9.9.9.9")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2, ioc3)

        self.cron.run()

        # MAX_CANDIDATES=1 so only 1 IP should be flagged
        self.assertEqual(IOC.objects.filter(high_credential_reuse=True).count(), 1)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_multiple_candidates_all_flagged(self):
        """Multiple qualifying IPs are all flagged."""
        ioc1 = self._make_ioc("10.0.0.1")
        ioc2 = self._make_ioc("10.0.0.2")
        ioc3 = self._make_ioc("10.0.0.3")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2, ioc3)

        self.cron.run()

        flagged = set(IOC.objects.filter(high_credential_reuse=True).values_list("name", flat=True))
        self.assertEqual(flagged, {"10.0.0.1", "10.0.0.2", "10.0.0.3"})

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_idempotent_run(self):
        """A second run finds no new candidates and writes nothing."""
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        # second run: only the candidate query, no UPDATE
        with self.assertNumQueries(1):
            self.cron.run()

        self.assertEqual(IOC.objects.filter(high_credential_reuse=True).count(), 2)
