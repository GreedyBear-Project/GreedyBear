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
    def test_tags_high_reuse_ip(self):
        """IP using widely reused credential gets tagged."""
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        self.assertTrue(
            Tag.objects.filter(
                source="credential_reuse",
                ioc=ioc1,
                key="behavior",
                value="high_credential_reuse",
            ).exists()
        )

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_correct_tag_fields(self):
        """Tag has correct key, value and source fields."""
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        tag = Tag.objects.get(source="credential_reuse", ioc=ioc1)
        self.assertEqual(tag.key, "behavior")
        self.assertEqual(tag.value, "high_credential_reuse")
        self.assertEqual(tag.source, "credential_reuse")

    def test_below_min_login_attempts_not_tagged(self):
        """IP with too few login attempts is not tagged."""
        ioc1 = self._make_ioc("1.1.1.1", login_attempts=1)
        ioc2 = self._make_ioc("2.2.2.2", login_attempts=1)

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        self.assertFalse(Tag.objects.filter(source="credential_reuse").exists())

    def test_below_min_days_seen_not_tagged(self):
        """IP seen on too few days is not tagged."""
        ioc1 = self._make_ioc("1.1.1.1", days_seen=1)
        ioc2 = self._make_ioc("2.2.2.2", days_seen=1)

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()

        self.assertFalse(Tag.objects.filter(source="credential_reuse").exists())

    def test_below_min_credential_reuse_not_tagged(self):
        """IP whose credentials are not widely reused is not tagged."""
        ioc = self._make_ioc("1.1.1.1")

        cred = self._make_credential()
        # only one source , below MIN_CREDENTIAL_REUSE=10
        cred.sources.add(ioc)

        self.cron.run()

        self.assertFalse(Tag.objects.filter(source="credential_reuse").exists())

    def test_domain_ioc_not_tagged(self):
        """Domain IOCs are excluded — only IPs are processed."""
        domain_ioc = self._make_ioc("malware.example.com", ioc_type=IocType.DOMAIN)
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(domain_ioc, ioc2)

        self.cron.run()

        self.assertFalse(Tag.objects.filter(source="credential_reuse", ioc=domain_ioc).exists())

    def test_no_credentials_not_tagged(self):
        """IP with no credentials is not tagged."""
        self._make_ioc("3.3.3.3")

        self.cron.run()

        self.assertFalse(Tag.objects.filter(source="credential_reuse").exists())

    def test_excludes_already_tagged(self):
        """IP already tagged is not tagged again."""
        ioc1 = self._make_ioc("5.5.5.5")
        ioc2 = self._make_ioc("6.6.6.6")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        # already tagged
        Tag.objects.create(
            ioc=ioc1,
            key="behavior",
            value="high_credential_reuse",
            source="credential_reuse",
        )

        self.cron.run()

        # count must still be 1, no duplicate
        self.assertEqual(Tag.objects.filter(source="credential_reuse", ioc=ioc1).count(), 1)

    def test_no_candidates_runs_cleanly(self):
        """Empty database produces no tags and no errors."""
        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="credential_reuse").count(), 0)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_add_tags_called_once(self):
        """add_tags is called exactly once per run."""
        ioc1 = self._make_ioc("4.4.4.4")
        ioc2 = self._make_ioc("5.5.5.5")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        with patch.object(self.cron.tag_repo, "add_tags") as mock_add:
            self.cron.run()
            mock_add.assert_called_once()
            # verifying correct source name passed
            args = mock_add.call_args[0]
            self.assertEqual(args[0], "credential_reuse")
            # verifying tag entries not empty
            self.assertTrue(len(args[1]) > 0)

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

        # MAX_CANDIDATES=1 so only 1 IP should be tagged
        self.assertEqual(Tag.objects.filter(source="credential_reuse").count(), 1)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    @patch("greedybear.cronjobs.credential_reuse.MIN_LOGIN_ATTEMPTS", 1)
    def test_multiple_candidates_all_tagged(self):
        """Multiple qualifying IPs are all tagged."""
        ioc1 = self._make_ioc("10.0.0.1")
        ioc2 = self._make_ioc("10.0.0.2")
        ioc3 = self._make_ioc("10.0.0.3")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2, ioc3)

        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="credential_reuse").count(), 3)

    @patch("greedybear.cronjobs.credential_reuse.MIN_CREDENTIAL_REUSE", 1)
    def test_idempotent_run(self):
        ioc1 = self._make_ioc("1.1.1.1")
        ioc2 = self._make_ioc("2.2.2.2")

        cred = self._make_credential()
        cred.sources.add(ioc1, ioc2)

        self.cron.run()
        self.cron.run()

        self.assertEqual(Tag.objects.filter(source="credential_reuse").count(), 2)
