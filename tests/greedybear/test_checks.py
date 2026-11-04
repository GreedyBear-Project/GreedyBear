# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.test import SimpleTestCase, override_settings

from greedybear.checks import check_allowed_hosts_wildcard


class AllowedHostsCheckTests(SimpleTestCase):
    @override_settings(ALLOWED_HOSTS=["*"])
    def test_wildcard_triggers_warning(self):
        """Wildcard-only ALLOWED_HOSTS should produce greedybear.W001."""
        warnings = check_allowed_hosts_wildcard(app_configs=None, databases=None)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].id, "greedybear.W001")

    @override_settings(ALLOWED_HOSTS=["example.com"])
    def test_specific_host_no_warning(self):
        """A specific hostname should not produce any warning."""
        warnings = check_allowed_hosts_wildcard(app_configs=None, databases=None)
        self.assertEqual(len(warnings), 0)

    @override_settings(ALLOWED_HOSTS=["example.com", "*"])
    def test_wildcard_among_others_triggers_warning(self):
        """A wildcard mixed with real hostnames should still produce a warning."""
        warnings = check_allowed_hosts_wildcard(app_configs=None, databases=None)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].id, "greedybear.W001")

    @override_settings(ALLOWED_HOSTS=[])
    def test_empty_allowed_hosts_no_warning(self):
        """An empty ALLOWED_HOSTS should not produce the wildcard warning."""
        warnings = check_allowed_hosts_wildcard(app_configs=None, databases=None)
        self.assertEqual(len(warnings), 0)
