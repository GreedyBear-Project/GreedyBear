from django.test import SimpleTestCase

from greedybear.cronjobs.extraction.bucket_updater import _bucket_key_from_hit


class BucketKeyFromHitTestCase(SimpleTestCase):
    def setUp(self):
        self.base_hit = {"type": "Cowrie", "@timestamp": "2025-01-15T10:00:00"}

    def _key_for(self, src_ip):
        return _bucket_key_from_hit({**self.base_hit, "src_ip": src_ip})

    def test_equivalent_ipv6_forms_produce_same_key(self):
        compressed = self._key_for("2001:4860::8888")
        self.assertEqual(compressed[0], "2001:4860::8888")
        self.assertEqual(self._key_for("2001:4860::8888".upper()), compressed)
        self.assertEqual(self._key_for("2001:4860:0:0:0:0:0:8888"), compressed)

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        self.assertEqual(self._key_for("::ffff:8.8.8.8")[0], "8.8.8.8")

    def test_ipv4_is_unchanged(self):
        self.assertEqual(self._key_for("8.8.8.8")[0], "8.8.8.8")

    def test_non_global_ip_is_skipped(self):
        self.assertIsNone(self._key_for("10.0.0.1"))
