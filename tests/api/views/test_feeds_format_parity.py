from django.test import override_settings

from tests import CustomTestCase


class FeedsFormatParityTestCase(CustomTestCase):
    """Ensures different DRF renderers selects the *same* set of IOC values."""

    FORMATS = ("json", "txt", "csv", "stix21")
    INCLUDE_ALL = "?include_mass_scanners&include_tor_exit_nodes"

    def _get_response(self, fmt: str, query=""):
        """Helper for making requests."""
        return self.client.get(f"/api/feeds/all/all/recent.{fmt}{query}")

    def _get_ioc_names(self, fmt: str, response) -> set:
        """Extract the set of IOC values from a feed response, per format."""
        match fmt:
            case "json":
                return {ioc["value"] for ioc in response.json()["iocs"]}
            case "stix21":
                return {obj["name"] for obj in response.json()["objects"] if obj.get("type") == "indicator"}
            case _: # txt and csv
                body = response.content.decode("utf-8")
                return {line.strip() for line in body.splitlines() if line.strip() and not line.startswith("#")}

    def test_all_formats_return_200(self):
        for fmt in self.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertEqual(self._get_response(fmt).status_code, 200)

    def test_formats_return_identical_ioc_set(self):
        expected = {self.ioc.name, self.ioc_2.name, self.ioc_3.name, self.ioc_domain.name}
        for fmt in self.FORMATS:
            response = self._get_response(fmt, self.INCLUDE_ALL)
            self.assertEqual(response.status_code, 200, fmt)
            ioc_names = self._get_ioc_names(fmt, response)
            with self.subTest(fmt=fmt):
                self.assertEqual(ioc_names, expected)

    def test_formats_apply_filtering_consistently(self):
        query = "?ioc_type=ip&include_mass_scanners&include_tor_exit_nodes"
        for fmt in self.FORMATS:
            with self.subTest(fmt=fmt):
                values = self._get_ioc_names(fmt, self._get_response(fmt, query))
                self.assertIn(self.ioc.name, values)
                self.assertNotIn(self.ioc_domain.name, values)

    def test_formats_respect_inclusion_defaults(self):
        excluded = {self.ioc_2.name, self.ioc_3.name}
        for fmt in self.FORMATS:
            with self.subTest(fmt=fmt):
                values = self._get_ioc_names(fmt, self._get_response(fmt))
                self.assertEqual(values & excluded, set())
                self.assertIn(self.ioc.name, values)

    @override_settings(FEEDS_LICENSE="https://example.com/license")
    def test_text_and_csv_prefix_license_without_leaking_into_values(self):
        for fmt in ("txt", "csv"):
            with self.subTest(fmt=fmt):
                response = self._get_response(fmt)
                first_line = response.content.decode("utf-8").splitlines()[0]
                self.assertEqual(first_line, "# https://example.com/license")
                self.assertNotIn("https://example.com/license", self._get_ioc_names(fmt, response))
