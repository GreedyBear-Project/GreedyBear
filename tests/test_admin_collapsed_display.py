from unittest.mock import Mock

from greedybear.admin import TITLE_MAX_CHARS, IOCModelAdmin, collapsed_list_display

from . import CustomTestCase


class FakeRelated(list):
    """Minimal stand-in for a M2M manager: hasattr .all() like a queryset."""

    def all(self):
        return list(self)


class CollapsedListDisplayTestCase(CustomTestCase):
    def test_long_list_escapes_title_and_body(self):
        payload = '"><img src=x onerror=alert(1)>'
        self.ioc.related_urls = [f"http://example.com/{i}" for i in range(6)] + [payload]
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        self.assertIn("<span title=", output)
        self.assertNotIn("<img", output)
        self.assertIn("&quot;&gt;&lt;img", output)

    def test_special_chars_escaped(self):
        values = ['a"b', "c'd", "e&f", "g<h", "i>j", "k,l", "m"]
        self.ioc.related_urls = values
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        self.assertNotIn('a"b', output)
        self.assertIn("a&quot;b", output)
        self.assertIn("c&#x27;d", output)
        self.assertIn("e&amp;f", output)
        self.assertIn("g&lt;h", output)
        self.assertIn("i&gt;j", output)

    def test_short_path_escaped(self):
        payload = '"><svg onload=alert(1)>'
        self.ioc.related_urls = ["http://example.com/a", payload]
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        self.assertNotIn("<svg", output)
        self.assertIn("&quot;&gt;&lt;svg", output)

    def test_sensor_label_m2m_escaped(self):
        malicious = Mock()
        malicious.__str__ = Mock(return_value='"><svg onload=alert(1)>')
        obj = Mock()
        obj.sensors = FakeRelated([malicious] + [Mock(__str__=Mock(return_value=f"10.0.0.{i}")) for i in range(6)])
        display = collapsed_list_display("sensors")
        output = display(None, obj)
        self.assertNotIn("<svg", output)
        self.assertIn("&quot;&gt;&lt;svg", output)

    def test_boundary_and_empty(self):
        self.ioc.related_urls = [f"http://example.com/{i}" for i in range(6)]
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        self.assertNotIn("<span", output)

        self.ioc.related_urls = [f"http://example.com/{i}" for i in range(7)]
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        self.assertIn("<span", output)
        self.assertIn("(+3 more)", output)

        self.ioc.related_urls = []
        self.assertEqual(IOCModelAdmin.related_urls_display(None, self.ioc), "")
        self.ioc.related_urls = None
        self.assertEqual(IOCModelAdmin.related_urls_display(None, self.ioc), "")

    def test_title_capped(self):
        self.ioc.related_urls = [f"http://example.com/{'a' * 50}/{i}" for i in range(200)]
        output = IOCModelAdmin.related_urls_display(None, self.ioc)
        # title attribute content must stay bounded even with hundreds of URLs
        title_part = output.split('title="', 1)[1].rsplit('"', 1)[0]
        # title holds escaped text; raw cap + ellipsis, allow growth from escaping
        self.assertLessEqual(len(title_part), TITLE_MAX_CHARS + 600)
        self.assertIn("…", title_part)
