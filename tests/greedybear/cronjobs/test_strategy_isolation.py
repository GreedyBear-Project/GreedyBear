"""One malformed record must cost that record, not the rest of the chunk."""

from unittest.mock import MagicMock, patch

from greedybear.cronjobs.extraction.hit import SkipHitError
from greedybear.cronjobs.extraction.strategies.generic import GenericExtractionStrategy
from greedybear.models import IOC, Honeypot
from tests import CustomTestCase

HONEYPOT = "Dionaea"
IPS = ["45.83.64.1", "45.83.64.2", "45.83.64.3"]


def hit(ip):
    return {"src_ip": ip, "type": HONEYPOT, "@timestamp": "2026-09-29T10:00:00.000Z", "geoip": {}}


class SkipOnErrorTestCase(CustomTestCase):
    def setUp(self):
        Honeypot.objects.get_or_create(name=HONEYPOT, defaults={"active": True})

    def _strategy(self):
        from greedybear.cronjobs.repositories import IocRepository, SensorRepository

        return GenericExtractionStrategy(HONEYPOT, IocRepository(), SensorRepository())

    @patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission")
    def test_control_all_three_are_extracted(self, _tf):
        strategy = self._strategy()
        strategy.extract_from_hits([hit(ip) for ip in IPS])
        self.assertEqual(len(strategy.ioc_records), 3)
        self.assertEqual(strategy.skipped, 0)

    @patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission")
    def test_one_failing_record_does_not_lose_the_others(self, _tf):
        strategy = self._strategy()
        real_add = strategy.ioc_processor.add_ioc

        def explode_on_the_second(ioc, *args, **kwargs):
            if ioc.name == IPS[1]:
                raise ValueError("boom")
            return real_add(ioc, *args, **kwargs)

        with patch.object(strategy.ioc_processor, "add_ioc", side_effect=explode_on_the_second):
            strategy.extract_from_hits([hit(ip) for ip in IPS])

        self.assertEqual(len(strategy.ioc_records), 2)
        self.assertEqual(strategy.skipped, 1)
        self.assertTrue(IOC.objects.filter(name=IPS[0]).exists())
        self.assertTrue(IOC.objects.filter(name=IPS[2]).exists())

    @patch("greedybear.cronjobs.extraction.strategies.generic.threatfox_submission")
    def test_failure_does_not_escape_the_strategy(self, _tf):
        """The per honeypot try in the pipeline stays as an outer net, but must not be needed here."""
        strategy = self._strategy()
        with patch.object(strategy.ioc_processor, "add_ioc", side_effect=ValueError("boom")):
            strategy.extract_from_hits([hit(ip) for ip in IPS])
        self.assertEqual(strategy.skipped, 3)
        self.assertEqual(strategy.ioc_records, [])

    def test_skip_hit_error_is_logged_quietly(self):
        strategy = self._strategy()
        strategy.log = MagicMock()
        with strategy.skip_on_error("IoC 1.2.3.4"):
            raise SkipHitError("missing required field 'src_ip'")
        self.assertEqual(strategy.skipped, 1)
        strategy.log.debug.assert_called_once()
        strategy.log.exception.assert_not_called()

    def test_unexpected_error_keeps_its_traceback(self):
        strategy = self._strategy()
        strategy.log = MagicMock()
        with strategy.skip_on_error("IoC 1.2.3.4"):
            raise ValueError("boom")
        self.assertEqual(strategy.skipped, 1)
        strategy.log.exception.assert_called_once()

    def test_clean_body_does_not_count_as_skipped(self):
        strategy = self._strategy()
        with strategy.skip_on_error("IoC 1.2.3.4"):
            pass
        self.assertEqual(strategy.skipped, 0)


class RealMalformedRecordTestCase(CustomTestCase):
    """
    The case this change exists for: an over long RFI hostname.

    IOC.name holds 256 characters and the URL regex has no upper bound, so an
    attacker can send a hostname that Postgres refuses. Before the guard that
    DataError left the strategy and the per honeypot except in the pipeline
    threw away every remaining record in the chunk.
    """

    LONG_HOST = "a" * 300

    def setUp(self):
        from greedybear.cronjobs.extraction.strategies.tanner import TANNER_HONEYPOT

        Honeypot.objects.get_or_create(name=TANNER_HONEYPOT, defaults={"active": True})

    def _tanner(self):
        from greedybear.cronjobs.extraction.strategies.tanner import TANNER_HONEYPOT, TannerExtractionStrategy
        from greedybear.cronjobs.repositories import IocRepository, SensorRepository

        return TannerExtractionStrategy(TANNER_HONEYPOT, IocRepository(), SensorRepository())

    def _tanner_hit(self, ip, host):
        return {
            "src_ip": ip,
            "type": "tanner",
            "@timestamp": "2026-09-29T10:00:00.000Z",
            "url": f"/index.php?page=http://{host}/shell.txt",
            "geoip": {},
        }

    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_overlong_rfi_hostname_costs_one_record_not_the_chunk(self, _tf):
        strategy = self._tanner()
        chunk = [self._tanner_hit(f"45.83.64.{i}", f"good{i}.example.com") for i in range(1, 6)]
        chunk.insert(0, self._tanner_hit("193.32.162.99", self.LONG_HOST))

        strategy.extract_from_hits(chunk)

        # the five well formed RFI hostnames survive the poisoned first record
        saved = IOC.objects.filter(type="domain", name__startswith="good").count()
        self.assertEqual(saved, 5)
        self.assertEqual(strategy.skipped, 1)

    @patch("greedybear.cronjobs.extraction.strategies.tanner.threatfox_submission")
    def test_nothing_escapes_to_the_pipeline(self, _tf):
        strategy = self._tanner()
        strategy.extract_from_hits([self._tanner_hit("193.32.162.99", self.LONG_HOST)])
        self.assertEqual(strategy.skipped, 1)
