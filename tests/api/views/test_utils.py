import types

from django.db.models import F

from api.views.utils import build_ioc_json_list, stream_ioc_objects
from greedybear.models import IOC
from tests import CustomTestCase


class StreamIocObjectsTestCase(CustomTestCase):
    def get_test_queryset(self):
        from django.contrib.postgres.aggregates import ArrayAgg

        return (
            IOC.objects.annotate(value=F("name")).filter(honeypots__active=True).annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True)).distinct()
        )

    def test_stream_ioc_objects_returns_generator(self):
        qs = self.get_test_queryset()
        result = stream_ioc_objects(qs)
        self.assertIsInstance(result, types.GeneratorType)

    def test_stream_ioc_objects_yields_correct_fields(self):
        qs = self.get_test_queryset()
        iocs = list(stream_ioc_objects(qs))
        self.assertGreater(len(iocs), 0)
        for ioc in iocs:
            self.assertIsInstance(ioc, dict)
            self.assertIn("value", ioc)
            self.assertIn("first_seen", ioc)
            self.assertIn("feed_type", ioc)
            self.assertIn("tags", ioc)

    def test_build_ioc_json_list_returns_list(self):
        qs = self.get_test_queryset()
        result = build_ioc_json_list(qs)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertIsInstance(result[0], dict)
        self.assertIn("value", result[0])

    def test_stream_ioc_objects_correct_values(self):
        qs = self.get_test_queryset()
        values = [ioc["value"] for ioc in stream_ioc_objects(qs)]
        self.assertIn(self.ioc.name, values)

    def test_stream_ioc_objects_empty_queryset(self):
        qs = self.get_test_queryset().none()
        self.assertEqual(list(stream_ioc_objects(qs)), [])

    def test_build_ioc_json_list_empty_queryset(self):
        qs = self.get_test_queryset().none()
        self.assertEqual(build_ioc_json_list(qs), [])

    def test_stream_and_list_return_identical_data(self):
        qs = self.get_test_queryset()
        self.assertEqual(list(stream_ioc_objects(qs)), build_ioc_json_list(qs))

    def test_verbose_fields_parity(self):
        qs = self.get_test_queryset()
        stream_result = list(stream_ioc_objects(qs, verbose=True))
        list_result = build_ioc_json_list(qs, verbose=True)
        self.assertEqual(stream_result, list_result)
        for ioc in stream_result:
            self.assertIn("days_seen", ioc)
            self.assertIn("firehol_categories", ioc)

    def test_include_sensors_parity(self):
        qs = self.get_test_queryset()
        stream_result = list(stream_ioc_objects(qs, include_sensors=True))
        list_result = build_ioc_json_list(qs, include_sensors=True)
        self.assertEqual(stream_result, list_result)

    def test_list_input_support(self):
        ioc_list = list(IOC.objects.filter(honeypots__active=True))
        stream_result = list(stream_ioc_objects(ioc_list))
        list_result = build_ioc_json_list(ioc_list)
        self.assertEqual(stream_result, list_result)
        self.assertGreater(len(stream_result), 0)
        for ioc in stream_result:
            self.assertIsInstance(ioc, dict)
