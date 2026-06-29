from django.conf import settings

from greedybear.storage import QuarantineStorage

from . import CustomTestCase


class QuarantineStorageTestCase(CustomTestCase):
    def test_storage_location(self):
        storage = QuarantineStorage()
        self.assertEqual(storage.location, settings.QUARANTINE_DIR)

    def test_get_available_name_appends_vir(self):
        storage = QuarantineStorage()

        name1 = storage.get_available_name("malware.exe")
        self.assertTrue(name1.endswith(".vir"))

        name2 = storage.get_available_name("virus.sh.vir")
        self.assertEqual(name2, "virus.sh.vir")
