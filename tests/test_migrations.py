from django.db import IntegrityError
from django.test import tag

from . import MigrationTestCase


@tag("migration")
class TestRemoveHardcodedHoneypots(MigrationTestCase):
    """Tests that hardcoded honeypots are removed only when no IOC references them."""

    migrate_from = "0028_generalhoneypot_unique_generalhoneypot_name_ci"
    migrate_to = "0029_remove_hardcoded_honeypots"

    def test_honeypots_deleted_only_if_unused(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        used_hp = GeneralHoneypot.objects.get(name="Ciscoasa")

        ioc = IOC.objects.create()
        ioc.general_honeypot.add(used_hp)

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertFalse(
            hp_new.objects.filter(name="Heralding").exists(),
            "Unused honeypot should be deleted",
        )

        self.assertTrue(
            hp_new.objects.filter(name="Ciscoasa").exists(),
            "Honeypot linked to IOC must not be deleted",
        )


@tag("migration")
class TestCowrieLog4jMigration(MigrationTestCase):
    """Tests migration of cowrie and log4j boolean flags into the GeneralHoneypot M2M relation."""

    migrate_from = "0029_remove_hardcoded_honeypots"
    migrate_to = "0030_migrate_cowrie_log4j"

    def test_boolean_flags_are_migrated_to_m2m(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # creating iocs covering all flag combinations
        ioc_cowrie = IOC.objects.create(cowrie=True, log4j=False)
        ioc_log4j = IOC.objects.create(cowrie=False, log4j=True)
        ioc_both = IOC.objects.create(cowrie=True, log4j=True)
        ioc_none = IOC.objects.create(cowrie=False, log4j=False)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # fetching migrated honeypots
        cowrie_hp = hp_new.objects.get(name="Cowrie")
        log4pot_hp = hp_new.objects.get(name="Log4pot")

        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_cowrie.id).general_honeypot.all()),
            {cowrie_hp},
        )
        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_log4j.id).general_honeypot.all()),
            {log4pot_hp},
        )
        self.assertEqual(
            set(ioc_new.objects.get(id=ioc_both.id).general_honeypot.all()),
            {cowrie_hp, log4pot_hp},
        )
        self.assertEqual(
            ioc_new.objects.get(id=ioc_none.id).general_honeypot.count(),
            0,
        )


@tag("migration")
class TestRemoveUnusedLog4pot(MigrationTestCase):
    """Tests that Log4pot is removed only when it has no associated IOCs.

    Fixes issue #773: Log4pot is active despite having no data.
    """

    migrate_from = "0033_disable_additional_honeypots"
    migrate_to = "0034_remove_unused_log4pot"

    def test_log4pot_deleted_if_unused(self):
        """Log4pot should be deleted if it has no associated IOCs."""
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")

        # Ensure Log4pot exists (created by migration 0030)
        GeneralHoneypot.objects.get_or_create(name="Log4pot", defaults={"active": True})

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertFalse(
            hp_new.objects.filter(name="Log4pot").exists(),
            "Log4pot with no IOCs should be deleted",
        )

    def test_log4pot_kept_if_has_iocs(self):
        """Log4pot should NOT be deleted if it has associated IOCs."""
        GeneralHoneypot = self.old_state.apps.get_model(self.app_name, "GeneralHoneypot")
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        log4pot_hp, _ = GeneralHoneypot.objects.get_or_create(name="Log4pot", defaults={"active": True})

        # Create an IOC and link it to Log4pot
        ioc = IOC.objects.create()
        ioc.general_honeypot.add(log4pot_hp)

        new_state = self.apply_tested_migration()
        hp_new = new_state.apps.get_model(self.app_name, "GeneralHoneypot")

        self.assertTrue(
            hp_new.objects.filter(name="Log4pot").exists(),
            "Log4pot with IOCs should NOT be deleted",
        )


@tag("migration")
class TestIocAsnToAutonomousSystem(MigrationTestCase):
    """Tests migration from IOC.asn -> IOC.autonomous_system."""

    migrate_from = "0042_credential_model_and_data_migration"
    migrate_to = "0043_autonomoussystem_remove_ioc_asn_and_more"

    def test_asn_migrated_to_autonomous_system(self):
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        ioc1 = ioc_old.objects.create(asn=12345)
        ioc2 = ioc_old.objects.create(asn=67890)
        ioc3 = ioc_old.objects.create(asn=None)

        # Apply migration
        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        ioc1_new = ioc_new.objects.get(pk=ioc1.pk)
        ioc2_new = ioc_new.objects.get(pk=ioc2.pk)
        ioc3_new = ioc_new.objects.get(pk=ioc3.pk)

        self.assertIsNotNone(ioc1_new.autonomous_system)
        self.assertEqual(ioc1_new.autonomous_system.asn, 12345)

        self.assertIsNotNone(ioc2_new.autonomous_system)
        self.assertEqual(ioc2_new.autonomous_system.asn, 67890)

        self.assertIsNone(ioc3_new.autonomous_system)

        self.assertEqual(as_new.objects.count(), 2)
        asns = set(as_new.objects.values_list("asn", flat=True))
        self.assertSetEqual(asns, {12345, 67890})

    def test_duplicate_asns_with_different_names(self):
        """Ensure migration does not duplicate ASNs."""
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        ioc_old.objects.create(asn=12345)
        ioc_old.objects.create(asn=12345)

        new_state = self.apply_tested_migration()
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        self.assertEqual(as_new.objects.count(), 1)

    def test_large_number_of_iocs(self):
        """Ensure migration works correctly for many IOCs."""
        ioc_old = self.old_state.apps.get_model(self.app_name, "IOC")

        num_iocs = 3500
        asns = [10000 + i % 10 for i in range(num_iocs)]

        for asn in asns:
            ioc_old.objects.create(asn=asn)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")
        as_new = new_state.apps.get_model(self.app_name, "AutonomousSystem")

        for ioc in ioc_new.objects.all():
            self.assertIsNotNone(ioc.autonomous_system)
            self.assertIn(ioc.autonomous_system.asn, range(10000, 10010))

        self.assertEqual(as_new.objects.count(), 10)


@tag("migration")
class TestCredentialModelMigration(MigrationTestCase):
    """Tests that credentials are correctly migrated from ArrayField to Credential model."""

    migrate_from = "0041_sharetoken"
    migrate_to = "0042_credential_model_and_data_migration"

    def test_credentials_migrated_to_credential_model(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        CowrieSession = self.old_state.apps.get_model(self.app_name, "CowrieSession")

        ioc = IOC.objects.create(name="1.2.3.4", type="ip")
        session = CowrieSession.objects.create(
            session_id=1,
            source=ioc,
            credentials=["root | password123", "admin | admin"],
        )

        new_state = self.apply_tested_migration()
        Credential = new_state.apps.get_model(self.app_name, "Credential")
        CowrieSession = new_state.apps.get_model(self.app_name, "CowrieSession")

        self.assertEqual(Credential.objects.count(), 2)
        self.assertTrue(Credential.objects.filter(username="root", password="password123").exists())
        self.assertTrue(Credential.objects.filter(username="admin", password="admin").exists())

        session = CowrieSession.objects.get(session_id=1)
        self.assertEqual(session.credentials.count(), 2)


@tag("migration")
class TestCredentialProtocolMigration(MigrationTestCase):
    """Tests migration adding protocol support to Credential uniqueness."""

    migrate_from = "0044_cowriefiletransfer"
    migrate_to = "0045_credential_protocol"

    def test_default_protocol_set_and_uniqueness_includes_protocol(self):
        credential_old = self.old_state.apps.get_model(self.app_name, "Credential")

        legacy = credential_old.objects.create(username="root", password="root")

        new_state = self.apply_tested_migration()
        Credential = new_state.apps.get_model(self.app_name, "Credential")

        migrated = Credential.objects.get(pk=legacy.pk)
        self.assertEqual(migrated.protocol, "")

        with self.assertRaises(IntegrityError):
            Credential.objects.create(username="root", password="root", protocol="")

        Credential.objects.create(username="root", password="root", protocol="ssh")
        Credential.objects.create(username="root", password="root", protocol="ftp")
        self.assertEqual(Credential.objects.filter(username="root", password="root").count(), 3)


@tag("migration")
class TestSensorLabelMigration(MigrationTestCase):
    """Tests the addition of the label field to the Sensor model."""

    migrate_from = "0045_credential_protocol"
    migrate_to = "0046_sensor_label"

    def test_existing_sensors_get_empty_label(self):
        Sensor = self.old_state.apps.get_model(self.app_name, "Sensor")
        Sensor.objects.create(address="10.0.0.1")

        new_state = self.apply_tested_migration()
        sensor_new = new_state.apps.get_model(self.app_name, "Sensor")
        migrated = sensor_new.objects.get(address="10.0.0.1")
        self.assertEqual(migrated.label, "")


@tag("migration")
class TestIocIdentityDeduplication(MigrationTestCase):
    """Tests IOC deduplication before enforcing the identity uniqueness constraint."""

    migrate_from = "0052_ioc_attacker_country_code_idx"
    migrate_to = "0053_deduplicate_ioc_identity_and_add_constraint"

    def test_keeps_ioc_with_highest_attack_count(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        kept_candidate = IOC.objects.create(name="1.2.3.4", type="ip", attack_count=9)
        IOC.objects.create(name="1.2.3.4", type="ip", attack_count=3)
        IOC.objects.create(name="1.2.3.4", type="ip", attack_count=1)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        remaining = list(ioc_new.objects.filter(name="1.2.3.4"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].id, kept_candidate.id)
        self.assertEqual(remaining[0].attack_count, 9)

    def test_keeps_latest_id_when_attack_count_ties(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        older = IOC.objects.create(name="dup.example", type="domain", attack_count=7)
        newer = IOC.objects.create(name="dup.example", type="domain", attack_count=7)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        remaining = list(ioc_new.objects.filter(name="dup.example"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].id, newer.id)
        self.assertNotEqual(remaining[0].id, older.id)

    def test_deduplicates_across_types_when_name_matches(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        kept = IOC.objects.create(name="shared-value", type="ip", attack_count=5)
        IOC.objects.create(name="shared-value", type="ip", attack_count=2)
        IOC.objects.create(name="shared-value", type="domain", attack_count=4)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        remaining = list(ioc_new.objects.filter(name="shared-value"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].id, kept.id)
        self.assertEqual(remaining[0].type, "ip")

    def test_unique_constraint_is_enforced_after_migration(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")
        IOC.objects.create(name="constraint-check", type="url", attack_count=4)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        with self.assertRaises(IntegrityError):
            ioc_new.objects.create(name="constraint-check", type="url", attack_count=1)

        with self.assertRaises(IntegrityError):
            ioc_new.objects.create(name="constraint-check", type="domain", attack_count=1)

    def test_keeps_distinct_names(self):
        IOC = self.old_state.apps.get_model(self.app_name, "IOC")

        first = IOC.objects.create(name="1.2.3.4", type="ip", attack_count=9)
        second = IOC.objects.create(name="example.com", type="domain", attack_count=3)

        new_state = self.apply_tested_migration()
        ioc_new = new_state.apps.get_model(self.app_name, "IOC")

        self.assertTrue(ioc_new.objects.filter(id=first.id).exists())
        self.assertTrue(ioc_new.objects.filter(id=second.id).exists())
        self.assertEqual(ioc_new.objects.count(), 2)
