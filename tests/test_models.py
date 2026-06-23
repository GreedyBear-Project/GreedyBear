from django.db import IntegrityError

from greedybear.enums import IpReputation
from greedybear.models import Credential, HoneypotPayload, IocType, Sensor, Statistics, Tag, ViewType

from . import CustomTestCase


class ModelsTestCase(CustomTestCase):
    def test_ioc_model(self):
        self.assertEqual(self.ioc.name, "140.246.171.141")
        self.assertEqual(self.ioc.type, IocType.IP.value)
        self.assertEqual(self.ioc.first_seen, self.current_time)
        self.assertEqual(self.ioc.last_seen, self.current_time)
        self.assertEqual(self.ioc.days_seen, [self.current_time.date()])
        self.assertEqual(self.ioc.number_of_days_seen, 1)
        self.assertEqual(self.ioc.attack_count, 1)
        self.assertEqual(self.ioc.interaction_count, 1)
        # Honeypots are now via M2M relationship
        self.assertIn(self.cowrie_hp, self.ioc.honeypots.all())
        self.assertIn(self.log4pot_hp, self.ioc.honeypots.all())
        self.assertEqual(self.ioc.scanner, True)
        self.assertEqual(self.ioc.payload_request, True)
        self.assertEqual(self.ioc.related_urls, [])
        self.assertEqual(self.ioc.ip_reputation, "")
        self.assertEqual(self.ioc.autonomous_system.asn, "12345")
        self.assertEqual(self.ioc.destination_ports, [22, 23, 24])
        self.assertEqual(self.ioc.login_attempts, 1)
        self.assertEqual(self.ioc.recurrence_probability, 0.1)
        self.assertEqual(self.ioc.expected_interactions, 11.1)

        self.assertEqual(self.ioc_2.ip_reputation, IpReputation.MASS_SCANNER)

        self.assertIn(self.heralding, self.ioc.honeypots.all())
        self.assertIn(self.ciscoasa, self.ioc.honeypots.all())

    def test_command_sequence_model(self):
        self.assertEqual(self.command_sequence.first_seen, self.current_time)
        self.assertEqual(self.command_sequence.last_seen, self.current_time)
        self.assertEqual(self.command_sequence.commands, self.cmd_seq)
        self.assertEqual(self.command_sequence.commands_hash, self.hash)
        self.assertEqual(self.command_sequence.cluster, 11)

    def test_cowrie_session_model(self):
        self.assertEqual(self.cowrie_session.session_id, int("ffffffffffff", 16))
        self.assertEqual(self.cowrie_session.start_time, self.current_time)
        self.assertEqual(self.cowrie_session.duration, 1.234)
        self.assertEqual(self.cowrie_session.login_attempt, True)
        self.assertEqual(str(self.cowrie_session.credentials.first()), "root | root")
        self.assertEqual(self.cowrie_session.command_execution, True)
        self.assertEqual(self.cowrie_session.interaction_count, 5)
        self.assertEqual(self.cowrie_session.source.name, "140.246.171.141")
        self.assertEqual(self.cowrie_session.commands.commands, self.cmd_seq)

    def test_sensor_model(self):
        sensor_no_label = Sensor.objects.create(address="10.0.0.1")
        self.assertEqual(sensor_no_label.label, "")
        self.assertEqual(str(sensor_no_label), "10.0.0.1")

        sensor_with_label = Sensor.objects.create(address="10.0.0.2", label="home-pi")
        self.assertEqual(sensor_with_label.label, "home-pi")
        self.assertEqual(str(sensor_with_label), "10.0.0.2 (home-pi)")

    def test_statistics_model(self):
        self.statistic = Statistics.objects.create(
            source="140.246.171.141",
            view=ViewType.ENRICHMENT_VIEW.value,
            request_date=self.current_time,
        )
        self.assertEqual(self.statistic.source, "140.246.171.141")
        self.assertEqual(self.statistic.view, ViewType.ENRICHMENT_VIEW.value)
        self.assertEqual(self.statistic.request_date, self.current_time)

    def test_honeypot_model(self):
        self.assertEqual(self.heralding.name, "Heralding")
        self.assertEqual(self.heralding.active, True)

    def test_tag_model(self):
        tag = Tag.objects.create(
            ioc=self.ioc,
            key="malware",
            value="Mirai",
            source="threatfox",
        )
        self.assertEqual(tag.key, "malware")
        self.assertEqual(tag.value, "Mirai")
        self.assertEqual(tag.source, "threatfox")
        self.assertEqual(tag.ioc, self.ioc)
        self.assertEqual(str(tag), "140.246.171.141 - malware: Mirai (threatfox)")

    def test_tag_cascade_delete(self):
        """Tags should be deleted when their IOC is deleted."""
        from greedybear.models import IOC, IocType

        temp_ioc = IOC.objects.create(name="10.20.30.40", type=IocType.IP.value)
        Tag.objects.create(ioc=temp_ioc, key="test", value="test_val", source="test_source")

        self.assertEqual(Tag.objects.filter(ioc=temp_ioc).count(), 1)

        temp_ioc.delete()

        self.assertEqual(Tag.objects.filter(ioc_id=temp_ioc.id).count(), 0)

    def test_credential_unique_constraint_with_default_protocol(self):
        Credential.objects.create(username="dup_user", password="dup_pass", protocol="")

        with self.assertRaises(IntegrityError):
            Credential.objects.create(username="dup_user", password="dup_pass", protocol="")

    def test_credential_unique_constraint_allows_same_pair_across_protocols(self):
        Credential.objects.create(username="proto_user", password="proto_pass", protocol="")
        Credential.objects.create(username="proto_user", password="proto_pass", protocol="ssh")
        Credential.objects.create(username="proto_user", password="proto_pass", protocol="ftp")

        self.assertEqual(Credential.objects.filter(username="proto_user", password="proto_pass").count(), 3)

    def test_honeypot_payload_model(self):
        payload = HoneypotPayload.objects.create(sha256="1234567890abcdef", mime_type="application/x-executable", size=9000)
        payload.source_honeypots.add(self.heralding)
        payload.iocs.add(self.ioc)

        self.assertEqual(payload.sha256, "1234567890abcdef")
        self.assertEqual(payload.source_honeypots.first().name, "Heralding")
        self.assertEqual(str(payload), "Payload 1234567890abcdef")

    def test_honeypot_payload_model_unique_constraint(self):
        HoneypotPayload.objects.create(sha256="unique_test_hash", mime_type="text/plain", size=123)
        with self.assertRaises(IntegrityError):
            HoneypotPayload.objects.create(sha256="unique_test_hash", mime_type="text/html", size=456)

    def test_honeypot_payload_model_multiple_relations(self):
        payload = HoneypotPayload.objects.create(sha256="multiple_relations_hash", mime_type="application/x-executable", size=9000)
        payload.iocs.add(self.ioc, self.ioc_2)
        payload.source_honeypots.add(self.heralding, self.cowrie_hp)

        self.assertEqual(payload.iocs.count(), 2)
        self.assertEqual(payload.source_honeypots.count(), 2)
