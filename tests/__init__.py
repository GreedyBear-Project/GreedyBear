from datetime import datetime
from hashlib import sha256
from unittest.mock import Mock

from certego_saas.apps.user.models import User
from django.test import TestCase, TransactionTestCase
from django_test_migrations.migrator import Migrator

from greedybear.enums import IpReputation
from greedybear.models import (
    IOC,
    AutonomousSystem,
    CommandSequence,
    CowrieSession,
    Credential,
    Honeypot,
    IocType,
)


class CustomTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        cls.as_obj, _ = AutonomousSystem.objects.get_or_create(asn="12345", defaults={"name": "greedybear"})
        cls.heralding = Honeypot.objects.get_or_create(name="Heralding", defaults={"active": True})[0]
        cls.ciscoasa = Honeypot.objects.get_or_create(name="Ciscoasa", defaults={"active": True})[0]
        cls.ddospot = Honeypot.objects.get_or_create(name="Ddospot", defaults={"active": False})[0]

        cls.current_time = datetime.now()

        # Create honeypots for Cowrie and Log4pot (replacing boolean fields)
        cls.cowrie_hp = Honeypot.objects.get_or_create(name="Cowrie", defaults={"active": True})[0]
        cls.log4pot_hp = Honeypot.objects.get_or_create(name="Log4pot", defaults={"active": True})[0]

        cls.ioc = IOC.objects.create(
            name="140.246.171.141",
            type=IocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time.date()],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation="",
            autonomous_system=cls.as_obj,
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
            attacker_country="China",
            attacker_country_code="CN",
        )

        cls.ioc_2 = IOC.objects.create(
            name="99.99.99.99",
            type=IocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time.date()],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation=IpReputation.MASS_SCANNER,
            autonomous_system=cls.as_obj,
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
            attacker_country="China",
            attacker_country_code="CN",
        )

        cls.ioc_3 = IOC.objects.create(
            name="100.100.100.100",
            type=IocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time.date()],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=True,
            payload_request=True,
            related_urls=[],
            ip_reputation=IpReputation.TOR_EXIT_NODE,
            autonomous_system=cls.as_obj,
            destination_ports=[22, 23, 24],
            login_attempts=1,
            recurrence_probability=0.1,
            expected_interactions=11.1,
            attacker_country="United States",
            attacker_country_code="US",
        )

        cls.ioc_domain = IOC.objects.create(
            name="malicious.example.com",
            type=IocType.DOMAIN.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time.date()],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            scanner=False,
            payload_request=True,
            related_urls=[],
            ip_reputation="",
            autonomous_system=None,
            destination_ports=[],
            login_attempts=0,
            recurrence_probability=0.2,
            expected_interactions=5.5,
        )

        cls.ioc.honeypots.add(cls.heralding)  # FEEDS
        cls.ioc.honeypots.add(cls.ciscoasa)  # FEEDS
        cls.ioc.honeypots.add(cls.cowrie_hp)  # Cowrie honeypot
        cls.ioc.honeypots.add(cls.log4pot_hp)  # Log4pot honeypot
        cls.ioc.save()
        cls.ioc_2.honeypots.add(cls.heralding)  # FEEDS
        cls.ioc_2.honeypots.add(cls.ciscoasa)  # FEEDS
        cls.ioc_2.honeypots.add(cls.cowrie_hp)  # Cowrie honeypot
        cls.ioc_2.honeypots.add(cls.log4pot_hp)  # Log4pot honeypot
        cls.ioc_2.save()
        cls.ioc_3.honeypots.add(cls.cowrie_hp)  # Cowrie honeypot
        cls.ioc_3.save()
        cls.ioc_domain.honeypots.add(cls.heralding)  # FEEDS
        cls.ioc_domain.honeypots.add(cls.log4pot_hp)  # Log4pot honeypot
        cls.ioc_domain.save()

        # IOC with an inactive-only honeypot
        cls.ioc_inactive_country = IOC.objects.create(
            name="1.2.3.7",
            type=IocType.IP.value,
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            days_seen=[cls.current_time],
            number_of_days_seen=1,
            attack_count=1,
            interaction_count=1,
            attacker_country="Russia",
            attacker_country_code="RU",
        )
        cls.ioc_inactive_country.honeypots.add(cls.ddospot)
        cls.ioc_inactive_country.save()

        cls.cmd_seq = ["cd foo", "ls -la"]
        cls.hash = sha256("\n".join(cls.cmd_seq).encode()).hexdigest()
        cls.command_sequence = CommandSequence.objects.create(
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            commands=cls.cmd_seq,
            commands_hash=cls.hash,
            cluster=11,
        )
        cls.command_sequence.save()

        cls.cowrie_session = CowrieSession.objects.create(
            session_id=int("ffffffffffff", 16),
            start_time=cls.current_time,
            duration=1.234,
            login_attempt=True,
            command_execution=True,
            interaction_count=5,
            source=cls.ioc,
            commands=cls.command_sequence,
        )
        credential, _ = Credential.objects.get_or_create(username="root", password="root", protocol="")
        cls.cowrie_session.credentials.add(credential)
        cls.cowrie_session.save()

        cls.cmd_seq_2 = ["cd bar", "ls -la"]
        cls.command_sequence_2 = CommandSequence.objects.create(
            first_seen=cls.current_time,
            last_seen=cls.current_time,
            commands=cls.cmd_seq_2,
            commands_hash=sha256("\n".join(cls.cmd_seq_2).encode()).hexdigest(),
            cluster=11,
        )
        cls.command_sequence_2.save()

        cls.cowrie_session_2 = CowrieSession.objects.create(
            session_id=int("eeeeeeeeeeee", 16),
            start_time=cls.current_time,
            duration=2.234,
            login_attempt=True,
            command_execution=True,
            interaction_count=5,
            source=cls.ioc_2,
            commands=cls.command_sequence_2,
        )
        credential_2, _ = Credential.objects.get_or_create(username="user", password="user", protocol="")
        cls.cowrie_session_2.credentials.add(credential_2)
        cls.cowrie_session_2.save()

        try:
            cls.superuser = User.objects.get(is_superuser=True)
        except User.DoesNotExist:
            cls.superuser = User.objects.create_superuser(username="test", email="test@greedybear.com", password="test")
        try:
            cls.regular_user = User.objects.get(is_superuser=False)
        except User.DoesNotExist:
            cls.regular_user = User.objects.create_user(username="regular", email="regular@greedybear.com", password="regular")


class ExtractionTestCase(CustomTestCase):
    def setUp(self):
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()
        self.mock_sensor_repo.cache = {}  # Initialize cache as empty dict for sensor filtering
        self.mock_session_repo = Mock()

    def _create_mock_ioc(
        self,
        name="1.2.3.4",
        ioc_type="ip",
        attack_count=1,
        interaction_count=1,
        related_urls=None,
        destination_ports=None,
        login_attempts=0,
        days_seen=None,
        first_seen=None,
        last_seen=None,
        ip_reputation="",
        asn=1234,
        firehol_categories=None,
        attacker_country="",
        attacker_country_code="",
    ):
        mock = Mock(spec=IOC)
        mock.name = name
        mock.type = ioc_type
        mock.scanner = False
        mock.payload_request = False
        mock.attack_count = attack_count
        mock.interaction_count = interaction_count
        mock.related_urls = related_urls if related_urls is not None else []
        mock.destination_ports = destination_ports if destination_ports is not None else []
        mock.days_seen = days_seen if days_seen is not None else []
        mock.login_attempts = login_attempts
        mock.first_seen = first_seen if first_seen is not None else datetime.now()
        mock.last_seen = last_seen if last_seen is not None else datetime.now()
        mock.ip_reputation = ip_reputation
        mock.firehol_categories = firehol_categories if firehol_categories is not None else []
        mock.number_of_days_seen = len(mock.days_seen)
        mock.attacker_country = attacker_country
        mock.attacker_country_code = attacker_country_code

        if asn is not None:
            mock.autonomous_system = Mock()
            mock.autonomous_system.asn = asn
        else:
            mock.autonomous_system = None

        return mock


class MockElasticHit:
    """Mock Elasticsearch hit that behaves like AttrDict from elasticsearch-dsl."""

    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def to_dict(self):
        return self._data.copy()


class MigrationTestCase(TransactionTestCase):
    """
    Reusable base class for migration tests.
    """

    app_name = "greedybear"
    migrate_from = None
    migrate_to = None

    def setUp(self):
        super().setUp()
        self.migrator = Migrator(database="default")
        self.old_state = self.migrator.apply_initial_migration((self.app_name, self.migrate_from))

    def apply_tested_migration(self):
        return self.migrator.apply_tested_migration((self.app_name, self.migrate_to))

    def tearDown(self):
        self.migrator.reset()
        super().tearDown()


class E2ETestCase(ExtractionTestCase):
    """Base test case for E2E pipeline tests with real strategies.

    This base class provides helpers for creating pipelines with mocked
    repositories but REAL strategies, enabling true integration testing.
    """

    def _create_pipeline_with_real_factory(self):
        """
        Create a pipeline with mocked repositories but REAL factory/strategies.

        This approach tests the actual integration:
        Pipeline → real Factory → real Strategy → IOC extraction

        Returns:
            ExtractionPipeline: Pipeline with mocked repos, real strategies.
        """
        from unittest.mock import patch

        with (
            patch("greedybear.cronjobs.extraction.pipeline.SensorRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.IocRepository"),
            patch("greedybear.cronjobs.extraction.pipeline.ElasticRepository"),
        ):
            from greedybear.cronjobs.extraction.pipeline import ExtractionPipeline

            return ExtractionPipeline()
