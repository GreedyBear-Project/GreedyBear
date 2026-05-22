# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.db.models.functions import Lower, Now

from greedybear.enums import IpReputation


class ViewType(models.TextChoices):
    FEEDS_VIEW = "feeds"
    ENRICHMENT_VIEW = "enrichment"
    COMMAND_SEQUENCE_VIEW = "command sequence"
    COWRIE_SESSION_VIEW = "cowrie session"


class IocType(models.TextChoices):
    IP = "ip"
    DOMAIN = "domain"


class Sensor(models.Model):
    address = models.GenericIPAddressField(unique=True)
    country = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )
    label = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Optional human-readable label to identify this sensor (e.g. 'home-pi', 'cloud-aws-eu').",
    )

    def __str__(self):
        return f"{self.address} ({self.label})" if self.label else self.address


class Honeypot(models.Model):
    name = models.CharField(max_length=15)
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(Lower("name"), name="unique_honeypot_name_ci")]

    def __str__(self):
        return self.name


class FireHolList(models.Model):
    ip_address = models.CharField(max_length=256)
    added = models.DateTimeField(db_default=Now())
    source = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address} ({self.source or 'unknown'})"


class AutonomousSystem(models.Model):
    asn = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=256, blank=True)

    def __str__(self):
        return f"{self.name} ({self.asn})" if self.name else str(self.asn)


class IOC(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=32, choices=IocType.choices)
    first_seen = models.DateTimeField(db_default=Now())
    last_seen = models.DateTimeField(db_default=Now())
    days_seen = pg_fields.ArrayField(models.DateField(), blank=True, default=list)
    number_of_days_seen = models.IntegerField(default=1)
    attack_count = models.IntegerField(default=1)
    interaction_count = models.IntegerField(default=1)
    attacker_country = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )
    attacker_country_code = models.CharField(
        max_length=2,
        blank=True,
        default="",
    )
    autonomous_system = models.ForeignKey(
        AutonomousSystem,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="iocs",
    )
    # FEEDS - list of honeypots from general list, from which the IOC was detected
    honeypots = models.ManyToManyField(Honeypot, blank=True)
    # SENSORS - list of T-Pot sensors that detected this IOC
    sensors = models.ManyToManyField(Sensor, blank=True)
    scanner = models.BooleanField(default=False)
    payload_request = models.BooleanField(default=False)
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(models.CharField(max_length=900, blank=True), blank=True, default=list)
    ip_reputation = models.CharField(max_length=32, blank=True)
    firehol_categories = pg_fields.ArrayField(models.CharField(max_length=64, blank=True), blank=True, default=list)
    destination_ports = pg_fields.ArrayField(models.IntegerField(), default=list)
    login_attempts = models.IntegerField(default=0)
    # SCORES
    recurrence_probability = models.FloatField(null=True, default=0)
    expected_interactions = models.FloatField(null=True, default=0)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["attacker_country"]),
            models.Index(fields=["attacker_country_code"]),
        ]

    def __str__(self):
        return self.name


class CommandSequence(models.Model):
    first_seen = models.DateTimeField(db_default=Now())
    last_seen = models.DateTimeField(db_default=Now())
    commands = pg_fields.ArrayField(
        models.CharField(max_length=1024, blank=True),
        default=list,
    )
    commands_hash = models.CharField(max_length=64, unique=True, blank=True, null=True)
    cluster = models.IntegerField(blank=True, null=True)

    def __str__(self):
        cmd_string = "; ".join(self.commands)
        return cmd_string[:29] + "..." if len(cmd_string) > 32 else cmd_string


class Credential(models.Model):
    username = models.CharField(max_length=256, blank=False)
    password = models.CharField(max_length=256, blank=False)
    protocol = models.CharField(max_length=32, blank=True, default="")
    sources = models.ManyToManyField(
        "IOC",
        blank=True,
        related_name="credentials",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["username", "password", "protocol"],
                name="unique_credential",
            )
        ]
        indexes = [
            models.Index(fields=["username"]),
            models.Index(fields=["password"]),
        ]

    def __str__(self):
        protocol_part = f" | {self.protocol}" if self.protocol else ""
        return f"{self.username} | {self.password}{protocol_part}"


class CowrieSession(models.Model):
    session_id = models.BigIntegerField(primary_key=True)
    start_time = models.DateTimeField(blank=True, null=True)
    duration = models.FloatField(blank=True, null=True)
    login_attempt = models.BooleanField(default=False)
    credentials = models.ManyToManyField(Credential, blank=True)
    command_execution = models.BooleanField(default=False)
    interaction_count = models.IntegerField(default=0)
    source = models.ForeignKey(IOC, on_delete=models.CASCADE)
    commands = models.ForeignKey(CommandSequence, on_delete=models.SET_NULL, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["source"]),
        ]

    def __str__(self):
        if self.session_id is None:
            return "New Session (unsaved)"
        return f"Session {self.session_id:x} from {self.source.name}"


class CowrieFileTransfer(models.Model):
    session = models.ForeignKey(CowrieSession, on_delete=models.CASCADE, related_name="file_transfers")
    shasum = models.CharField(max_length=64)
    url = models.CharField(max_length=900, blank=True)
    outfile = models.CharField(max_length=256, blank=True)
    timestamp = models.DateTimeField(blank=False)

    class Meta:
        indexes = [
            models.Index(fields=["shasum"]),
        ]
        constraints = [models.UniqueConstraint(fields=["shasum", "session"], name="unique_download_per_session")]

    def __str__(self):
        return f"{self.shasum[:8]} from session {self.session_id}"


class Statistics(models.Model):
    source = models.CharField(max_length=64)
    view = models.CharField(
        max_length=32,
        choices=ViewType.choices,
        default=ViewType.FEEDS_VIEW.value,
    )
    request_date = models.DateTimeField(db_default=Now())

    def __str__(self):
        return f"{self.source} - {self.view} ({self.request_date.strftime('%Y-%m-%d %H:%M')})"


class MassScanner(models.Model):
    ip_address = models.GenericIPAddressField()
    added = models.DateTimeField(db_default=Now())
    reason = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address}{f' ({self.reason})' if self.reason else ''}"


class TorExitNode(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    added = models.DateTimeField(db_default=Now())
    reason = models.CharField(max_length=64, blank=True, default=IpReputation.TOR_EXIT_NODE)

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address} ({IpReputation.TOR_EXIT_NODE})"


class WhatsMyIPDomain(models.Model):
    domain = models.CharField(max_length=256)
    added = models.DateTimeField(db_default=Now())

    class Meta:
        indexes = [
            models.Index(fields=["domain"]),
        ]

    def __str__(self):
        return self.domain


class Tag(models.Model):
    """Tags for IOCs from enrichment sources like ThreatFox and AbuseIPDB."""

    ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name="tags")
    key = models.CharField(max_length=128, db_index=True)
    value = models.CharField(max_length=256)
    source = models.CharField(max_length=64)  # e.g., "threatfox", "abuseipdb"
    added = models.DateTimeField(db_default=Now())

    class Meta:
        indexes = [
            models.Index(fields=["source", "ioc"]),
        ]

    def __str__(self):
        return f"{self.ioc.name} - {self.key}: {self.value} ({self.source})"


class ShareToken(models.Model):
    """
    Tracks shared feed tokens issued via the ``/api/feeds/share`` endpoint.

    The raw token is never persisted; only its SHA-256 hash is stored so that
    a leaked database cannot be used to reconstruct valid tokens.
    A ``revoked`` flag allows tokens to be invalidated without deleting the record,
    making it easy to build an admin view for token management in the future.
    Only the user who created the token can revoke it.
    """

    user = models.ForeignKey(
        "certego_saas_user.User",
        on_delete=models.CASCADE,
        related_name="share_tokens",
    )
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hex digest of the raw signed token.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=256, blank=True, default="")

    def __str__(self):
        status = "revoked" if self.revoked else "active"
        return f"ShareToken({self.token_hash[:12]}… [{status}])"


class AttackerActivityBucket(models.Model):
    attacker_ip = models.GenericIPAddressField()
    feed_type = models.CharField(max_length=32)
    bucket_start = models.DateTimeField()
    interaction_count = models.IntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["attacker_ip", "feed_type", "bucket_start"], name="unique_attacker_activity_bucket"),
        ]
        indexes = [
            models.Index(fields=["bucket_start"]),
            models.Index(fields=["feed_type", "bucket_start"]),
            models.Index(fields=["attacker_ip", "bucket_start"]),
        ]

    def __str__(self):
        return f"{self.attacker_ip} [{self.feed_type}] @ {self.bucket_start} ({self.interaction_count})"
