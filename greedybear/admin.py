# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.contrib import admin, messages
from django.db.models import Q
from django.utils.translation import ngettext

from greedybear.models import (
    IOC,
    AttackerActivityBucket,
    CommandSequence,
    CowrieSession,
    Credential,
    FireHolList,
    Honeypot,
    MassScanner,
    Sensor,
    Statistics,
    Tag,
    TorExitNode,
    WhatsMyIPDomain,
)

logger = logging.getLogger(__name__)


@admin.register(TorExitNode)
class TorExitNodeModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "reason"]
    search_fields = ["ip_address"]
    search_help_text = "search for the IP address"


@admin.register(Sensor)
class SensorsModelAdmin(admin.ModelAdmin):
    list_display = ["id", "address", "country", "label"]
    list_editable = ["label"]
    search_fields = ["address", "label"]
    search_help_text = "search for the sensor IP address or label"


@admin.register(Statistics)
class StatisticsModelAdmin(admin.ModelAdmin):
    list_display = ["source", "view", "request_date"]
    list_filter = ["source"]
    search_fields = ["source"]
    search_help_text = "search for the IP address source"


@admin.register(WhatsMyIPDomain)
class WhatsMyIPModelAdmin(admin.ModelAdmin):
    list_display = ["domain", "added"]
    search_fields = ["domain"]
    search_help_text = "search for the domain"


@admin.register(MassScanner)
class MassScannersModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "reason"]
    list_filter = ["reason"]
    search_fields = ["ip_address"]
    search_help_text = "search for the IP address"


@admin.register(FireHolList)
class FireHolListModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "source"]
    list_filter = ["source"]
    search_fields = ["ip_address"]
    search_help_text = "search for the IP address"


class TagInline(admin.TabularInline):
    model = Tag
    fields = ["key", "value", "source", "added"]
    readonly_fields = ["added"]
    extra = 0
    ordering = ["source", "key"]


class SessionInline(admin.TabularInline):
    model = CowrieSession
    fields = [
        "source",
        "start_time",
        "duration",
        "credential_list",
        "interaction_count",
        "commands",
    ]
    readonly_fields = fields
    show_change_link = True
    extra = 0
    ordering = ["-start_time"]

    def credential_list(self, session):
        return ", ".join([str(c) for c in session.credentials.all()])


@admin.register(CowrieSession)
class CowrieSessionModelAdmin(admin.ModelAdmin):
    list_display = [
        "session_id",
        "start_time",
        "duration",
        "login_attempt",
        "credential_list",
        "command_execution",
        "interaction_count",
        "source",
    ]
    search_fields = ["source__name"]
    search_help_text = "search for the IP address source"
    raw_id_fields = ["source", "commands"]
    list_filter = ["login_attempt", "command_execution"]

    def credential_list(self, session):
        return ", ".join([str(c) for c in session.credentials.all()])


@admin.register(Credential)
class CredentialModelAdmin(admin.ModelAdmin):
    list_display = ["username", "password"]
    search_fields = ["username", "password"]
    search_help_text = "search for username or password"


@admin.register(CommandSequence)
class CommandSequenceModelAdmin(admin.ModelAdmin):
    list_display = ["first_seen", "last_seen", "cluster", "commands", "commands_hash"]
    inlines = [SessionInline]
    search_fields = ["source__name", "commands_hash"]
    list_filter = ["cluster", "commands_hash"]


@admin.register(IOC)
class IOCModelAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "type",
        "first_seen",
        "last_seen",
        "days_seen",
        "number_of_days_seen",
        "attack_count",
        "interaction_count",
        "related_urls",
        "scanner",
        "payload_request",
        "honeypots_list",
        "sensor_list",
        "ip_reputation",
        "firehol_categories",
        "autonomous_system_display",
        "destination_ports",
        "login_attempts",
    ]
    list_filter = [
        "type",
        "scanner",
        "payload_request",
        "ip_reputation",
        "autonomous_system",
    ]
    search_fields = ["name", "related_ioc__name"]
    search_help_text = "search by IOC name or related IOC name"
    raw_id_fields = ["related_ioc"]
    filter_horizontal = ["honeypots", "sensors"]
    inlines = [TagInline, SessionInline]

    def honeypots_list(self, ioc):
        return ", ".join([str(element) for element in ioc.honeypots.all()])

    def sensor_list(self, ioc):
        return ", ".join([str(sensor.address) for sensor in ioc.sensors.all()])

    def autonomous_system_display(self, ioc):
        """
        Shows ASN and AS name neatly in list_display.
        """
        if ioc.autonomous_system:
            asn = ioc.autonomous_system.asn
            name = ioc.autonomous_system.name
            return f"{asn} ({name})" if name else str(asn)
        return "-"

    autonomous_system_display.short_description = "Autonomous System"
    autonomous_system_display.admin_order_field = "autonomous_system__asn"

    def get_queryset(self, request):
        """Override to optimize queries and avoid N+1 problems."""
        return super().get_queryset(request).select_related("autonomous_system").prefetch_related("sensors", "honeypots")


@admin.register(AttackerActivityBucket)
class AttackerActivityBucketAdmin(admin.ModelAdmin):
    list_display = ["attacker_ip", "feed_type", "bucket_start", "interaction_count"]
    list_filter = ["feed_type"]
    search_fields = ["attacker_ip"]
    search_help_text = "search for the attacker IP address"
    date_hierarchy = "bucket_start"
    ordering = ["-bucket_start"]


@admin.register(Honeypot)
class HoneypotAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "active",
    ]
    actions = ["disable_honeypot", "enable_honeypot"]

    @admin.action(description="Disable selected honeypot")
    def disable_honeypot(self, request, queryset):
        disableable = Q(active=True)
        honeypots = queryset.filter(disableable).all()
        number_updated = honeypots.update(active=False)
        self.message_user(
            request,
            ngettext(
                "%d honeypot was successfully disabled.",
                "%d honeypots were successfully disabled.",
                number_updated,
            )
            % number_updated,
            messages.SUCCESS,
        )

    @admin.action(description="Enable selected honeypot")
    def enable_honeypot(self, request, queryset):
        enableable = Q(active=False)
        honeypots = queryset.filter(enableable).all()
        number_updated = honeypots.update(active=True)
        self.message_user(
            request,
            ngettext(
                "%d honeypot was successfully enabled.",
                "%d honeypots were successfully enabled.",
                number_updated,
            )
            % number_updated,
            messages.SUCCESS,
        )
