# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging

from django.contrib import admin, messages
from django.db.models import Q
from django.utils.html import format_html
from django.utils.translation import ngettext

from greedybear.models import (
    IOC,
    APISource,
    AttackerActivityBucket,
    CommandSequence,
    CowrieSession,
    Credential,
    EventStatus,
    FireHolList,
    Honeypot,
    HoneypotPayload,
    MassScanner,
    RawEvent,
    Sensor,
    Statistics,
    Tag,
    TorExitNode,
    WhatsMyIPDomain,
)

logger = logging.getLogger(__name__)

MAX_LISTED_ITEMS = 6


def collapsed_list_display(attribute, description=None, max_items=MAX_LISTED_ITEMS):
    """Build a list_display callable that renders an object attribute as a collapsed list."""

    @admin.display(description=description or attribute.replace("_", " "))
    def display(self, obj):
        values = getattr(obj, attribute)
        if hasattr(values, "all"):
            values = values.all()
        values = [str(value) for value in values or []]
        values_str = ", ".join(values)
        if len(values) <= max_items:
            return values_str
        preview_values_str = ", ".join(values[: max_items - 2])
        hidden_count = len(values) - max_items + 2
        html = f'<span title="{values_str}">{preview_values_str}, … (+{hidden_count} more)</span>'
        return format_html(html)

    return display


@admin.register(TorExitNode)
class TorExitNodeModelAdmin(admin.ModelAdmin):
    list_display = ["ip_address", "added", "reason"]
    search_fields = ["ip_address"]
    search_help_text = "search for the IP address"


@admin.register(Sensor)
class SensorsModelAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "address",
        "country",
        "label",
        "honeypot_type",
        "honeypot_software",
        "group_label",
        "source_type",
        "api_source",
        "autonomous_system",
    ]
    list_filter = ["source_type", "honeypot_type"]
    list_editable = ["label"]
    search_fields = ["address", "label", "group_label"]
    search_help_text = "search by sensor IP, label, or group"
    readonly_fields = ["created_at", "updated_at"]


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
        "days_seen_display",
        "number_of_days_seen",
        "attack_count",
        "interaction_count",
        "related_urls_display",
        "scanner",
        "payload_request",
        "honeypots_display",
        "sensors_display",
        "ip_reputation",
        "firehol_categories_display",
        "autonomous_system_display",
        "destination_ports_display",
        "protocols_display",
        "cves_display",
        "login_attempts",
        "recurrence_probability",
        "expected_interactions",
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
    ordering = ["-last_seen"]

    days_seen_display = collapsed_list_display("days_seen")
    honeypots_display = collapsed_list_display("honeypots")
    sensors_display = collapsed_list_display("sensors")
    related_urls_display = collapsed_list_display("related_urls", description="Related URLs")
    firehol_categories_display = collapsed_list_display("firehol_categories", description="FireHol Categories")
    destination_ports_display = collapsed_list_display("destination_ports")
    protocols_display = collapsed_list_display("protocols")
    cves_display = collapsed_list_display("cves", description="CVEs")

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


@admin.register(APISource)
class APISourceModelAdmin(admin.ModelAdmin):
    list_display = ["name", "user", "is_active", "invalid_event_count", "created_at", "last_activity"]
    list_filter = ["is_active"]
    search_fields = ["name", "user__username"]
    search_help_text = "search by source name or username"
    readonly_fields = ["created_at", "last_activity", "invalid_event_count"]


@admin.register(EventStatus)
class EventStatusAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "api_source",
        "status",
        "ioc_count",
        "last_error",
        "created_at",
        "processed_at",
    ]
    list_filter = ["status"]
    search_fields = ["task_id", "api_source__name"]
    search_help_text = "search by task_id or api_source name"
    readonly_fields = [
        "task_id",
        "api_source",
        "status",
        "ioc_count",
        "last_error",
        "created_at",
        "processed_at",
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(RawEvent)
class RawEventAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "src_ip",
        "event_type",
        "timestamp",
        "sensor",
        "get_api_source",
        "dest_port",
        "protocol",
        "service_name",
        "processed",
        "created_at",
    ]
    list_filter = ["processed", "event_type", "protocol"]
    search_fields = ["src_ip", "session_id", "cve_id", "username", "command"]
    search_help_text = "search by src_ip, session_id, CVE, username, or command"
    readonly_fields = [
        "src_ip",
        "event_type",
        "timestamp",
        "sensor",
        "get_api_source",
        "batch",
        "session_id",
        "token_id",
        "src_port",
        "dest_port",
        "protocol",
        "service_name",
        "username",
        "password",
        "related_url",
        "payload_hash",
        "command",
        "cve_id",
        "data",
        "created_at",
        "processed",
    ]

    @admin.display(description="API Source")
    def get_api_source(self, obj):
        return obj.sensor.api_source if obj.sensor else None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related(
                "sensor",
                "sensor__api_source",
            )
        )


@admin.register(HoneypotPayload)
class HoneypotPayloadAdmin(admin.ModelAdmin):
    list_display = [
        "sha256",
        "mime_type",
        "size",
        "get_source_honeypots",
    ]
    search_fields = ["sha256", "md5", "sha1", "mime_type"]
    list_filter = ["source_honeypots", "mime_type"]
    readonly_fields = ["payload_file"]

    @admin.display(description="Source Honeypots")
    def get_source_honeypots(self, obj):
        return ", ".join([h.name for h in obj.source_honeypots.all()])
