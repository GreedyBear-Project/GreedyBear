from rest_framework import serializers

DATABASE_STATES = ["up", "down", "degraded"]
QCLUSTER_STATES = ["up", "idle", "down", "unknown"]
ELASTICSEARCH_STATES = ["up", "down", "not configured", "unknown"]


class SystemStatusSerializer(serializers.Serializer):
    uptime_seconds = serializers.IntegerField(read_only=True, help_text="Seconds elapsed since the application started.")
    database = serializers.ChoiceField(choices=DATABASE_STATES, read_only=True, help_text="`degraded` means the database answers but the aggregation failed.")
    qcluster = serializers.ChoiceField(
        choices=QCLUSTER_STATES, read_only=True, help_text="`idle` means jobs are scheduled but none ran in the last 10 minutes."
    )
    elasticsearch = serializers.ChoiceField(choices=ELASTICSEARCH_STATES, read_only=True, help_text="`not configured` means no Elasticsearch client is set up.")


class IocCountsSerializer(serializers.Serializer):
    total = serializers.IntegerField(help_text="All IOCs on record.")
    new_last_24h = serializers.IntegerField(help_text="IOCs first seen in the last 24 hours.")


class SessionCountsSerializer(serializers.Serializer):
    total = serializers.IntegerField(help_text="All Cowrie sessions on record.")
    last_24h = serializers.IntegerField(help_text="Cowrie sessions started in the last 24 hours.")


class HoneypotCountsSerializer(serializers.Serializer):
    total = serializers.IntegerField(help_text="Configured honeypots.")
    active = serializers.IntegerField(help_text="Honeypots currently marked active.")


class ThreatListCountsSerializer(serializers.Serializer):
    firehol = serializers.IntegerField(help_text="Entries pulled from the FireHol lists.")
    mass_scanners = serializers.IntegerField(help_text="Known mass scanners on record.")
    tor_exit_nodes = serializers.IntegerField(help_text="Known Tor exit nodes on record.")


class JobCountsSerializer(serializers.Serializer):
    scheduled = serializers.IntegerField(help_text="Django-Q schedules currently registered.")
    failed_last_24h = serializers.IntegerField(help_text="Jobs that failed in the last 24 hours.")
    successful_last_24h = serializers.IntegerField(help_text="Jobs that succeeded in the last 24 hours.")


class OverviewSerializer(serializers.Serializer):
    iocs = IocCountsSerializer(required=False)
    sessions = SessionCountsSerializer(required=False)
    honeypots = HoneypotCountsSerializer(required=False)
    threat_lists = ThreatListCountsSerializer(required=False)
    jobs = JobCountsSerializer(required=False)


class HealthSerializer(serializers.Serializer):
    system = SystemStatusSerializer(read_only=True)
    overview = OverviewSerializer(read_only=True, help_text="Empty when the database is down.")
