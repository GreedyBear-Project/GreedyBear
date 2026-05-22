import hashlib

from django.conf import settings
from django_q.models import Schedule


def _external_weekly_cron(job_name: str) -> str:
    """Return a deterministic Sunday cron for external jobs outside 00:00-02:00."""
    seed_value = f"{settings.SECRET_KEY}:{job_name}"
    digest = hashlib.sha256(seed_value.encode()).digest()
    seed_int = int.from_bytes(digest[:8], byteorder="big", signed=False)

    minute = seed_int % 60
    hour = 2 + ((seed_int // 60) % 22)
    return f"{minute} {hour} * * 0"


def setup_schedules():
    """
    Configure Django Q2 scheduled tasks for the GreedyBear application.

    Reads schedule definitions and creates or updates
    the corresponding Django Q2 Schedule entries. Any existing schedules
    whose names are not present in the schedule definitions are treated as orphaned
    and automatically removed.

    Returns:
        None: This function is called for its side effects on the database.
    """
    extraction_interval = settings.EXTRACTION_INTERVAL

    schedules = [
        # Extraction: Every EXTRACTION_INTERVAL minutes
        {
            "name": "extract_all",
            "func": "greedybear.tasks.extract_all",
            "cron": f"*/{extraction_interval} * * * *",
        },
        # Monitor Honeypots: Hourly at :07
        {
            "name": "monitor_honeypots",
            "func": "greedybear.tasks.monitor_honeypots",
            "cron": "7 * * * *",
        },
        # Monitor Logs: Hourly at :07
        {
            "name": "monitor_logs",
            "func": "greedybear.tasks.monitor_logs",
            "cron": "7 * * * *",
        },
        # Trending Buckets Cleanup: Hourly at :12
        {
            "name": "clean_up_trending_buckets",
            "func": "greedybear.tasks.clean_up_trending_buckets",
            "cron": "12 * * * *",
        },
        # Cluster Commands: Daily at 01:07
        {
            "name": "cluster_commands",
            "func": "greedybear.tasks.cluster_commands",
            "cron": "7 1 * * *",
        },
        # Clean Up DB: Daily at 01:07
        {
            "name": "clean_up_db",
            "func": "greedybear.tasks.clean_up_db",
            "cron": "7 1 * * *",
        },
        # Mass Scanners: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "get_mass_scanners",
            "func": "greedybear.tasks.get_mass_scanners",
            "cron": _external_weekly_cron("get_mass_scanners"),
        },
        # WhatsMyIP: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "get_whatsmyip",
            "func": "greedybear.tasks.get_whatsmyip",
            "cron": _external_weekly_cron("get_whatsmyip"),
        },
        # Firehol Lists: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "extract_firehol_lists",
            "func": "greedybear.tasks.extract_firehol_lists",
            "cron": _external_weekly_cron("extract_firehol_lists"),
        },
        # Tor Exit Nodes: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "get_tor_exit_nodes",
            "func": "greedybear.tasks.get_tor_exit_nodes",
            "cron": _external_weekly_cron("get_tor_exit_nodes"),
        },
        # 10. Reverse DNS Scanner Check: Daily at 06:07
        {
            "name": "check_reverse_dns",
            "func": "greedybear.tasks.check_reverse_dns",
            "cron": "7 6 * * *",
        },
        # 11. ThreatFox Enrichment: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "enrich_threatfox",
            "func": "greedybear.tasks.enrich_threatfox",
            "cron": _external_weekly_cron("enrich_threatfox"),
        },
        # 12. AbuseIPDB Enrichment: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "enrich_abuseipdb",
            "func": "greedybear.tasks.enrich_abuseipdb",
            "cron": _external_weekly_cron("enrich_abuseipdb"),
        },
        # 13. SpamhausDrop Enrichment: Weekly (Sunday) at deterministic time outside 00:00-02:00
        {
            "name": "extract_spamhaus_drop",
            "func": "greedybear.tasks.extract_spamhaus_drop",
            "cron": _external_weekly_cron("extract_spamhaus_drop"),
        },
        # 14. Credential_reuse Detection: Daily at 02:07
        {
            "name": "detect_credential_reuse",
            "func": "greedybear.tasks.detect_credential_reuse",
            "cron": "7 2 * * *",
        },
    ]

    # create or update schedules
    for job in schedules:
        Schedule.objects.update_or_create(
            name=job["name"],
            defaults={
                "func": job["func"],
                "schedule_type": Schedule.CRON,
                "cron": job["cron"],
                "repeats": -1,
            },
        )

    # Remove orphaned schedules that are not in the current list
    active_job_names = [job["name"] for job in schedules]
    Schedule.objects.exclude(name__in=active_job_names).delete()
