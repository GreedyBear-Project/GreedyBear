# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.


from datetime import datetime

from greedybear.settings import CLUSTER_COWRIE_COMMAND_SEQUENCES, EXTRACTION_INTERVAL


def extract_all():
    from greedybear.cronjobs.extract import ExtractionJob

    # Check if this is the extraction run immediately after midnight
    midnight_extraction = datetime.now().hour == 0 and datetime.now().minute < EXTRACTION_INTERVAL

    ExtractionJob().execute()

    # If so, execute the training task
    if midnight_extraction:
        train_and_update()


def monitor_honeypots():
    from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots

    MonitorHoneypots().execute()


def monitor_logs():
    from greedybear.cronjobs.monitor_logs import MonitorLogs

    MonitorLogs().execute()


# SCORING
def train_and_update():
    from greedybear.cronjobs.scoring.scoring_jobs import TrainModels, UpdateScores

    trainer = TrainModels()
    trainer.execute()

    updater = UpdateScores()
    updater.data = trainer.current_data
    updater.execute()


# COMMANDS
def cluster_commands():
    from greedybear.cronjobs.commands.cluster import ClusterCommandSequences

    if CLUSTER_COWRIE_COMMAND_SEQUENCES:
        ClusterCommandSequences().execute()


# CLEAN UP
def clean_up_db():
    from greedybear.cronjobs.cleanup import CleanUp

    CleanUp().execute()


def get_mass_scanners():
    from greedybear.cronjobs.mass_scanners import MassScannersCron

    MassScannersCron().execute()


def get_whatsmyip():
    from greedybear.cronjobs.whatsmyip import WhatsMyIPCron

    WhatsMyIPCron().execute()


def extract_firehol_lists():
    from greedybear.cronjobs.firehol import FireHolCron

    FireHolCron().execute()


def get_tor_exit_nodes():
    from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron

    TorExitNodesCron().execute()


def check_reverse_dns():
    from greedybear.cronjobs.reverse_dns import ReverseDNSCron

    ReverseDNSCron().execute()


def enrich_threatfox():
    from greedybear.cronjobs.threatfox_feed import ThreatFoxCron

    ThreatFoxCron().execute()


def enrich_abuseipdb():
    from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron

    AbuseIPDBCron().execute()


def extract_spamhaus_drop():
    from greedybear.cronjobs.spamhaus_drop import SpamhausDropCron

    SpamhausDropCron().execute()


def clean_up_trending_buckets():
    from greedybear.cronjobs.bucket_cleanup import TrendingBucketCleanupCron

    TrendingBucketCleanupCron().execute()


def detect_credential_reuse():
    from greedybear.cronjobs.credential_reuse import CredentialReuseCron

    CredentialReuseCron().execute()
