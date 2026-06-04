import hashlib
import logging
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
from greedybear.cronjobs.extraction.utils import iocs_from_hits
from greedybear.cronjobs.repositories import IocRepository, SensorRepository
from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
from greedybear.models import CommandSequence, Credential, EventStatus, RawEvent
from greedybear.utils import get_attack_type, is_valid_url

logger = logging.getLogger(__name__)


def _normalize_raw_event_to_hit(raw):
    """
    Convert a RawEvent into the hit-dict format expected by iocs_from_hits.
    """
    # one bad event shuouldn't crash the whole batch.
    if not raw.src_ip:
        logger.warning(f"RawEvent pk={raw.pk} missing src_ip — skipping")
        return None

    if raw.sensor_id is None:
        logger.warning(f"RawEvent pk={raw.pk} missing sensor — skipping")
        return None

    hit: dict = {
        "src_ip": raw.src_ip,
        # loaded via a selected_realted
        "_sensor": raw.sensor,
    }

    if raw.timestamp:
        hit["@timestamp"] = raw.timestamp.isoformat()
    if raw.dest_port:
        hit["dest_port"] = raw.dest_port
    if raw.username:
        hit["username"] = raw.username
    if raw.password:
        hit["password"] = raw.password

    if raw.username and raw.password:
        hit["_credential"] = {
            "username": raw.username,
            "password": raw.password,
            "protocol": raw.protocol,
        }

    if raw.related_url and is_valid_url(raw.related_url):
        hit["_related_url"] = raw.related_url
    if raw.command:
        hit["_command"] = raw.command

    return hit


def _process_credentials(saved_ioc, ip_hits):
    """
    Linking all credentials data to ioc
    """
    for hit in ip_hits:
        cred = hit.get("_credential")
        if not cred:
            continue

        # Credential has a unique constraint on (username, password, protocol).
        # get_or_create is atomic and race-condition safe , no duplicate rows
        #  even if two batches submit the same credential simultaneously.
        credential, _ = Credential.objects.get_or_create(
            username=cred["username"],
            password=cred["password"],
            protocol=cred["protocol"],
        )

        # Credential.sources is M2M to IOC. One credential can appear across
        # many attacker IPs; one IOC can have many credentials. add() is
        # idempotent,calling it twice doesn't create duplicate M2M rows.
        credential.sources.add(saved_ioc)
        logger.debug(f"linked credential '{credential}' → IOC {saved_ioc.name}")


def _process_related_urls(saved_ioc, ip_hits):
    """
    Extracts, filters, and appends unique related URLs from raw hits to an IOC instance.

    Validates that URLs have non-empty paths, deduplicates against existing records
    to maintain idempotency, and persists changes back to the database.
    """
    new_urls = {hit["_related_url"] for hit in ip_hits if hit.get("_related_url") and is_valid_url(hit["_related_url"])}
    if not new_urls:
        return
    # IOC.related_urls is a db ArrayField. We deduplicate against
    # existing values so re-processing the same batch is safe/idempotent.
    # using sets makes this O(n) instead of O(n²).
    existing = set(saved_ioc.related_urls or [])
    to_add = new_urls - existing
    if to_add:
        saved_ioc.related_urls = sorted(existing | to_add)
        saved_ioc.save(update_fields=["related_urls"])
        logger.debug(f"added {len(to_add)} related_url(s) → IOC {saved_ioc.name}")


def _process_commands(ip_hits):
    """
    Deduplicates and registers order-preserving sequences of executed commands from raw hits.

    Generates a unique SHA-256 hash representing the complete sequence to handle
    idempotent generation of CommandSequence records.
    """
    # commands have semantic meaning in order ("cd /tmp; wget ...").
    # A set would lose that. We deduplicate repeated identical lines
    # while keeping the first occurrence in sequence.
    seen: set[str] = set()
    unique_commands: list[str] = []
    for hit in ip_hits:
        cmd = hit.get("_command")
        if cmd and cmd.strip() and cmd not in seen:
            seen.add(cmd)
            unique_commands.append(cmd.strip())

    if not unique_commands:
        return

    # CommandSequence.commands_hash is a unique constraint. The hash
    # is the deduplication key, same commands = same hash = same row.
    commands_hash = hashlib.sha256("|".join(unique_commands).encode()).hexdigest()
    _, created = CommandSequence.objects.get_or_create(
        commands_hash=commands_hash,
        defaults={
            "commands": unique_commands,
            "first_seen": timezone.now(),
            "last_seen": timezone.now(),
        },
    )
    # the link goes through CowrieSession, which needs a valid hex
    # session_id. RawEvent.session_id is free text (may be empty or
    # non-hex). our discussion https://github.com/GreedyBear-Project/GreedyBear/discussions/1348
    # marked session_id → None for now. The ClusterCommandSequences cronjob picks up all sequences in DB
    # automatically,  no action needed from us.
    if created:
        logger.debug(f"created CommandSequence hash={commands_hash[:12]}…")


def process_incoming_event(source_id, task_id):
    """
    Process a batch of RawEvents into IOCs.

    Django-Q serializes task args into its DB. Passing N events
    would bloat the queue. We pass only the batch_id and fetch fresh
    from DB, faster queue, no serialization overhead.


    All exceptions are caught and written to EventStatus.last_error.
    The batch always ends in a terminal state (completed / failed).
    The finally block guarantees the status is saved even on crash.
    """
    try:
        batch = EventStatus.objects.get(task_id=task_id)
    except EventStatus.DoesNotExist:
        logger.exception(f"[batch={task_id}] EventStatus not found — aborting")
        return

    if batch.status in ["processing", "completed"]:
        logger.warning(f"[task={task_id}] Batch already {batch.status} — skipping to avoid race condition")
        return

    batch.status = "processing"
    batch.ioc_count = 0
    batch.last_error = ""
    batch.save(update_fields=["status", "ioc_count", "last_error"])
    logger.info(f"[batch={task_id}] Started (source_id={source_id})")

    processed_iocs = []

    try:
        # fetching RawEvents
        raw_events = list(RawEvent.objects.filter(batch=batch, processed=False).select_related("sensor"))

        if not raw_events:
            logger.warning(f"[task_id={task_id}] No unprocessed RawEvents — completing")
            batch.status = "completed"
            batch.processed_at = timezone.now()
            batch.save(update_fields=["status", "ioc_count", "processed_at"])
            return

        logger.info(f"[task={task_id}] {len(raw_events)} RawEvents fetched")

        # normaizing hit dicts
        hits = []
        skipped = 0
        for raw in raw_events:
            hit = _normalize_raw_event_to_hit(raw)
            if hit is not None:
                hits.append(hit)
            else:
                skipped += 1

        if skipped:
            logger.warning(f"[task={task_id}] {skipped} RawEvent(s) skipped (bad data)")

        if not hits:
            error_msg = f"All {len(raw_events)} RawEvents invalid after normalization"
            logger.error(f"[task={task_id}] {error_msg}")
            batch.status = "failed"
            batch.last_error = error_msg
            return

        logger.info(f"[task={task_id}] {len(hits)} valid hits")

        ioc_objects = iocs_from_hits(hits)

        if not ioc_objects:
            error_msg = "iocs_from_hits returned 0 IOCs, all source IPs may be non-global or filtered"
            logger.error(f"[task={task_id}] {error_msg}")
            batch.status = "failed"
            batch.last_error = error_msg
            return

        logger.info(f"[task_id={task_id}] {len(ioc_objects)} unique IOCs")

        # grouping hits by src_ip for post-processing lookup
        hits_by_ip: dict[str, list[dict]] = defaultdict(list)
        for hit in hits:
            hits_by_ip[hit["src_ip"]].append(hit)

        # post processing
        ioc_repo = IocRepository()
        sensor_repo = SensorRepository()
        processor = IocProcessor(ioc_repo, sensor_repo)

        with transaction.atomic():
            filtered = 0
            for ioc in ioc_objects:
                ip_hits = hits_by_ip.get(ioc.name, [])
                attack_type = get_attack_type(ip_hits)
                saved_ioc = processor.add_ioc(
                    ioc,
                    attack_type,
                    # external sensors don't use Honeypot model
                    honeypot_name=None,
                )

                if saved_ioc is None:
                    logger.debug(f"[task={task_id}] {ioc.name} filtered by processor")
                    filtered += 1
                    continue

                _process_credentials(saved_ioc, ip_hits)
                _process_related_urls(saved_ioc, ip_hits)
                _process_commands(ip_hits)

                processed_iocs.append(saved_ioc)

            if filtered:
                logger.info(f"[task={task_id}] {filtered} IOC(s) filtered out")

            logger.info(f"[task={task_id}] {len(processed_iocs)} IOC(s) persisted")

            # score
            if processed_iocs:
                UpdateScores().score_only(processed_iocs)
                logger.info(f"[task={task_id}] Scoring complete")

            RawEvent.objects.filter(batch=batch, processed=False).update(processed=True)

            batch.status = "completed"
            batch.ioc_count = len(processed_iocs)

    except Exception as exc:
        logger.exception(f"[task={task_id}] Failed")
        batch.status = "failed"
        batch.last_error = str(exc)[:1000]

    finally:
        batch.processed_at = timezone.now()
        batch.save(update_fields=["status", "ioc_count", "last_error", "processed_at"])
        logger.info(f"[task={task_id}] Done — status={batch.status}, iocs={batch.ioc_count}")
