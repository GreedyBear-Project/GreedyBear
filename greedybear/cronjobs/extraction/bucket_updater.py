import logging
from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from ipaddress import ip_address

from greedybear.cronjobs.extraction.utils import parse_timestamp
from greedybear.cronjobs.repositories import TrendingBucketRepository
from greedybear.utils import is_non_global_ip

logger = logging.getLogger(__name__)

BucketKey = tuple[str, str, datetime]


class BucketUpdater:
    def __init__(self):
        self.counters: Counter[BucketKey] = Counter()
        self.total_update_count: int = 0

    def collect_hits(self, hits: Iterable[dict]) -> None:
        for hit in hits:
            key = _bucket_key_from_hit(hit)
            if key is not None:
                self.counters[key] += 1

    def update(self) -> int:
        if not self.counters:
            return 0

        try:
            update_count = TrendingBucketRepository().upsert_bucket_counts(self.counters)
        except Exception:
            logger.exception("Failed to update activity buckets from hits for current chunk")
            return 0
        else:
            logger.debug(f"Updated {update_count} buckets")
            self.total_update_count += update_count
            return update_count
        finally:
            self.counters = Counter()


def _bucket_start(timestamp: str) -> datetime:
    parsed = parse_timestamp(timestamp)
    return parsed.replace(minute=0, second=0, microsecond=0)


def _bucket_key_from_hit(hit: dict) -> BucketKey | None:
    attacker_ip = hit.get("src_ip")
    feed_type = hit.get("type")
    timestamp = hit.get("@timestamp")
    if not attacker_ip or not feed_type or not timestamp:
        return None

    normalized_ip = str(attacker_ip)
    try:
        parsed_ip = ip_address(normalized_ip)
    except ValueError:
        return None

    if is_non_global_ip(parsed_ip):
        return None

    try:
        return normalized_ip, str(feed_type).lower(), _bucket_start(timestamp)
    except Exception:
        return None
