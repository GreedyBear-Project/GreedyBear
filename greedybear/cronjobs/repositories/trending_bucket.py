from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from django.db import connection
from django.db.models import Sum

from greedybear.models import AttackerActivityBucket

BucketKey = tuple[str, str, datetime]


class TrendingBucketRepository:
    """Repository for reading and writing aggregated attacker activity buckets."""

    UPSERT_BATCH_SIZE = 10_000
    _UPSERT_VALUE_PLACEHOLDER = "(%s, %s, %s, %s)"

    @classmethod
    def _build_upsert_query(cls, quoted_table_name: str, row_count: int) -> str:
        values_sql = ",".join([cls._UPSERT_VALUE_PLACEHOLDER] * row_count)
        return f"""
            INSERT INTO {quoted_table_name} (attacker_ip, feed_type, bucket_start, interaction_count)
            VALUES {values_sql}
            ON CONFLICT (attacker_ip, feed_type, bucket_start)
            DO UPDATE
            SET interaction_count = {quoted_table_name}.interaction_count + EXCLUDED.interaction_count
        """

    @staticmethod
    def _build_upsert_params(batch: list[tuple[BucketKey, int]]) -> list[str | datetime | int]:
        params: list[str | datetime | int] = []
        for (attacker_ip, feed_type, bucket_start), interaction_count in batch:
            params.extend((attacker_ip, feed_type, bucket_start, interaction_count))
        return params

    @staticmethod
    def _normalize_feed_types(feed_types: str | Iterable[str]) -> list[str]:
        if isinstance(feed_types, str):
            return [feed_types]
        return list(feed_types)

    def upsert_bucket_counts(self, counters: Counter[BucketKey]) -> int:
        """Insert or increment bucket counts in batches and return the number of unique keys."""
        if not counters:
            return 0

        table_name = AttackerActivityBucket._meta.db_table
        quoted_table_name = connection.ops.quote_name(table_name)
        counter_items = list(counters.items())
        with connection.cursor() as cursor:
            for batch_start in range(0, len(counter_items), self.UPSERT_BATCH_SIZE):
                batch = counter_items[batch_start : batch_start + self.UPSERT_BATCH_SIZE]
                query = self._build_upsert_query(quoted_table_name, len(batch))
                params = self._build_upsert_params(batch)
                cursor.execute(query, params)

        return len(counters)

    def get_counts_in_window(self, window_start: datetime, window_end: datetime, feed_types: str | Iterable[str]) -> dict[str, int]:
        """Return summed interaction counts per attacker IP inside the requested time window."""
        queryset = AttackerActivityBucket.objects.filter(bucket_start__gte=window_start, bucket_start__lt=window_end)
        normalized_feed_types = self._normalize_feed_types(feed_types)

        if "all" not in normalized_feed_types:
            queryset = queryset.filter(feed_type__in=normalized_feed_types)

        return dict(queryset.values("attacker_ip").annotate(total=Sum("interaction_count")).values_list("attacker_ip", "total"))

    def delete_older_than(self, cutoff: datetime) -> int:
        """Delete buckets older than the cutoff and return Django's reported delete count."""
        deleted_count, _ = AttackerActivityBucket.objects.filter(bucket_start__lt=cutoff).delete()
        return deleted_count
