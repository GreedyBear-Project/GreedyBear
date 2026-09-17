import logging

from django.db import transaction

from greedybear.models import Tag


class TagRepository:
    """Repository for data access to Tag entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def replace_tags_for_source(self, source: str, tag_entries: list[dict]) -> int:
        """
        Replace all tags for a given source with new ones.

        This is the core operation for the "fetch and join directly" approach:
        1. Delete all existing tags from this source
        2. Bulk-create new tags from the current feed data

        Wrapped in a transaction to ensure atomicity — API consumers never
        see incomplete tag data during the replacement.

        Args:
            source: Source name (e.g., "threatfox", "abuseipdb").
            tag_entries: List of dicts with keys: ioc_id, key, value.

        Returns:
            Number of tags created.
        """
        with transaction.atomic():
            self.delete_tags_by_source(source)

            if not tag_entries:
                return 0

            # Bulk-create new tags
            tags_to_create = [
                Tag(
                    ioc_id=entry["ioc_id"],
                    key=entry["key"],
                    value=entry["value"],
                    source=source,
                )
                for entry in tag_entries
            ]

            Tag.objects.bulk_create(tags_to_create, batch_size=1000)
            self.log.info(f"Created {len(tags_to_create)} tags from source '{source}'")
            return len(tags_to_create)

    def add_tags(self, source: str, tag_entries: list[dict]) -> int:
        """
        Incrementally add tags for a source without removing existing ones.

        Unlike replace_tags_for_source, this only creates new tags and
        leaves previously stored tags intact. Suitable for sources that
        build up results over many runs (e.g., reverse DNS lookups).

        Use this when the calling job only processes a subset of new
        candidates each run (typically by excluding IOCs already tagged
        by that source in its query). replace_tags_for_source would be
        incorrect here, since it deletes all existing tags for the source
        before writing, which would wipe out tags from previous runs for
        IOCs that simply weren't part of the current batch.


        Args:
            source: Source name (e.g., "rdns").
            tag_entries: List of dicts with keys: ioc_id, key, value.

        Returns:
            Number of tags created.
        """
        if not tag_entries:
            return 0

        tags_to_create = [
            Tag(
                ioc_id=entry["ioc_id"],
                key=entry["key"],
                value=entry["value"],
                source=source,
            )
            for entry in tag_entries
        ]

        Tag.objects.bulk_create(tags_to_create, batch_size=1000, ignore_conflicts=True)
        self.log.info(f"Added {len(tags_to_create)} tags from source '{source}'")
        return len(tags_to_create)

    def get_tags_by_ioc(self, ioc):
        """
        Get all tags for a specific IOC.

        Args:
            ioc: IOC instance to get tags for.

        Returns:
            QuerySet of Tag objects.
        """
        return Tag.objects.filter(ioc=ioc)

    def get_tags_by_source(self, source: str):
        """
        Get all tags from a specific source.

        Args:
            source: Source name (e.g., "threatfox", "abuseipdb").

        Returns:
            QuerySet of Tag objects.
        """
        return Tag.objects.filter(source=source)

    def delete_tags_by_source(self, source: str) -> int:
        """
        Delete all tags from a specific source.

        Args:
            source: Source name (e.g., "threatfox", "abuseipdb").

        Returns:
            Number of tags deleted.
        """
        deleted_count, _ = Tag.objects.filter(source=source).delete()
        self.log.debug(f"Deleted {deleted_count} tags from source '{source}'")
        return deleted_count
