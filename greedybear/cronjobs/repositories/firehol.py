import logging
from collections import defaultdict
from datetime import datetime, timedelta

from django.db import DataError, connection, transaction
from django.db.models.functions import Now

from greedybear.models import FireHolList, IocType


class FireHolRepository:
    """
    Repository for data access to FireHol blocklist entries.
    """

    def __init__(self):
        """Initialize the repository."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, source: str) -> tuple[FireHolList | None, bool]:
        """
        Get an existing FireHol entry or create a new one.

        Refreshes `added` on entries that already exist, so it tracks when
        the entry was last seen on the blocklist. Cleanup deletes by `added`,
        so without this an entry still on the list would be dropped.

        The CIDR index means Postgres now parses every stored value, and its
        parser is not the same one the validators use. A value they accept
        can still be refused here, so it is skipped rather than allowed to
        abort the whole download.

        Args:
            ip_address: IP address or CIDR block.
            source: Source name (e.g., 'blocklist_de', 'greensnow').

        Returns:
            Tuple of (FireHolList object or None, created_flag). The object is
            None when the value could not be stored.
        """
        try:
            with transaction.atomic():
                entry, created = FireHolList.objects.update_or_create(
                    ip_address=ip_address,
                    source=source,
                    defaults={"added": Now()},
                )
        except DataError:
            self.log.warning(f"Skipping entry Postgres cannot store as an address: {ip_address}")
            return None, False
        return entry, created

    def get_entries_by_ip(self) -> dict[str, list[str]]:
        """
        Get all stored exact IP entries, grouped by IP.

        CIDR entries are left out. They need a membership test, not an
        equality match, so they are handled separately.

        Returns:
            Dict mapping IP address to the list of sources it appears in.
        """
        entries_by_ip = defaultdict(list)
        for ip_address_value, source in FireHolList.objects.exclude(ip_address__contains="/").values_list("ip_address", "source"):
            if source:
                entries_by_ip[ip_address_value].append(source)
        return dict(entries_by_ip)

    def get_cidr_matches(self) -> list[tuple[int, str]]:
        """
        Find IOCs that sit inside a stored CIDR range.

        Uses Postgres network containment, so the comparison happens in the
        database. In Python this means loading every IP-type IOC and testing
        each one against every range, which does not scale.

        `pg_input_is_valid` replaces the try/except this used to need. A row
        that cannot be read as an address is skipped instead of aborting the
        whole query.

        Returns:
            List of (ioc_id, source) tuples, one per match.
        """
        query = """
            SELECT ioc.id, fh.source
            FROM greedybear_ioc ioc
            JOIN greedybear_firehollist fh
              ON ioc.name::inet <<= fh.ip_address::inet
            WHERE ioc.type = %s
              AND fh.source <> ''
              AND fh.ip_address LIKE %s
              AND pg_input_is_valid(ioc.name, 'inet')
              AND pg_input_is_valid(fh.ip_address, 'inet')
        """
        with connection.cursor() as cursor:
            cursor.execute(query, [IocType.IP, "%/%"])
            return cursor.fetchall()

    def has_entries(self) -> bool:
        """
        Whether any blocklist entries are stored.

        Returns:
            True if the table holds at least one row.
        """
        return FireHolList.objects.exists()

    def save(self, entry: FireHolList) -> FireHolList:
        """
        Save a FireHolList entry to the database.

        Args:
            entry: FireHolList instance to save.

        Returns:
            The saved FireHolList instance.
        """
        entry.save()
        return entry

    def delete_old_entries(self, cutoff_date: datetime) -> int:
        """
        Delete FireHolList entries older than the specified date.

        Args:
            cutoff_date: DateTime threshold - entries added before this will be deleted.

        Returns:
            Number of entries deleted.
        """
        deleted_count, _ = FireHolList.objects.filter(added__lt=cutoff_date).delete()
        return deleted_count

    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Delete FireHolList entries older than the specified number of days.

        Args:
            days: Number of days to retain entries. Defaults to 30.

        Returns:
            Number of entries deleted.
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        return self.delete_old_entries(cutoff_date)
