import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta

from django.contrib.postgres.expressions import ArraySubquery
from django.core.exceptions import ValidationError
from django.db import DataError, transaction
from django.db.models import Exists, OuterRef, Q
from django.db.models.functions import Cast, Now
from netfields import InetAddressField

from greedybear.models import IOC, FireHolList, IocType
from greedybear.utils import normalize_ip


class FireHolRepository:
    """
    Repository for data access to FireHol blocklist entries.
    """

    def __init__(self):
        """Initialize the repository."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @staticmethod
    def _normalize_sources(sources: str | Iterable[str]) -> list[str]:
        """
        Turn one source name or a list of names into a list.

        Args:
            sources: A single source name or an iterable of source names.

        Returns:
            List of source names.
        """
        if isinstance(sources, str):
            return [sources]
        return list(sources)

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
        except (DataError, ValidationError):
            self.log.warning(f"Skipping entry Postgres cannot store as an address: {ip_address}")
            return None, False
        return entry, created

    def get_entries_by_ip(self, sources: str | Iterable[str]) -> dict[str, list[str]]:
        """
        Get the stored exact IP entries of the given sources, grouped by normalized IP.

        CIDR entries are left out. They need a membership test, not an
        equality match, so they are handled separately.

        Args:
            sources: Source name or names to read, e.g. "spamhaus_drop".

        Returns:
            Dict mapping IP address to the list of sources it appears in.
        """
        single_hosts = Q(ip_address__family=4, ip_address__prefixlen=32) | Q(ip_address__family=6, ip_address__prefixlen=128)
        entries_by_ip = defaultdict(list)
        queryset = FireHolList.objects.filter(
            single_hosts,
            source__in=self._normalize_sources(sources),
        )

        for network, source in queryset.values_list("ip_address", "source"):
            entries_by_ip[normalize_ip(str(network.network_address))].append(source)
        return dict(entries_by_ip)

    def get_cidr_matches(self, sources: str | Iterable[str]) -> list[tuple[int, list[str]]]:
        """
        Find IOCs that sit inside a stored CIDR range of the given sources.

        The containment test runs in the database, against the partial GiST
        index on the blocklist. In Python it means loading every IP-type IOC
        and testing each one against every range, which does not scale.

        `Exists` filters first and stops at the first match, so the list of
        sources is only built for IOCs that actually match.

        Args:
            sources: Source name or names to read, e.g. "spamhaus_drop".

        Returns:
            List of (ioc_id, sources) tuples, one per matching IOC.
        """
        ranges = FireHolList.objects.filter(
            ip_address__prefixlen__lte=31,
            ip_address__net_contains_or_equals=Cast(OuterRef("name"), InetAddressField()),
            source__in=self._normalize_sources(sources),
        )

        return list(
            IOC.objects.filter(type=IocType.IP)
            .filter(Exists(ranges))
            .annotate(blocklist_sources=ArraySubquery(ranges.values("source")))
            .values_list("id", "blocklist_sources")
        )

    def has_entries(self, sources: str | Iterable[str]) -> bool:
        """
        Whether any blocklist entries of the given sources are stored.

        Args:
            sources: Source name or names to check, e.g. "spamhaus_drop".

        Returns:
            True if the table holds at least one row of those sources.
        """
        return FireHolList.objects.filter(source__in=self._normalize_sources(sources)).exists()

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
