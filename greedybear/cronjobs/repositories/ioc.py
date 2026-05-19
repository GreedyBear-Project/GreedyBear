import logging

from django.contrib.postgres.aggregates import ArrayAgg
from django.db import IntegrityError
from django.db.models import F

from greedybear.models import IOC, Honeypot


class IocRepository:
    """
    Repository for IOC and honeypot data access with honeypot caching.

    Maintains a cache of existing honeypot names, populated at initialization
    and updated when new honeypots are created.
    """

    def __init__(self):
        """Initialize the repository and populate the honeypot cache from the database."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._honeypot_cache = {self._normalize_name(hp.name): hp for hp in Honeypot.objects.all()}

    def _normalize_name(self, name: str) -> str:
        """Normalize honeypot names for consistent cache and DB usage."""
        return name.lower().strip()

    def add_honeypot_to_ioc(self, honeypot_name: str, ioc: IOC) -> IOC:
        """
        Associate a honeypot with an IOC.

        Args:
            honeypot_name: Name of the honeypot to associate.
            ioc: IOC instance to add the honeypot to.

        Returns:
            The updated IOC instance.
        """
        normalized_name = self._normalize_name(honeypot_name)

        honeypot_set = set(ioc._seen_honeypots) if hasattr(ioc, "_seen_honeypots") else {self._normalize_name(hp.name) for hp in ioc.honeypots.all()}

        if normalized_name not in honeypot_set:
            self.log.debug(f"adding honeypot {honeypot_name} to IoC {ioc}")
            honeypot = self._honeypot_cache.get(normalized_name)
            if honeypot is not None:
                ioc.honeypots.add(honeypot)
                honeypot_set.add(normalized_name)
            else:
                self.log.error(f"Honeypot '{honeypot_name}' not found in cache; skipping association for IOC {ioc}")

        # Cache the current honeypot names explicitly on the IOC
        # to avoid N+1 queries when looking up `ioc.general_honeypot.all()` downstream
        ioc._seen_honeypots = list(honeypot_set)
        return ioc

    def create_honeypot(self, honeypot_name: str) -> Honeypot:
        """
        Create a new honeypot or return an existing one.

        If a honeypot with the same name (case-insensitive) already exists,
        recover and return the existing one instead. This method also updates
        the internal honeypot cache accordingly.

        Args:
            honeypot_name: Name for the new honeypot.

        Returns:
            A Honeypot instance (newly created or existing).
        """
        normalized = self._normalize_name(honeypot_name)

        try:
            honeypot = Honeypot.objects.create(
                name=honeypot_name,
                active=True,
            )
        except IntegrityError:
            self.log.exception(f"IntegrityError creating honeypot '{honeypot_name}'")
            honeypot = self.get_hp_by_name(honeypot_name)
            if honeypot is None:
                raise

        self._honeypot_cache[normalized] = honeypot
        return honeypot

    def get_active_honeypots(self) -> list[Honeypot]:
        """
        Retrieve a list of all active honeypots.

        Returns:
            A list of all active honeypots in the database.
        """
        return list(Honeypot.objects.filter(active=True))

    def get_ioc_by_name(self, name: str) -> IOC | None:
        """
        Retrieve an IOC by its name.

        Args:
            name: The IOC name to look up.

        Returns:
            The matching IOC, or None if not found.
        """
        try:
            return IOC.objects.prefetch_related("honeypots").get(name=name)
        except IOC.DoesNotExist:
            return None

    def get_hp_by_name(self, name: str) -> Honeypot | None:
        """
        Retrieve a honeypot by its name.

        Args:
            name: The honeypot name to look up.

        Returns:
            The matching Honeypot, or None if not found.
        """
        return Honeypot.objects.filter(name__iexact=name).first()

    def is_empty(self) -> bool:
        """
        Check if the database holds any IOC records.

        Returns:
            True if no IOCs exist, False otherwise.
        """
        return not IOC.objects.exists()

    def is_enabled(self, honeypot_name: str) -> bool:
        """
        Check if a honeypot is enabled.
        General honeypots are enabled based on their active flag.

        Args:
            honeypot_name: Name of the honeypot to check.

        Returns:
            True if the honeypot is enabled, False otherwise.
        """
        normalized = self._normalize_name(honeypot_name)
        hp = self._honeypot_cache.get(normalized)
        return hp.active if hp is not None else False

    def is_ready_for_extraction(self, honeypot_name: str) -> bool:
        """
        Check if a honeypot is ready for data extraction.
        Loads the honeypot if it doesn't exist, then checks if it's enabled.

        Args:
            honeypot_name: Name of the honeypot to check.

        Returns:
            True if the honeypot exists and is enabled, False otherwise.
        """
        normalized = self._normalize_name(honeypot_name)
        if normalized not in self._honeypot_cache:
            self.create_honeypot(honeypot_name)
        return self.is_enabled(honeypot_name)

    def save(self, ioc: IOC) -> IOC:
        """
        Saves an IOC to the database.

        Args:
            ioc: The IOC instance to save.

        Returns:
            The saved IOC instance.
        """
        ioc.save()
        return ioc

    def get_scanners_for_scoring(self, score_fields: list[str]) -> list[IOC]:
        """
        Get all scanners associated with active honeypots for scoring.

        Retrieves IOCs that are marked as scanners and are associated with any
        active honeypot. Returns only the name field and specified score fields for efficiency.

        Args:
            score_fields: List of score field names to retrieve (e.g., ['recurrence_probability']).

        Returns:
            QuerySet of IOC objects with only name and score fields loaded.
        """
        return IOC.objects.filter(honeypots__active=True).filter(scanner=True).distinct().only("name", *score_fields)

    def get_scanners_by_pks(self, primary_keys: set[int]):
        """
        Retrieve scanners by their primary keys with related honeypot data.

        Args:
            primary_keys: Set of IOC primary keys to retrieve.

        Returns:
            QuerySet of IOC objects with prefetched honeypots relationships
            and annotated with value and honeypots fields.
        """
        return (
            IOC.objects.filter(pk__in=primary_keys)
            .prefetch_related("honeypots")
            .annotate(value=F("name"))
            .annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
            .values()
        )

    def get_recent_scanners(self, cutoff_date, days_lookback: int = 30):
        """
        Get scanners seen after a specific cutoff date.

        Retrieves IOCs that are marked as scanners, associated with active honeypots,
        and have been seen after the specified cutoff date.

        Args:
            cutoff_date: DateTime threshold - only IOCs seen after this will be returned.
            days_lookback: Number of days to look back (used for logging, not query).

        Returns:
            QuerySet of IOC objects with prefetched relationships and annotations.
        """
        return (
            IOC.objects.filter(honeypots__active=True)
            .filter(last_seen__gte=cutoff_date, scanner=True)
            .prefetch_related("honeypots")
            .annotate(value=F("name"))
            .annotate(honeypot_names=ArrayAgg("honeypots__name", distinct=True))
            .values()
        )

    def bulk_update_scores(self, iocs: list[IOC], score_fields: list[str], batch_size: int = 1000) -> int:
        """
        Bulk update IOC score fields in the database.

        Args:
            iocs: List of IOC objects with updated score values.
            score_fields: List of field names to update (e.g., ['recurrence_probability']).
            batch_size: Number of objects to update per database query.

        Returns:
            Number of objects updated (Note: Django's bulk_update returns None,
            so we return the count of iocs provided).
        """
        if not iocs:
            return 0
        IOC.objects.bulk_update(iocs, score_fields, batch_size=batch_size)
        return len(iocs)

    def delete_old_iocs(self, cutoff_date) -> int:
        """
        Delete IOC records older than the specified cutoff date.

        Args:
            cutoff_date: DateTime threshold - IOCs with last_seen before this will be deleted.

        Returns:
            Number of IOC objects deleted.
        """
        deleted_count, _ = IOC.objects.filter(last_seen__lte=cutoff_date).delete()
        return deleted_count

    def update_ioc_reputation(self, ip_address: str, reputation: str) -> bool:
        """
        Update the IP reputation for a specific IOC.

        Args:
            ip_address: IP address to update.
            reputation: New reputation value.

        Returns:
            True if IOC was found and updated, False otherwise.
        """
        try:
            ioc = IOC.objects.get(name=ip_address)
        except IOC.DoesNotExist:
            return False
        else:
            ioc.ip_reputation = reputation
            ioc.save()
            self.log.info(f"Updated IOC {ip_address} reputation to '{reputation}'")
            return True

    def bulk_update_ioc_reputation(self, ip_addresses: list[str], reputation: str) -> int:
        """
        Bulk update the IP reputation for a list of IOCs.

        Args:
            ip_addresses: List of IP addresses to update.
            reputation: New reputation value.

        Returns:
            Number of IOC records updated.
        """
        if not ip_addresses:
            return 0
        return IOC.objects.filter(name__in=ip_addresses).update(ip_reputation=reputation)
