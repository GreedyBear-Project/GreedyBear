from django.db.models import Count

from greedybear.cache import invalidate_ioc_cache
from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, IocType

# heuristic thresholds
MIN_LOGIN_ATTEMPTS = 5
MIN_DAYS_SEEN = 2
MIN_CREDENTIAL_REUSE = 10

# Max candidates per run
MAX_CANDIDATES = 500


class CredentialReuseCron(Cronjob):
    """
    Experimental heuristic to highlight IPs that:
    - perform repeated login attempts
    - persist over time
    - interact with widely reused credentials

    This is intended as a lightweight exploratory signal
    to help analyze patterns in login activity, not a
    definitive classification of attacker behavior.
    """

    def run(self) -> None:
        candidates = self._get_candidates()

        if not candidates:
            self.log.info("No credential reuse candidates found")
            return

        self.log.info(f"Found {len(candidates)} credential reuse candidates")

        ioc_ids = []
        for ioc_id, name, credential_reuse in candidates:
            self.log.debug(f"credential reuse candidate: {name} (shared across {credential_reuse} IPs)")
            ioc_ids.append(ioc_id)

        # Only ever sets the flag to True. Candidates already flagged are
        # excluded in _get_candidates, and a flag is never removed.
        flagged = IOC.objects.filter(id__in=ioc_ids).update(high_credential_reuse=True)

        self.log.info(f"Credential reuse detection complete: flagged {flagged} IPs")
        invalidate_ioc_cache()

    def _get_candidates(self) -> list[tuple]:
        queryset = (
            IOC.objects.filter(
                type=IocType.IP,
                login_attempts__gte=MIN_LOGIN_ATTEMPTS,
                number_of_days_seen__gte=MIN_DAYS_SEEN,
                credentials__isnull=False,
                high_credential_reuse=False,
            )
            .annotate(
                credential_reuse=Count(
                    "credentials__sources",
                    distinct=True,
                )
            )
            .filter(credential_reuse__gte=MIN_CREDENTIAL_REUSE)
            .order_by("-credential_reuse")
            .values_list("id", "name", "credential_reuse")
            .distinct()
        )

        return list(queryset[:MAX_CANDIDATES])
