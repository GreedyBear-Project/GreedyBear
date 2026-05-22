from django.db.models import Count

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC, IocType

# source name used for tagging
SOURCE_NAME = "credential_reuse"

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

    def __init__(self, tag_repo=None):
        super().__init__()
        self.tag_repo = tag_repo or TagRepository()

    def run(self) -> None:
        candidates = self._get_candidates()

        if not candidates:
            self.log.info("No credential reuse candidates found")
            return

        self.log.info(f"Found {len(candidates)} credential reuse candidates")

        tag_entries = []
        for ioc_id, name, credential_reuse in candidates:
            self.log.debug(f"credential reuse candidate: {name} (shared across {credential_reuse} IPs)")

            tag_entries.append(
                {
                    "ioc_id": ioc_id,
                    "key": "behavior",
                    "value": "high_credential_reuse",
                }
            )

        created = self.tag_repo.add_tags(SOURCE_NAME, tag_entries)

        self.log.info(f"Credential reuse detection complete: tagged {created} IPs")

    def _get_candidates(self) -> list[tuple]:
        queryset = (
            IOC.objects.filter(
                type=IocType.IP,
                login_attempts__gte=MIN_LOGIN_ATTEMPTS,
                number_of_days_seen__gte=MIN_DAYS_SEEN,
                credentials__isnull=False,
            )
            .annotate(
                credential_reuse=Count(
                    "credentials__sources",
                    distinct=True,
                )
            )
            .exclude(tags__source=SOURCE_NAME)
            .filter(credential_reuse__gte=MIN_CREDENTIAL_REUSE)
            .order_by("-credential_reuse")
            .values_list("id", "name", "credential_reuse")
            .distinct()
        )

        return list(queryset[:MAX_CANDIDATES])
