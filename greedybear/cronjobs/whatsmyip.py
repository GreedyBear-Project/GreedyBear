import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.models import IOC, WhatsMyIPDomain


class WhatsMyIPCron(Cronjob):
    """Fetch and store 'What's My IP' domains from MISP warning lists."""

    def run(self) -> None:
        try:
            r = requests.get(
                "https://raw.githubusercontent.com/MISP/misp-warninglists/refs/heads/main/lists/whats-my-ip/list.json",
                timeout=10,
            )
            r.raise_for_status()
        except requests.RequestException:
            self.log.exception("Failed to fetch whats-my-ip list")
            raise

        try:
            json_file = r.json()
        except ValueError:
            self.log.exception("Failed to parse whats-my-ip response as JSON")
            raise

        if "list" not in json_file:
            self.log.error("Unexpected JSON structure: missing 'list' key")
            raise KeyError("Missing 'list' key in whats-my-ip JSON response")

        for domain in json_file["list"]:
            try:
                WhatsMyIPDomain.objects.get(domain=domain)
            except WhatsMyIPDomain.DoesNotExist:
                WhatsMyIPDomain(domain=domain).save()
                self.log.info(f"added new whatsmyip domain {domain=}")
                self._remove_old_ioc(domain)

    def _remove_old_ioc(self, domain):
        try:
            ioc = IOC.objects.get(name=domain)
        except IOC.DoesNotExist:
            pass
        else:
            ioc.delete()
            self.log.info(f"deleted whatsmyip {domain=}")
