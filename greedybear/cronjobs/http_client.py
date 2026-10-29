import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class FingerprintAdapter(HTTPAdapter):
    """
    HTTPAdapter that pins the server certificate to a SHA-256 fingerprint.
    """

    def __init__(self, fingerprint: str, **kwargs):
        self.fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """Add fingerprint and turn off the hostname check before the PoolManager is created."""
        pool_kwargs["assert_fingerprint"] = self.fingerprint
        pool_kwargs["assert_hostname"] = False
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Connections through a proxy use their own pool manager, which must pin the cert as well."""
        proxy_kwargs["assert_fingerprint"] = self.fingerprint
        proxy_kwargs["assert_hostname"] = False
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class HttpClient:
    """
    A shared HTTP client wrapper based on requests.Session.
    Provides standard defaults like timeouts, retries, and automatic error raising.

    If cert_fingerprint is given, HTTPS connections only accept a server
    certificate with this SHA-256 fingerprint (hex, colons optional).
    """

    def __init__(self, default_timeout=10.0, retries=3, backoff_factor=0.3, cert_fingerprint: str | None = None):
        self.default_timeout = default_timeout
        self.session = requests.Session()

        # Configure retries for idempotent methods only (urllib3 defaults).
        # POST is intentionally excluded to prevent duplicate side effects.
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=backoff_factor,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        if cert_fingerprint is None:
            self.session.mount("https://", adapter)
            return

        # Use fingerprint
        self.session.mount("https://", FingerprintAdapter(cert_fingerprint, max_retries=retry_strategy))
        self.session.verify = False # the pinned fingerprint replaces CA validation

    def request(self, method, url, **kwargs):
        """
        Sends a request using the configured session.
        Applies default timeout if not provided and raises for status automatically.
        """
        # Apply default timeout if not specified
        kwargs.setdefault("timeout", self.default_timeout)

        logger.debug(f"Sending {method} request to {url}")

        try:
            # Execute the request
            response = self.session.request(method, url, **kwargs)

            # Always raise for status to ensure consistent error handling
            response.raise_for_status()
        except requests.RequestException:
            logger.exception(f"HTTP Request failed for {method} {url}")
            raise
        else:
            return response

    def get(self, url, **kwargs):
        """Sends a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """Sends a POST request."""
        return self.request("POST", url, data=data, json=json, **kwargs)

    def close(self):
        """Closes the underlying session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
