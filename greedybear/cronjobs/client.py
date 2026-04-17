import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HttpClient:
    """
    A shared HTTP client wrapper based on requests.Session.
    Provides standard defaults like timeouts, retries, and automatic error raising.
    """

    def __init__(self, default_timeout=10.0, retries=3, backoff_factor=0.3):
        self.default_timeout = default_timeout
        self.session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=backoff_factor,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        """
        Sends a request using the configured session.
        Applies default timeout if not provided and raises for status automatically.
        """
        # Apply default timeout if not specified
        kwargs.setdefault("timeout", self.default_timeout)

        # Execute the request
        response = self.session.request(method, url, **kwargs)

        # Always raise for status to ensure consistent error handling
        response.raise_for_status()

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
