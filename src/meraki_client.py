"""Read-only HTTP client for the Meraki Dashboard API v1.

DESIGN CONSTRAINT: this module issues GET requests only. There is no method here
that can POST, PUT or DELETE, and `_get` hardcodes the verb. A tool that audits
production network configuration must not be able to change it. If someone
asks "could running this take a site down?", the answer has to be provably no,
and "provably" means one grep, not a code review.

The three things this handles that are easy to get wrong:

  1. Pagination. Meraki paginates large collections with `perPage` and an
     opaque `startingAfter` cursor, and hands you the next page as a full URL
     in an RFC 8288 `Link` header. You follow that URL; you don't build it.
  2. Rate limits. The Dashboard API allows roughly 10 requests per second per
     organization and answers 429 with a `Retry-After` header in seconds.
     Honour the header rather than sleeping a fixed amount.
  3. Errors. A 401 or 404 should say what to do next, not just print a status.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterator, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.meraki.com/api/v1"

MAX_RETRIES = 5
DEFAULT_BACKOFF_SECONDS = 2
MAX_SLEEP_SECONDS = 60
DEFAULT_TIMEOUT = 30


class MerakiError(Exception):
    """Base class for every error this client deliberately raises."""


class MerakiAuthError(MerakiError):
    """401/403 — the key is wrong, revoked, or lacks access to this resource."""


class MerakiNotFoundError(MerakiError):
    """404 — the resource doesn't exist *for this network*.

    Common and non-fatal. Meraki returns 404 (or 400) for product-specific
    endpoints on networks that don't contain that product: asking a
    wireless-only network for its appliance VLANs is a 404, not a bug. Checks
    treat it as "not applicable".
    """


class MerakiRateLimitError(MerakiError):
    """429 that survived every retry."""


class MerakiAPIError(MerakiError):
    """Any other non-2xx response."""


class MerakiClient:
    """A thin, read-only wrapper around the Meraki Dashboard API.

    Args:
        api_key: the Dashboard API key. Never logged, never put in an exception.
        base_url: override for regional clouds (e.g. China, Canada) or tests.
        timeout: per-request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError(
                "api_key is required. Set MERAKI_API_KEY in your .env file - see "
                ".env.example. Never pass a key as a command-line argument; it "
                "ends up in your shell history."
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        # One Session: headers set once, TCP/TLS connection reused across the
        # hundreds of calls a multi-site audit makes.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "meraki-config-auditor/0.1 (read-only)",
            }
        )

    # ---------------------------------------------------------------- internals

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return f"{self.base_url}/{path_or_url.lstrip('/')}"

    @staticmethod
    def _sleep_seconds(response: requests.Response) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.5, min(float(retry_after), MAX_SLEEP_SECONDS))
            except (TypeError, ValueError):
                logger.debug("Unparseable Retry-After: %r", retry_after)
        return DEFAULT_BACKOFF_SECONDS

    def _raise_for_status(self, response: requests.Response) -> None:
        if response.ok:
            return

        detail = ""
        try:
            body = response.json()
            errors = body.get("errors") if isinstance(body, dict) else None
            if errors:
                detail = " Meraki says: " + "; ".join(str(e) for e in errors)
        except ValueError:
            detail = f" Response body: {response.text[:200]}"

        url = response.url
        status = response.status_code

        if status == 401:
            raise MerakiAuthError(
                "401 Unauthorized - the API key was rejected.\n"
                "  Check MERAKI_API_KEY in your .env. Keys are revoked when the "
                "admin who generated them is removed, and DevNet sandbox keys "
                "rotate - fetch the current one from the sandbox page."
                f"{detail}"
            )
        if status == 403:
            raise MerakiAuthError(
                f"403 Forbidden - the key is valid but cannot read {url}.\n"
                "  A key inherits the permissions of the admin who generated "
                "it. Network-scoped admins can't read org-level endpoints. A "
                "read-only *organization* admin is sufficient for this tool."
                f"{detail}"
            )
        if status in (400, 404):
            # Meraki uses 400 as well as 404 for "this product isn't in this
            # network", so both map to not-found for the checks' purposes.
            raise MerakiNotFoundError(
                f"{status} - {url}\n"
                "  Usually means the network doesn't contain the product this "
                "endpoint is for (e.g. appliance VLANs on a switch-only network)."
                f"{detail}"
            )
        if status == 429:
            raise MerakiRateLimitError(
                f"429 Too Many Requests - gave up after {MAX_RETRIES} retries on "
                f"{url}.\n"
                "  The Dashboard API budget is shared by every application using "
                "this organization. The DevNet sandbox is shared by everyone, so "
                "it is rate limited far more often than a real org.\n"
                "  Fix: rerun with --checks to audit fewer things, or wait a minute."
                f"{detail}"
            )
        raise MerakiAPIError(f"{status} from {url}.{detail}")

    def _get(
        self, path_or_url: str, params: Optional[Dict[str, Any]] = None
    ) -> requests.Response:
        """Issue one GET, retrying on 429.

        This is the only place in the codebase that performs a network request,
        and it is hardcoded to GET. That is the read-only guarantee, in one line.
        """
        url = self._url(path_or_url)
        last: Optional[requests.Response] = None

        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
            except requests.exceptions.Timeout as exc:
                raise MerakiAPIError(
                    f"Request to {url} timed out after {self.timeout}s."
                ) from exc
            except requests.exceptions.ConnectionError as exc:
                raise MerakiAPIError(
                    f"Could not connect to {url}. Check your network, proxy, and "
                    "that api.meraki.com is reachable from here."
                ) from exc

            if response.status_code != 429:
                self._raise_for_status(response)
                return response

            last = response
            wait = self._sleep_seconds(response)
            logger.warning(
                "Rate limited on %s (attempt %d/%d); sleeping %.1fs",
                url, attempt + 1, MAX_RETRIES, wait,
            )
            time.sleep(wait)

        assert last is not None
        self._raise_for_status(last)
        raise MerakiRateLimitError(f"Exhausted retries on {url}")  # pragma: no cover

    # ------------------------------------------------------------------- public

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET one resource and return decoded JSON."""
        return self._get(path, params=params).json()

    def paginate(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        """Yield every item across every page, following `Link: rel=next`.

        A generator: nothing is fetched until iterated, and a caller that
        breaks early never requests the remaining pages.
        """
        url: Optional[str] = path
        while url:
            response = self._get(url, params=params)
            payload = response.json()
            if isinstance(payload, list):
                yield from payload
            else:
                yield payload
            url = response.links.get("next", {}).get("url")
            # The next URL already carries the cursor; resending params would
            # duplicate or overwrite it.
            params = None

    def get_optional(
        self, path: str, params: Optional[Dict[str, Any]] = None, default: Any = None
    ) -> Any:
        """GET, returning `default` when the endpoint doesn't apply here."""
        try:
            return self.get(path, params=params)
        except (MerakiNotFoundError, MerakiAuthError) as exc:
            logger.info("Skipping %s: %s", path, str(exc).splitlines()[0])
            return default

    def verify_connection(self) -> Any:
        """One cheap call to fail fast on a bad key, before any check runs."""
        return self.get("/organizations")

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "MerakiClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
