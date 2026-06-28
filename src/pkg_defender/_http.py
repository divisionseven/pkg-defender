"""Shared HTTP fetch utility with retry, backoff with jitter, and configurable error handling."""

from __future__ import annotations

import logging
import random
from asyncio import sleep as _asyncio_sleep
from dataclasses import dataclass
from typing import Any, Literal

import aiohttp

from pkg_defender.config import get_http_timeout, get_max_retries
from pkg_defender.core.registry_domains import is_domain_allowed
from pkg_defender.exceptions import SecurityError

logger = logging.getLogger(__name__)

# Default retryable HTTP status codes (server errors + rate limit)
_DEFAULT_RETRYABLE_STATUSES: tuple[int, ...] = (429, 500, 502, 503, 504)


def calc_retry_wait(attempt: int, status: int, resp: aiohttp.ClientResponse) -> float:
    """Calculate retry wait time, respecting Retry-After header for 429 responses.

    For 429 (rate limit) responses, the server's Retry-After header takes
    precedence when present and parseable. Falls back to exponential backoff
    with jitter for other retryable statuses or when the header is missing
    or invalid.

    Args:
        attempt: Current retry attempt number (0-based).
        status: HTTP response status code.
        resp: The aiohttp response object (for accessing headers).

    Returns:
        Wait time in seconds.
    """
    if status == 429:
        try:
            retry_after = resp.headers.get("Retry-After", "60")
        except (AttributeError, TypeError):
            pass
        else:
            try:
                return int(retry_after)
            except (ValueError, TypeError):
                pass
    return 2**attempt + random.uniform(0, 1)  # type: ignore[no-any-return]


@dataclass
class FetchResult:
    """Result of an HTTP fetch operation."""

    data: dict[str, Any] | list[Any] | None = None
    status: int | None = None
    error: str | None = None
    success: bool = True


async def fetch_json(
    url: str,
    *,
    method: Literal["GET", "POST"] = "GET",
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float | None = None,
    max_retries: int | None = None,
    retryable_statuses: tuple[int, ...] | None = None,
    session: aiohttp.ClientSession | None = None,
    on_404: Literal["raise", "return_none"] = "raise",
    manager: str | None = None,
) -> FetchResult:
    """
    Fetch JSON from a URL with retry, backoff with jitter, and configurable
    error handling.

    Args:
        url: The URL to fetch.
        method: HTTP method (GET or POST).
        headers: Optional HTTP headers.
        json_body: Optional JSON body for POST requests.
        timeout: Request timeout in seconds. Defaults to config value.
        max_retries: Maximum number of retry attempts. Defaults to config value.
        retryable_statuses: HTTP status codes that trigger a retry.
            Defaults to (429, 500, 502, 503, 504).
        session: Optional aiohttp session for connection pooling.
        on_404: Whether to raise on 404 or return FetchResult with data=None.
        manager: Optional package manager name for SSRF domain allowlist
            check. When provided, the URL's domain is verified against the
            manager's allowlist before the request is made. ``None`` skips
            the check (backward-compatible default).

    Returns:
        FetchResult with data on success, or error details on failure.

    Raises:
        aiohttp.ClientResponseError: On non-retryable HTTP errors (4xx except 429).
        aiohttp.ClientError: On network errors (after retries exhausted).
        TimeoutError: On timeout (after retries exhausted).
        SecurityError: When the URL domain is not in the manager's allowlist.
    """
    # SSRF defense-in-depth: verify domain against allowlist before request
    if manager is not None and not is_domain_allowed(manager, url):
        raise SecurityError(f"SSRF domain check failed: {url!r} is not in the allowlist for manager {manager!r}")

    _timeout = timeout if timeout is not None else get_http_timeout()
    _max_retries = max_retries if max_retries is not None else get_max_retries()
    _retryable = retryable_statuses if retryable_statuses is not None else _DEFAULT_RETRYABLE_STATUSES

    async def _do_fetch(sess: aiohttp.ClientSession) -> FetchResult:
        for attempt in range(_max_retries):
            resp: aiohttp.ClientResponse | None = None
            try:
                timeout_cfg = aiohttp.ClientTimeout(total=_timeout)
                async with sess.request(method, url, headers=headers, json=json_body, timeout=timeout_cfg) as resp:
                    # Handle 404 based on caller preference
                    if resp.status == 404 and on_404 == "return_none":
                        return FetchResult(data=None, status=404, success=True)

                    resp.raise_for_status()
                    data = await resp.json()
                    return FetchResult(data=data, status=resp.status, success=True)

            except aiohttp.ClientResponseError as exc:
                if exc.status in _retryable:
                    if attempt < _max_retries - 1:
                        if resp is not None:
                            wait = calc_retry_wait(attempt, exc.status, resp)
                        else:
                            wait = 2**attempt + random.uniform(0, 1)
                        logger.debug(
                            "HTTP %d on %s, retrying in %.1fs (attempt %d/%d)",
                            exc.status,
                            url,
                            wait,
                            attempt + 1,
                            _max_retries,
                        )
                        await _asyncio_sleep(wait)
                        continue
                    raise  # Retries exhausted

                # Non-retryable status — raise immediately
                raise

            except (TimeoutError, aiohttp.ClientError) as exc:
                if attempt < _max_retries - 1:
                    wait = 2**attempt + random.uniform(0, 1)
                    logger.debug(
                        "Network error on %s, retrying in %.1fs (attempt %d/%d): %s",
                        url,
                        wait,
                        attempt + 1,
                        _max_retries,
                        exc,
                    )
                    await _asyncio_sleep(wait)
                    continue
                raise

        # Should not be reached
        raise RuntimeError(f"Unreachable: failed to fetch {url} after {_max_retries} retries")

    if session is not None:
        return await _do_fetch(session)

    async with aiohttp.ClientSession() as tmp_session:
        return await _do_fetch(tmp_session)
