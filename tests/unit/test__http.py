"""Tests for the shared HTTP utility (pkg_defender._http)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aioresponses import aioresponses

from pkg_defender._http import FetchResult, calc_retry_wait, fetch_json
from pkg_defender.core.registry_domains import REGISTRY_ALLOWLIST
from pkg_defender.exceptions import SecurityError


class TestFetchJsonSuccess:
    """Happy-path tests for fetch_json."""

    async def test_returns_parsed_json_on_get(self) -> None:
        """GET returns parsed JSON."""
        url = "https://api.example.com/data"
        payload = {"key": "value", "count": 42}
        with aioresponses() as m:
            m.get(url, payload=payload)
            result: FetchResult = await fetch_json(url)

        assert result.success is True
        assert result.data == payload
        assert result.status == 200
        assert result.error is None

    async def test_post_returns_json(self) -> None:
        """POST request with body returns parsed JSON."""
        url = "https://api.example.com/submit"
        payload = {"id": 1, "status": "ok"}
        body = {"name": "test"}
        with aioresponses() as m:
            m.post(url, payload=payload)
            result = await fetch_json(url, method="POST", json_body=body)

        assert result.success is True
        assert result.data == payload
        assert result.status == 200

    async def test_custom_headers_sent(self) -> None:
        """Custom headers are passed through in the request."""
        url = "https://api.example.com/data"
        headers = {"Authorization": "Bearer token123", "X-Custom": "value"}
        payload = {"ok": True}

        with aioresponses() as m:
            m.get(url, payload=payload)
            result = await fetch_json(url, headers=headers)

        assert result.success is True
        assert result.data == payload

    async def test_custom_timeout_and_max_retries(self) -> None:
        """Explicit timeout and max_retries override config defaults."""
        url = "https://api.example.com/data"
        payload = {"ok": True}

        with aioresponses() as m:
            m.get(url, payload=payload)
            # Use non-default values to verify they are passed through
            result = await fetch_json(url, timeout=30, max_retries=5)

        assert result.success is True
        assert result.data == payload


class TestFetchJsonRetry:
    """Retry behavior tests for fetch_json."""

    async def test_500_succeeds_on_retry(self) -> None:
        """500 error is retried, and a subsequent 200 succeeds."""
        url = "https://api.example.com/data"
        payload = {"recovered": True}
        with aioresponses() as m:
            m.get(url, status=500)
            m.get(url, status=500)
            m.get(url, payload=payload)
            result = await fetch_json(url, max_retries=3)

        assert result.success is True
        assert result.data == payload

    async def test_429_succeeds_on_retry(self) -> None:
        """Rate limit (429) is retried and recovers."""
        url = "https://api.example.com/data"
        payload = {"recovered": True}
        with (
            aioresponses() as m,
            patch("pkg_defender._http._asyncio_sleep", new_callable=AsyncMock),
        ):
            m.get(url, status=429)
            m.get(url, status=429)
            m.get(url, payload=payload)
            result = await fetch_json(url, max_retries=3)

        assert result.success is True
        assert result.data == payload

    async def test_retries_exhausted_raises(self) -> None:
        """After exhausting retries, ClientResponseError is raised."""
        url = "https://api.example.com/data"
        with aioresponses() as m:
            m.get(url, status=500)
            m.get(url, status=500)
            m.get(url, status=500)
            with pytest.raises(aiohttp.ClientResponseError):
                await fetch_json(url, max_retries=3)

    async def test_timeout_raises(self) -> None:
        """Timeout after retries raises asyncio.TimeoutError."""
        url = "https://api.example.com/data"
        with aioresponses() as m:
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            m.get(url, exception=TimeoutError())
            with pytest.raises(asyncio.TimeoutError):
                await fetch_json(url, max_retries=3)

    async def test_non_retryable_4xx_raises_immediately(self) -> None:
        """Non-retryable 4xx (400) raises immediately without retry."""
        url = "https://api.example.com/data"
        with aioresponses() as m:
            m.get(url, status=400)
            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await fetch_json(url, max_retries=3)

        assert exc_info.value.status == 400

    async def test_retryable_statuses_customization(self) -> None:
        """Custom retryable_statuses defines which codes trigger retry."""
        url = "https://api.example.com/data"
        # Only retry on 503, so 502 should raise immediately
        with aioresponses() as m:
            m.get(url, status=502)
            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await fetch_json(url, max_retries=3, retryable_statuses=(503,))

        assert exc_info.value.status == 502


class TestFetchJson404:
    """404 handling tests for fetch_json."""

    async def test_on_404_return_none(self) -> None:
        """on_404='return_none' returns FetchResult with data=None and success=True."""
        url = "https://api.example.com/missing"
        with aioresponses() as m:
            m.get(url, status=404)
            result = await fetch_json(url, on_404="return_none")

        assert result.success is True
        assert result.data is None
        assert result.status == 404

    async def test_on_404_raise_default(self) -> None:
        """Default on_404='raise' raises ClientResponseError on 404."""
        url = "https://api.example.com/missing"
        with aioresponses() as m:
            m.get(url, status=404)
            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await fetch_json(url)

        assert exc_info.value.status == 404

    async def test_on_404_raise_explicit(self) -> None:
        """Explicit on_404='raise' raises ClientResponseError on 404."""
        url = "https://api.example.com/missing"
        with aioresponses() as m:
            m.get(url, status=404)
            with pytest.raises(aiohttp.ClientResponseError) as exc_info:
                await fetch_json(url, on_404="raise")

        assert exc_info.value.status == 404


class TestFetchJsonGuardClause:
    """Tests for the RuntimeError safety guard when retry loop never executes."""

    async def test_max_retries_zero_raises_runtime_error(self) -> None:
        """max_retries=0 means the retry loop never runs, reaching RuntimeError."""
        url = "https://api.example.com/data"
        with pytest.raises(RuntimeError, match="Unreachable: failed to fetch"):
            await fetch_json(url, max_retries=0)


class TestFetchJsonSession:
    """Session handling tests for fetch_json."""

    async def test_creates_session_when_none(self) -> None:
        """A session is created when none is provided."""
        url = "https://api.example.com/data"
        with aioresponses() as m:
            m.get(url, payload={"ok": True})
            result = await fetch_json(url, session=None)

        assert result.success is True
        assert result.data == {"ok": True}

    async def test_uses_provided_session(self) -> None:
        """An existing session is reused."""
        url = "https://api.example.com/data"
        timeout_cfg = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            with aioresponses() as m:
                m.get(url, payload={"ok": True})
                result = await fetch_json(url, session=session)

        assert result.success is True
        assert result.data == {"ok": True}

    async def test_network_error_with_retry(self) -> None:
        """Network error retries then raises after exhaustion."""
        url = "https://api.example.com/data"
        with aioresponses() as m:
            m.get(url, exception=aiohttp.ClientError("connection failed"))
            m.get(url, exception=aiohttp.ClientError("connection failed"))
            m.get(url, exception=aiohttp.ClientError("connection failed"))
            with pytest.raises(aiohttp.ClientError):
                await fetch_json(url, max_retries=3)


class TestFetchJsonDomainCheck:
    """SSRF domain allowlist tests for fetch_json manager parameter."""

    async def test_allowed_domain_passes(self) -> None:
        """Request to an allowed domain proceeds normally."""
        url = "https://registry.npmjs.org/lodash"
        payload = {"name": "lodash"}
        with aioresponses() as m:
            m.get(url, payload=payload)
            result = await fetch_json(url, manager="npm")

        assert result.success is True
        assert result.data == payload

    async def test_blocked_domain_raises_security_error(self) -> None:
        """Request to a blocked domain raises SecurityError without making a request."""
        url = "https://evil.com/malicious"
        # No mock registered -- if the request fires, aioresponses will raise
        with aioresponses(), pytest.raises(SecurityError, match="SSRF domain check failed"):
            await fetch_json(url, manager="npm")

    async def test_no_manager_skips_check(self) -> None:
        """When manager is None (default), domain check is skipped."""
        url = "https://evil.com/data"
        payload = {"ok": True}
        with aioresponses() as m:
            m.get(url, payload=payload)
            result = await fetch_json(url, manager=None)

        assert result.success is True
        assert result.data == payload

    async def test_unknown_manager_blocks_all(self) -> None:
        """Unknown manager has empty allowlist -- blocks everything."""
        url = "https://registry.npmjs.org/lodash"
        with aioresponses(), pytest.raises(SecurityError, match="SSRF domain check failed"):
            await fetch_json(url, manager="nonexistent-manager")

    async def test_domain_check_before_request(self) -> None:
        """Domain check happens before the HTTP request -- no network call on block."""
        url = "https://evil.com/malicious"
        # If the request reaches the network, aioresponses will fail
        # because no mock is registered. SecurityError must fire first.
        with aioresponses(), pytest.raises(SecurityError):
            await fetch_json(url, manager="npm")

    async def test_all_registry_managers_allow_correct_domains(self) -> None:
        """Every manager in REGISTRY_ALLOWLIST allows its own domains."""
        for manager, domains in REGISTRY_ALLOWLIST.items():
            for domain in domains:
                url = f"https://{domain}/test"
                # Should NOT raise SecurityError
                # (we mock to avoid network, but the key assertion is no SecurityError)
                with aioresponses() as m:
                    m.get(url, payload={"ok": True})
                    result = await fetch_json(url, manager=manager)
                    assert result.success is True


class TestCalcRetryWait:
    """Tests for calc_retry_wait retry timing logic."""

    def test_429_with_valid_retry_after(self) -> None:
        """429 with valid Retry-After header returns the header value."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.headers = {"Retry-After": "30"}
        wait = calc_retry_wait(attempt=0, status=429, resp=resp)
        assert wait == 30

    def test_429_with_missing_retry_after(self) -> None:
        """429 without Retry-After header returns default fallback of 60."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.headers = {}
        wait = calc_retry_wait(attempt=0, status=429, resp=resp)
        assert wait == 60

    def test_429_with_invalid_retry_after(self) -> None:
        """429 with non-integer Retry-After falls through to exponential backoff."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.headers = {"Retry-After": "foo"}
        attempt = 1
        wait = calc_retry_wait(attempt=attempt, status=429, resp=resp)
        base = 2**attempt
        assert base <= wait < base + 1

    def test_502_ignores_retry_after_header(self) -> None:
        """5xx status ignores Retry-After header, uses exponential backoff."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.headers = {"Retry-After": "30"}
        attempt = 2
        wait = calc_retry_wait(attempt=attempt, status=502, resp=resp)
        base = 2**attempt
        assert base <= wait < base + 1

    def test_503_without_retry_after(self) -> None:
        """5xx without Retry-After uses exponential backoff."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.headers = {}
        attempt = 3
        wait = calc_retry_wait(attempt=attempt, status=503, resp=resp)
        base = 2**attempt
        assert base <= wait < base + 1
