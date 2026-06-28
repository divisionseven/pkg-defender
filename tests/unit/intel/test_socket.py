"""Tests for the Socket.dev feed source."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.intel.base import FeedFetchResult, FetchStatus
from pkg_defender.intel.socket import (
    SOCKET_API_BASE,
    SocketFeed,
    _get_api_key,
    _score_to_severity,
    _socket_fetch,
)

# =========================================================================
# Helpers — shared mock factories
# =========================================================================


def _make_response(
    status: int = 200,
    json_data: dict | None = None,
    exc: Exception | None = None,
) -> MagicMock:
    """Build a mock ``aiohttp.ClientResponse``.

    Args:
        status: HTTP status code.
        json_data: Payload returned by ``.json()``.
        exc: If provided, ``raise_for_status()`` raises this exception.

    Returns:
        A configured mock response.
    """
    resp = MagicMock(spec=aiohttp.ClientResponse)
    resp.status = status
    if exc is not None:
        resp.raise_for_status = MagicMock(side_effect=exc)
    else:
        resp.raise_for_status = MagicMock()
    resp.json = AsyncMock(return_value=json_data or {})
    return resp


def _make_session(responses: list[MagicMock] | MagicMock) -> MagicMock:
    """Build a mock ``aiohttp.ClientSession``.

    Args:
        responses: One or more mock response objects (``side_effect`` list).

    Returns:
        A configured mock session.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    session.get = AsyncMock(
        side_effect=responses if isinstance(responses, list) else [responses],
    )
    session.close = AsyncMock()
    return session


# =========================================================================
# _get_api_key
# =========================================================================


class TestGetApiKey:
    """Tests for _get_api_key()."""

    def test_returns_key_when_present(self) -> None:
        """Key present in config with trailing whitespace → returns stripped key."""
        mock_config = MagicMock()
        mock_config.feeds.socket_api_key = "my-api-key  "

        with patch("pkg_defender.intel.socket.load_config", return_value=mock_config):
            result = _get_api_key()

        assert result == "my-api-key"

    def test_returns_none_when_key_empty(self) -> None:
        """Key is empty string → returns None."""
        mock_config = MagicMock()
        mock_config.feeds.socket_api_key = ""

        with patch("pkg_defender.intel.socket.load_config", return_value=mock_config):
            result = _get_api_key()

        assert result is None

    def test_returns_none_when_key_whitespace(self) -> None:
        """Key is whitespace-only → returns None."""
        mock_config = MagicMock()
        mock_config.feeds.socket_api_key = "   \t  "

        with patch("pkg_defender.intel.socket.load_config", return_value=mock_config):
            result = _get_api_key()

        assert result is None


class TestGetApiKeyLogging:
    """Regression tests for ``logger.debug`` on ``_get_api_key`` config load failure.

    S15 added ``logger.debug()`` before bare ``except Exception`` blocks that were
    silently swallowing errors. This test verifies that debug logging occurs
    when ``load_config`` raises during API key retrieval.
    """

    def test_get_api_key_logs_debug_on_config_load_failure(self) -> None:
        """When ``load_config`` raises, ``logger.debug`` must be called.

        Root cause: ``pkg_defender/intel/socket.py:39`` — bare ``except Exception:``
        block that silently passed before S15. Now logs debug before continuing.
        This test FAILS before the fix and PASSES after.

        Scenario: ``load_config()`` raises ``RuntimeError("config error")``.
        Expected: returns None, calls ``logger.debug("socket: config load for API key failed")``.
        Previously: exception was silently swallowed via bare ``except Exception: pass``.
        """
        from pkg_defender.intel.socket import _get_api_key

        with (
            patch(
                "pkg_defender.intel.socket.load_config",
                side_effect=RuntimeError("config error"),
            ),
            patch("pkg_defender.intel.socket.logger") as mock_logger,
        ):
            result = _get_api_key()

        assert result is None
        mock_logger.debug.assert_called_once()
        args, _ = mock_logger.debug.call_args
        assert "socket" in args[0]
        assert "config load" in args[0]
        assert "failed" in args[0]


# =========================================================================
# _score_to_severity
# =========================================================================


class TestScoreToSeverity:
    """Tests for _score_to_severity()."""

    # (supply_chain_risk, malware, expected_severity)
    @pytest.mark.parametrize(
        ("sc_risk", "malware", "expected"),
        [
            # ----- malware >= 0.8 → CRITICAL -----
            (0.0, 0.8, "CRITICAL"),
            (0.0, 0.9, "CRITICAL"),
            (0.0, 1.0, "CRITICAL"),
            (0.5, 0.8, "CRITICAL"),
            (0.9, 0.8, "CRITICAL"),
            (1.0, 1.0, "CRITICAL"),
            # ----- malware >= 0.5 or SC >= 0.9 → HIGH -----
            # malware 0.5-0.79
            (0.0, 0.5, "HIGH"),
            (0.0, 0.6, "HIGH"),
            (0.0, 0.79, "HIGH"),
            (0.69, 0.5, "HIGH"),
            # SC >= 0.9
            (0.9, 0.0, "HIGH"),
            (0.9, 0.4, "HIGH"),
            (1.0, 0.0, "HIGH"),
            (0.95, 0.0, "HIGH"),
            # ----- SC >= 0.7 → MEDIUM -----
            (0.7, 0.0, "MEDIUM"),
            (0.7, 0.49, "MEDIUM"),
            (0.8, 0.0, "MEDIUM"),
            (0.89, 0.0, "MEDIUM"),
            # ----- everything else → UNKNOWN -----
            (0.0, 0.0, "UNKNOWN"),
            (0.69, 0.0, "UNKNOWN"),
            (0.0, 0.49, "UNKNOWN"),
            (0.69, 0.49, "UNKNOWN"),
            # ----- Edge: negative values (must not crash) -----
            (-0.1, 0.0, "UNKNOWN"),
            (-1.0, 0.0, "UNKNOWN"),
            (0.0, -0.1, "UNKNOWN"),
            (0.0, -1.0, "UNKNOWN"),
            (-0.5, 0.9, "CRITICAL"),
            # ----- Edge: values > 1.0 (must not crash) -----
            (1.5, 0.0, "HIGH"),
            (2.0, 0.0, "HIGH"),
            (0.0, 0.85, "CRITICAL"),
            (0.0, 1.5, "CRITICAL"),
        ],
    )
    def test_score_to_severity(self, sc_risk: float, malware: float, expected: str) -> None:
        """Verify severity mapping for all boundary conditions."""
        assert _score_to_severity(sc_risk, malware) == expected


# =========================================================================
# _socket_fetch
# =========================================================================


class TestSocketFetch:
    """Tests for _socket_fetch()."""

    # ------------------------------------------------------------------
    # Success paths
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_returns_parsed_json_when_fetch_succeeds(self) -> None:
        """200 + valid JSON → returns parsed dict."""
        data = {"key": "value", "score": {"supplyChainRisk": 0.8}}
        session = _make_session(_make_response(json_data=data))

        result = await _socket_fetch("/test", session=session)

        assert result == data

    @pytest.mark.asyncio
    async def test_with_api_key_sends_auth_header(self) -> None:
        """With api_key → sends ``Authorization: api <key>`` header."""
        data = {"ok": True}
        session = _make_session(_make_response(json_data=data))

        await _socket_fetch("/test", api_key="my-key", session=session)

        session.get.assert_awaited_once()
        _, kwargs = session.get.call_args
        assert kwargs.get("headers", {}).get("Authorization") == "api my-key"

    @pytest.mark.asyncio
    async def test_without_api_key_no_auth_header(self) -> None:
        """Without api_key → no Authorization header."""
        data = {"ok": True}
        session = _make_session(_make_response(json_data=data))

        await _socket_fetch("/test", session=session)

        session.get.assert_awaited_once()
        _, kwargs = session.get.call_args
        assert "Authorization" not in kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_external_session_not_closed(self) -> None:
        """External session provided → not closed by function."""
        session = _make_session(_make_response())

        await _socket_fetch("/test", session=session)

        session.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_own_session_created_and_closed(self) -> None:
        """No session provided → own session is created, used, and closed."""
        data = {"ok": True}
        response = _make_response(json_data=data)
        mock_session_instance = MagicMock(spec=aiohttp.ClientSession)
        mock_session_instance.get = AsyncMock(return_value=response)
        mock_session_instance.close = AsyncMock()

        with patch(
            "pkg_defender.intel.socket.aiohttp.ClientSession",
            return_value=mock_session_instance,
        ):
            result = await _socket_fetch("/test", api_key=None)

        assert result == data
        mock_session_instance.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_own_session_closed_on_error(self) -> None:
        """Own session is closed in ``finally`` even when fetch raises."""
        exc = aiohttp.ClientResponseError(
            MagicMock(),
            (),
            status=404,
            message="Not Found",
            headers=None,
        )
        response = _make_response(exc=exc)
        mock_session_instance = MagicMock(spec=aiohttp.ClientSession)
        mock_session_instance.get = AsyncMock(return_value=response)
        mock_session_instance.close = AsyncMock()

        with (
            patch(
                "pkg_defender.intel.socket.aiohttp.ClientSession",
                return_value=mock_session_instance,
            ),
            pytest.raises(aiohttp.ClientResponseError),
        ):
            await _socket_fetch("/test", api_key=None)

        mock_session_instance.close.assert_awaited_once()

    # ------------------------------------------------------------------
    # JSON decode error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_non_json_response_raises(self) -> None:
        """200 + non-JSON body → ``JSONDecodeError`` propagates."""
        resp = MagicMock(spec=aiohttp.ClientResponse)
        resp.status = 200
        resp.raise_for_status = MagicMock()
        resp.json = AsyncMock(
            side_effect=json.JSONDecodeError("Expecting value", "", 0),
        )
        session = _make_session(resp)

        with pytest.raises(json.JSONDecodeError):
            await _socket_fetch("/test", session=session)

    # ------------------------------------------------------------------
    # Non-retryable HTTP errors (raise immediately)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404])
    @pytest.mark.asyncio
    async def test_non_retryable_status_raises_immediately(self, status_code: int) -> None:
        """Non-retryable status (400/401/403/404) → raises immediately, no retry."""
        exc = aiohttp.ClientResponseError(
            MagicMock(),
            (),
            status=status_code,
            message="Error",
            headers=None,
        )
        response = _make_response(exc=exc)
        session = _make_session(response)

        with pytest.raises(aiohttp.ClientResponseError) as exc_info:
            await _socket_fetch("/test", session=session)

        assert exc_info.value.status == status_code
        session.get.assert_awaited_once()  # exactly one attempt

    # ------------------------------------------------------------------
    # Retryable HTTP errors
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("retry_status", [429, 500, 502, 503, 504])
    @pytest.mark.asyncio
    async def test_retryable_status_retries_then_raises(self, retry_status: int) -> None:
        """Retryable status (429/5xx) → retries, then raises last exception."""
        exc = aiohttp.ClientResponseError(
            MagicMock(),
            (),
            status=retry_status,
            message="Retry",
            headers=None,
        )
        response = _make_response(exc=exc)
        session = _make_session([response, response])

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=2),
            pytest.raises(aiohttp.ClientResponseError) as exc_info,
        ):
            await _socket_fetch("/test", session=session)

        assert exc_info.value.status == retry_status
        assert session.get.await_count == 2

    @pytest.mark.asyncio
    async def test_retry_then_succeeds(self) -> None:
        """Retryable error on first attempt → succeeds on second."""
        err_exc = aiohttp.ClientResponseError(
            MagicMock(),
            (),
            status=429,
            message="Too Many Requests",
            headers=None,
        )
        err_resp = _make_response(exc=err_exc)
        ok_data = {"score": {"supplyChainRisk": 0.8, "malware": 0.2}}
        ok_resp = _make_response(json_data=ok_data)
        session = _make_session([err_resp, ok_resp])

        with patch("pkg_defender.intel.socket.get_max_retries", return_value=2):
            result = await _socket_fetch("/test", session=session)

        assert result == ok_data
        assert session.get.await_count == 2

    # ------------------------------------------------------------------
    # ClientError / TimeoutError
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_client_error_retries_then_raises(self) -> None:
        """``aiohttp.ClientError`` → retries, then raises."""
        session = MagicMock(spec=aiohttp.ClientSession)
        session.get = AsyncMock(side_effect=aiohttp.ClientError("Connection refused"))
        session.close = AsyncMock()

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=2),
            pytest.raises(aiohttp.ClientError, match="Connection refused"),
        ):
            await _socket_fetch("/test", session=session)

        assert session.get.await_count == 2

    @pytest.mark.asyncio
    async def test_timeout_error_retries_then_raises(self) -> None:
        """``TimeoutError`` → retries, then raises."""
        session = MagicMock(spec=aiohttp.ClientSession)
        session.get = AsyncMock(side_effect=TimeoutError("Request timed out"))
        session.close = AsyncMock()

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=2),
            pytest.raises(TimeoutError, match="Request timed out"),
        ):
            await _socket_fetch("/test", session=session)

        assert session.get.await_count == 2

    # ------------------------------------------------------------------
    # All retries exhausted
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_all_retries_exhausted_raises_last_exception(self) -> None:
        """After exhausting all retries, the last exception is raised."""
        err_exc = aiohttp.ClientResponseError(
            MagicMock(),
            (),
            status=429,
            message="Rate limited",
            headers=None,
        )
        response = _make_response(exc=err_exc)
        session = _make_session([response, response, response])

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=3),
            pytest.raises(aiohttp.ClientResponseError) as exc_info,
        ):
            await _socket_fetch("/test", session=session)

        assert exc_info.value.status == 429
        assert session.get.await_count == 3

    # ------------------------------------------------------------------
    # Config timeout
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Edge: zero retries (max_retries=0) — hits RuntimeError fallback
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_zero_max_retries_raises_runtime_error(self) -> None:
        """``get_max_retries`` returns 0 → loop never runs → ``RuntimeError``."""
        session = _make_session(_make_response())

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=0),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _socket_fetch("/test", session=session)

        # Session.get should not have been called at all
        session.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_zero_max_retries_with_own_session_closes_it(self) -> None:
        """``max_retries=0`` with own session → session is still closed."""
        mock_session_instance = MagicMock(spec=aiohttp.ClientSession)
        mock_session_instance.get = AsyncMock()
        mock_session_instance.close = AsyncMock()

        with (
            patch("pkg_defender.intel.socket.get_max_retries", return_value=0),
            patch(
                "pkg_defender.intel.socket.aiohttp.ClientSession",
                return_value=mock_session_instance,
            ),
            pytest.raises(RuntimeError, match="Failed to fetch"),
        ):
            await _socket_fetch("/test", api_key=None)

        mock_session_instance.close.assert_awaited_once()

    # ------------------------------------------------------------------
    # Config timeout
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_config_timeout_applied_to_request(self) -> None:
        """Config ``http_timeout`` → applied to ``ClientSession``."""
        mock_session_instance = MagicMock(spec=aiohttp.ClientSession)
        mock_session_instance.get = AsyncMock(return_value=_make_response())
        mock_session_instance.close = AsyncMock()

        with (
            patch("pkg_defender.intel.socket.get_http_timeout", return_value=42),
            patch(
                "pkg_defender.intel.socket.aiohttp.ClientSession",
                return_value=mock_session_instance,
            ) as mock_cls,
        ):
            await _socket_fetch("/test", api_key=None)

        mock_cls.assert_called_once()
        _, kwargs = mock_cls.call_args
        assert kwargs["timeout"].total == 42

    # ------------------------------------------------------------------
    # URL construction
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_url_construction(self) -> None:
        """Endpoint is correctly appended to ``SOCKET_API_BASE``."""
        session = _make_session(_make_response())

        await _socket_fetch("/npm/lodash/4.17.21/score", session=session)

        session.get.assert_awaited_once()
        args, _ = session.get.call_args
        assert args[0] == f"{SOCKET_API_BASE}/npm/lodash/4.17.21/score"


# =========================================================================
# SocketFeed class
# =========================================================================


class TestSocketFeed:
    """Tests for SocketFeed class-level methods and properties."""

    def test_name(self) -> None:
        """``name`` property returns ``'socket'``."""
        assert SocketFeed().name == "socket"

    def test_supports_incremental(self) -> None:
        """``supports_incremental`` returns ``False``."""
        assert SocketFeed().supports_incremental is False

    def test_is_configured_true(self) -> None:
        """Returns ``True`` when enabled *and* key present."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "valid-key"

        assert feed.is_configured(config) is True

    def test_is_configured_false_when_disabled(self) -> None:
        """Returns ``False`` when ``socket_enabled`` is ``False``."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_enabled = False
        config.feeds.socket_api_key = "valid-key"

        assert feed.is_configured(config) is False

    def test_is_configured_false_when_key_empty(self) -> None:
        """Returns ``False`` when ``socket_api_key`` is empty."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = ""

        assert feed.is_configured(config) is False

    def test_is_configured_false_when_key_whitespace(self) -> None:
        """Returns ``False`` when ``socket_api_key`` is whitespace-only."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_enabled = True
        config.feeds.socket_api_key = "   "

        assert feed.is_configured(config) is False

    @pytest.mark.asyncio
    async def test_fetch_returns_failed(self) -> None:
        """``fetch()`` returns ``FeedFetchResult`` with ``FAILED`` status."""
        result = await SocketFeed().fetch()

        assert isinstance(result, FeedFetchResult)
        assert result.status == FetchStatus.FAILED
        assert result.records == []


# =========================================================================
# SocketFeed.check_package
# =========================================================================


class TestSocketFeedCheckPackage:
    """Tests for SocketFeed.check_package()."""

    # ------------------------------------------------------------------
    # Exception propagation (existing regression test)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_socket_check_package_propagates_exception(self) -> None:
        """Mock _socket_fetch to raise; exception propagates, not caught as [].

        After removing the except Exception block from check_package(),
        HTTP errors from _socket_fetch propagate to the caller instead
        of being silently converted to an empty list.
        """
        feed = SocketFeed()
        mock_config = MagicMock()
        mock_config.feeds.socket_api_key = "test-key"

        with (
            patch(
                "pkg_defender.intel.socket._socket_fetch",
                side_effect=aiohttp.ClientError("Socket API unavailable"),
            ),
            pytest.raises(aiohttp.ClientError, match="Socket API unavailable"),
        ):
            await feed.check_package(
                "test-pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=mock_config,
            )

    # ------------------------------------------------------------------
    # Ecosystem rejection
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_non_npm_ecosystem_returns_failed(self) -> None:
        """Non-npm ecosystem (pypi) → returns FAILED immediately."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        result = await feed.check_package(
            "some-pkg",
            "1.0.0",
            "pypi",
            session=MagicMock(),
            config=config,
        )

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_homebrew_ecosystem_returns_failed(self) -> None:
        """Non-npm ecosystem (homebrew) → returns FAILED immediately."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        result = await feed.check_package(
            "some-pkg",
            "1.0.0",
            "homebrew",
            session=MagicMock(),
            config=config,
        )

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Config and session handling
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_config_none_loads_config(self) -> None:
        """Config is ``None`` → calls ``load_config()``."""
        feed = SocketFeed()
        mock_cfg = MagicMock()
        mock_cfg.feeds.socket_api_key = "key"

        with (
            patch("pkg_defender.intel.socket.load_config", return_value=mock_cfg),
            patch(
                "pkg_defender.intel.socket._socket_fetch",
                return_value={"score": {"supplyChainRisk": 0.5, "malware": 0.4}},
            ),
        ):
            result = await feed.check_package("pkg", "1.0.0", "npm")

        assert result.status == FetchStatus.FAILED  # below threshold

    @pytest.mark.asyncio
    async def test_returns_failed_status_when_provided_session_used(self) -> None:
        """Session provided → uses it and does NOT close it."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"
        session = MagicMock(spec=aiohttp.ClientSession)
        session.get = AsyncMock()
        session.close = AsyncMock()

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": {"supplyChainRisk": 0.5, "malware": 0.4}},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=session,
                config=config,
            )

        assert result.status == FetchStatus.FAILED
        # session.close should NOT have been called (not own session)
        session.close.assert_not_called()

    # ------------------------------------------------------------------
    # Score parsing (missing / non-dict / default)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_score_key_missing_defaults_to_zero(self) -> None:
        """``score`` key missing from response → defaults to 0.0 → FAILED."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={},  # no "score" key
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_score_not_dict_defaults_to_zero(self) -> None:
        """``score`` is not a dict (e.g. string) → defaults to 0.0 → FAILED."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": "not-a-dict"},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    # ------------------------------------------------------------------
    # Threshold / severity paths
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_below_threshold_returns_failed(self) -> None:
        """SC=0.5, malware=0.3 → below threshold → FAILED."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": {"supplyChainRisk": 0.5, "malware": 0.3}},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.FAILED
        assert result.records == []

    @pytest.mark.asyncio
    async def test_medium_severity_threat(self) -> None:
        """SC=0.8, malware=0.2 → MEDIUM threat record."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": {"supplyChainRisk": 0.8, "malware": 0.2}},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_high_severity_threat(self) -> None:
        """SC=0.95, malware=0.0 → HIGH threat record."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": {"supplyChainRisk": 0.95, "malware": 0.0}},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].severity == "HIGH"

    @pytest.mark.asyncio
    async def test_critical_severity_threat(self) -> None:
        """SC=0.5, malware=0.9 → CRITICAL threat record."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={"score": {"supplyChainRisk": 0.5, "malware": 0.9}},
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        assert len(result.records) == 1
        assert result.records[0].severity == "CRITICAL"

    # ------------------------------------------------------------------
    # Issues handling
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_issues_included_in_summary(self) -> None:
        """Issues present → summary includes issue titles."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={
                "score": {"supplyChainRisk": 0.8, "malware": 0.2},
                "issues": [
                    {"title": "High supply chain risk"},
                    {"title": "Known vulnerability detected"},
                ],
            },
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        summary = result.records[0].summary
        assert "High supply chain risk" in summary
        assert "Known vulnerability detected" in summary

    @pytest.mark.asyncio
    async def test_issues_missing_no_issues_in_summary(self) -> None:
        """Issues key missing → summary without issue section."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={
                "score": {"supplyChainRisk": 0.8, "malware": 0.2},
                # no "issues" key
            },
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        summary = result.records[0].summary
        assert "supplyChainRisk=0.80" in summary
        assert " — " not in summary  # no issue separator present

    @pytest.mark.asyncio
    async def test_issues_truncated_to_five(self) -> None:
        """More than 5 issues → truncated to first 5 in summary."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={
                "score": {"supplyChainRisk": 0.8, "malware": 0.2},
                "issues": [{"title": f"Issue {i}"} for i in range(10)],
            },
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        summary = result.records[0].summary
        assert "Issue 0" in summary
        assert "Issue 4" in summary
        assert "Issue 5" not in summary  # beyond first 5
        assert "Issue 9" not in summary  # beyond first 5

    @pytest.mark.asyncio
    async def test_issue_without_title_skipped(self) -> None:
        """Issue entries without a title key or with empty title → skipped."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={
                "score": {"supplyChainRisk": 0.8, "malware": 0.2},
                "issues": [
                    {"title": "First issue"},
                    {"notitle": True},  # no title key
                    {"title": ""},  # empty title
                    {"title": "Second issue"},
                ],
            },
        ):
            result = await feed.check_package(
                "pkg",
                "1.0.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        summary = result.records[0].summary
        assert "First issue" in summary
        assert "Second issue" in summary
        assert "notitle" not in summary

    # ------------------------------------------------------------------
    # ThreatRecord field verification
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_threat_record_fields(self) -> None:
        """Verify every ``ThreatRecord`` field is correctly populated."""
        feed = SocketFeed()
        config = MagicMock()
        config.feeds.socket_api_key = "key"

        with patch(
            "pkg_defender.intel.socket._socket_fetch",
            return_value={
                "score": {"supplyChainRisk": 0.85, "malware": 0.3},
                "issues": [{"title": "Moderate risk detected"}],
            },
        ):
            result = await feed.check_package(
                "react",
                "18.2.0",
                "npm",
                session=MagicMock(),
                config=config,
            )

        assert result.status == FetchStatus.SUCCESS
        record = result.records[0]

        assert record.id == "socket:react:18.2.0"
        assert record.ecosystem == "npm"
        assert record.package_name == "react"
        assert record.affected_versions == ["18.2.0"]
        assert record.affected_ranges == []
        assert record.severity == "MEDIUM"
        assert record.confidence == 0.95
        assert record.source == "socket"
        assert record.source_id == "react@18.2.0"
        expected_summary = "Socket.dev: supplyChainRisk=0.85, malware=0.30 — Moderate risk detected"
        assert record.summary == expected_summary
        assert record.detail_url == "https://socket.dev/npm/package/react"
        assert record.cvss_score is None
        assert record.hit_count == 1
        assert record.is_malicious is False
        assert record.is_unverified is False
        # Timestamps should be set (rough check)
        assert record.first_seen is not None
        assert record.last_seen is not None
        assert record.published_at is not None
        assert record.ingested_at is not None
