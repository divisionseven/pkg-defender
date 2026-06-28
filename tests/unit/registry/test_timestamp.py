"""Tests for the TimestampResolver's Libraries.io integration and ResolutionResult.

Covers the ``_try_libraries_io`` private method, the ``resolve()`` method's
return of ``ResolutionResult``, and the module-level ``resolve_timestamp()``
function. Tests verify per-version timestamp parsing, edge cases, correct URL
construction, and structured resolution results with per-tier failure info.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender._http import FetchResult
from pkg_defender.registry._timestamp import (
    LIBRARIES_IO_BASE,
    ResolutionResult,
    TimestampResolver,
    _reset_timestamp_caches,
    get_resolver,
    resolve_timestamp,
)

_FetchResult = tuple[dict[str, Any] | list[Any] | None, str | None]


@pytest.mark.asyncio
async def test_try_libraries_io_finds_matching_version() -> None:
    """Given a versions array with 3 entries, returns the ``published_at`` for the matching version."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {
        "versions": [
            {"number": "1.0.0", "published_at": "2023-01-01T00:00:00.000Z"},
            {"number": "1.1.0", "published_at": "2023-06-15T00:00:00.000Z"},
            {"number": "2.0.0", "published_at": "2024-01-15T10:00:00.000Z"},
        ],
    }

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))):
        dt = await resolver._try_libraries_io("pypi", "requests", "1.1.0", AsyncMock())

    assert dt == datetime(2023, 6, 15, 0, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_try_libraries_io_returns_none_for_missing_version() -> None:
    """Version not in the ``versions`` array -> returns ``None``."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {
        "versions": [
            {"number": "1.0.0", "published_at": "2023-01-01T00:00:00.000Z"},
            {"number": "2.0.0", "published_at": "2024-01-15T10:00:00.000Z"},
        ],
    }

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))):
        dt = await resolver._try_libraries_io("pypi", "requests", "9.9.9", AsyncMock())

    assert dt is None


@pytest.mark.asyncio
async def test_try_libraries_io_returns_none_for_empty_versions() -> None:
    """Empty ``versions`` array -> returns ``None``."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response: dict[str, list[dict[str, str]]] = {"versions": []}

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))):
        dt = await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert dt is None


@pytest.mark.asyncio
async def test_try_libraries_io_returns_none_for_none_response() -> None:
    """API returns ``None`` (network error) -> returns ``None``."""
    resolver = TimestampResolver(libraries_io_key=None)

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "network_error"))):
        dt = await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert dt is None


@pytest.mark.asyncio
async def test_try_libraries_io_no_api_key_omits_param() -> None:
    """When ``_libraries_io_key`` is ``None``, the URL does **not** contain ``?api_key=``."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_fetch_json = AsyncMock(return_value=({"versions": []}, None))

    with patch.object(resolver, "_fetch_json", mock_fetch_json):
        await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    called_url = mock_fetch_json.call_args[0][0]
    assert "api_key" not in called_url
    assert called_url == f"{LIBRARIES_IO_BASE}/pypi/requests"


@pytest.mark.asyncio
async def test_try_libraries_io_with_api_key_includes_param() -> None:
    """When ``_libraries_io_key`` is set, the URL contains ``?api_key=KEY``."""
    resolver = TimestampResolver(libraries_io_key="my-secret-key")
    mock_fetch_json = AsyncMock(return_value=({"versions": []}, None))

    with patch.object(resolver, "_fetch_json", mock_fetch_json):
        await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    called_url = mock_fetch_json.call_args[0][0]
    assert "api_key=my-secret-key" in called_url
    assert called_url == f"{LIBRARIES_IO_BASE}/pypi/requests?api_key=my-secret-key"


# ── Structured logging tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_try_libraries_io_logs_attempt(caplog: pytest.LogCaptureFixture) -> None:
    """Libraries.io tier logs ``status=attempt`` on entry."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {"versions": [{"number": "1.0.0", "published_at": "2023-01-01T00:00:00.000Z"}]}

    with (
        caplog.at_level(logging.DEBUG),
        patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))),
    ):
        await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert any("status=attempt" in record.message for record in caplog.records), (
        "Expected a log record containing 'status=attempt'"
    )


@pytest.mark.asyncio
async def test_try_libraries_io_logs_success(caplog: pytest.LogCaptureFixture) -> None:
    """Libraries.io tier logs ``status=success`` on successful lookup."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {"versions": [{"number": "1.0.0", "published_at": "2023-01-01T00:00:00.000Z"}]}

    with (
        caplog.at_level(logging.DEBUG),
        patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))),
    ):
        await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert any("status=success" in record.message for record in caplog.records), (
        "Expected a log record containing 'status=success'"
    )


@pytest.mark.asyncio
async def test_try_libraries_io_logs_failure_reason(caplog: pytest.LogCaptureFixture) -> None:
    """Libraries.io tier logs ``failure_<reason>`` when fetch fails."""
    resolver = TimestampResolver(libraries_io_key=None)

    with (
        caplog.at_level(logging.DEBUG),
        patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "network_error"))),
    ):
        await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert any("failure_network_error" in record.message for record in caplog.records), (
        "Expected a log record containing 'failure_network_error'"
    )


@pytest.mark.asyncio
async def test_fetch_json_logs_rate_limited_warning(caplog: pytest.LogCaptureFixture) -> None:
    """``_fetch_json`` delegates to _http.fetch_json; 403 is caught and logged as WARNING."""
    resolver = TimestampResolver(github_token=None)

    mock_request_info = MagicMock()
    mock_exc = aiohttp.ClientResponseError(
        request_info=mock_request_info,
        history=(),
        status=403,
    )

    with (
        caplog.at_level(logging.WARNING),
        patch(
            "pkg_defender.registry._timestamp.fetch_json",
            side_effect=mock_exc,
        ),
    ):
        result = await resolver._fetch_json(
            "https://api.github.com/test",
            MagicMock(),
            {},
        )

    assert result == (None, "rate_limited")
    assert any("rate limited" in record.message for record in caplog.records)
    assert any(record.levelname == "WARNING" for record in caplog.records)


@pytest.mark.asyncio
async def test_resolve_logs_all_failed(caplog: pytest.LogCaptureFixture) -> None:
    """When all tiers return None, resolver logs ``status=all_failed``."""
    resolver = TimestampResolver(libraries_io_key=None)

    with (
        caplog.at_level(logging.DEBUG),
        patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))),
    ):
        result = await resolver.resolve(
            package="nonexistent",
            version="9.9.9",
            github_url=None,
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "no_github_url"
    assert any("status=all_failed" in record.message for record in caplog.records), (
        "Expected a log record containing 'status=all_failed'"
    )


# ── Metrics counter tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_libraries_io_counter_attempt() -> None:
    """Libraries.io tier attempts resolution."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {"versions": [{"number": "1.0.0", "published_at": "2023-01-01T00:00:00.000Z"}]}

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))):
        result = await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert result is not None


@pytest.mark.asyncio
async def test_libraries_io_counter_failure() -> None:
    """Libraries.io tier handles fetch failure."""
    resolver = TimestampResolver(libraries_io_key=None)

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "network_error"))):
        result = await resolver._try_libraries_io("pypi", "requests", "1.0.0", AsyncMock())

    assert result is None


@pytest.mark.asyncio
async def test_rate_limited_populates_session_errors() -> None:
    """A 403 response from ``_fetch_json`` adds ``rate_limited`` to session errors."""
    resolver = TimestampResolver(github_token=None)

    mock_request_info = MagicMock()
    mock_exc = aiohttp.ClientResponseError(
        request_info=mock_request_info,
        history=(),
        status=403,
    )

    with patch(
        "pkg_defender.registry._timestamp.fetch_json",
        side_effect=mock_exc,
    ):
        await resolver._fetch_json(
            "https://api.github.com/test",
            MagicMock(),
            {},
        )

    errors = resolver.get_session_errors()
    assert "rate_limited" in errors


@pytest.mark.asyncio
async def test_no_errors_on_successful_fetch() -> None:
    """A successful fetch does NOT populate session errors."""
    resolver = TimestampResolver(github_token=None)

    mock_result = FetchResult(data={"key": "value"}, status=200, success=True)

    with patch(
        "pkg_defender.registry._timestamp.fetch_json",
        new_callable=AsyncMock,
        return_value=mock_result,
    ):
        await resolver._fetch_json(
            "https://api.github.com/test",
            MagicMock(),
            {},
        )

    assert resolver.get_session_errors() == set()


@pytest.mark.asyncio
async def test_get_session_errors_returns_copy() -> None:
    """``get_session_errors()`` returns a copy that cannot mutate internal state."""
    resolver = TimestampResolver(github_token=None)
    resolver._session_errors.add("rate_limited")

    errors = resolver.get_session_errors()
    errors.add("not_found")

    assert "not_found" not in resolver._session_errors, "Mutating the returned set must not affect internal state"
    assert resolver._session_errors == {"rate_limited"}


# ── ResolutionResult tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_returns_resolution_result_success_tier1() -> None:
    """Tier 1 (Libraries.io) success returns ResolutionResult with resolved status."""
    resolver = TimestampResolver(libraries_io_key=None)
    mock_response = {
        "versions": [{"number": "1.0.0", "published_at": "2023-06-15T12:00:00.000Z"}],
    }

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(mock_response, None))):
        result = await resolver.resolve(
            package="requests",
            version="1.0.0",
            github_url="https://github.com/psf/requests",
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time == datetime(2023, 6, 15, 12, 0, 0, tzinfo=UTC)
    assert result.source_label == "libraries_io"
    assert result.resolution_status == "resolved"
    assert result.last_error is None
    assert result.tiers_attempted == ["libraries_io"]


@pytest.mark.asyncio
async def test_resolve_returns_resolution_result_success_tier2() -> None:
    """Tier 2 (GitHub Releases) success returns ResolutionResult with resolved status."""
    resolver = TimestampResolver(libraries_io_key=None)
    # Tier 1 fails (no library.io platform for 'unknown_eco')
    # Tier 2 succeeds
    mock_release = {"published_at": "2024-01-20T15:30:00Z"}

    call_count = 0

    async def _mock_fetch(url: str, session: object, headers: dict[str, str], **kwargs: Any) -> _FetchResult:
        nonlocal call_count
        call_count += 1
        if "releases/tags" in url:
            return (mock_release, None)
        return (None, "not_found")

    with patch.object(resolver, "_fetch_json", side_effect=_mock_fetch):
        result = await resolver.resolve(
            package="my-pkg",
            version="2.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="unknown_eco",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time == datetime(2024, 1, 20, 15, 30, 0, tzinfo=UTC)
    assert result.source_label == "github_releases"
    assert result.resolution_status == "resolved"
    assert result.tiers_attempted == ["github_releases"]


@pytest.mark.asyncio
async def test_resolve_returns_resolution_result_success_tier3() -> None:
    """Tier 3 (GitHub Tags) success returns ResolutionResult with resolved status."""
    resolver = TimestampResolver(libraries_io_key=None)
    # Tier 1 skipped (no ecosystem), Tier 2 fails, Tier 3 succeeds
    tag_sha = "abc123"

    async def _mock_fetch(url: str, session: object, headers: dict[str, str], **kwargs: Any) -> _FetchResult:
        if "releases/tags" in url:
            return (None, "not_found")
        if "/tags" in url and "commits" not in url:
            return ([{"name": "v1.0.0", "commit": {"sha": tag_sha}}], None)
        if f"/commits/{tag_sha}" in url:
            return ({"commit": {"committer": {"date": "2024-03-10T08:00:00Z"}}}, None)
        return (None, "not_found")

    with patch.object(resolver, "_fetch_json", side_effect=_mock_fetch):
        result = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time == datetime(2024, 3, 10, 8, 0, 0, tzinfo=UTC)
    assert result.source_label == "github_tags"
    assert result.resolution_status == "resolved"
    assert result.tiers_attempted == ["github_releases", "github_tags"]


@pytest.mark.asyncio
async def test_resolve_returns_resolution_result_all_failed() -> None:
    """When all tiers fail, ResolutionResult has failure status and derived source_label."""
    resolver = TimestampResolver(libraries_io_key=None)

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result = await resolver.resolve(
            package="nonexistent",
            version="9.9.9",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "not_found"
    assert result.last_error == "not_found"
    # source_label now derives from resolution_status instead of using "unresolved"
    assert result.source_label == "not_found"
    assert result.tiers_attempted == ["libraries_io", "github_releases", "github_tags"]


@pytest.mark.asyncio
async def test_resolve_rate_limited_derives_correct_status() -> None:
    """When _session_errors contains 'rate_limited', resolution_status and source_label are 'rate_limited'.

    Simulates the real flow: _fetch_json catches a 403, returns (None, "rate_limited"),
    and adds "rate_limited" to _session_errors. The resolve() method then derives
    resolution_status = "rate_limited" from the session errors and source_label = "rate_limited".
    """
    resolver = TimestampResolver(libraries_io_key=None)
    # Manually set the session error to simulate what _fetch_json does on 403
    resolver._session_errors.add("rate_limited")

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "rate_limited"
    assert result.source_label == "rate_limited"
    assert "rate_limited" in resolver.get_session_errors()


@pytest.mark.asyncio
async def test_resolve_no_github_url() -> None:
    """When github_url is None, resolution_status is 'no_github_url'."""
    resolver = TimestampResolver(libraries_io_key=None)

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url=None,
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "no_github_url"
    assert result.tiers_attempted == ["libraries_io"]


@pytest.mark.asyncio
async def test_resolve_tiers_attempted_list() -> None:
    """tiers_attempted is populated correctly based on which tiers were tried."""
    resolver = TimestampResolver(libraries_io_key=None)

    # No ecosystem, no github_url → no tiers tried
    result_nothing = await resolver.resolve(
        package="my-pkg",
        version="1.0.0",
        github_url=None,
        session=AsyncMock(),
    )
    assert result_nothing.tiers_attempted == []

    # Ecosystem only (no github_url) → only Libraries.io
    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result_lib = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url=None,
            session=AsyncMock(),
            ecosystem="pypi",
        )
    assert result_lib.tiers_attempted == ["libraries_io"]

    # GitHub URL only (no matching ecosystem) → GitHub Releases + Tags
    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result_gh = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="unknown_eco",
        )
    assert result_gh.tiers_attempted == ["github_releases", "github_tags"]

    # Both ecosystem and github_url → all three tiers
    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result_all = await resolver.resolve(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="pypi",
        )
    assert result_all.tiers_attempted == ["libraries_io", "github_releases", "github_tags"]


@pytest.mark.asyncio
async def test_resolve_timestamp_returns_resolution_result() -> None:
    """Module-level resolve_timestamp() returns ResolutionResult."""
    with patch(
        "pkg_defender.registry._timestamp.get_resolver",
    ) as mock_get_resolver:
        mock_resolver = mock_get_resolver.return_value
        mock_resolver.resolve = AsyncMock(
            return_value=ResolutionResult(
                publish_time=datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC),
                source_label="github_tags",
                resolution_status="resolved",
                last_error=None,
                tiers_attempted=["github_releases", "github_tags"],
            ),
        )
        result = await resolve_timestamp(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time == datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
    assert result.source_label == "github_tags"
    assert result.resolution_status == "resolved"
    assert result.tiers_attempted == ["github_releases", "github_tags"]


@pytest.mark.asyncio
async def test_resolve_timestamp_returns_resolution_result_on_exception() -> None:
    """resolve_timestamp() returns ResolutionResult with 'unknown_error' on exception."""
    with patch(
        "pkg_defender.registry._timestamp.get_resolver",
    ) as mock_get_resolver:
        mock_resolver = mock_get_resolver.return_value
        mock_resolver.resolve = AsyncMock(side_effect=RuntimeError("boom"))
        result = await resolve_timestamp(
            package="my-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "unknown_error"
    assert "boom" in (result.last_error or "")
    assert result.tiers_attempted == []


# ── Phase 6: source_label standardization tests ────────────────────


@pytest.mark.asyncio
async def test_resolve_all_sources_failed_has_correct_label() -> None:
    """When all tiers fail with a generic error, source_label is 'all_sources_failed'.

    This verifies that the resolver no longer returns the misleading
    'user_manual' label when all sources fail. The source_label now
    derives from resolution_status via _STATUS_TO_SOURCE_LABEL.
    """
    resolver = TimestampResolver(libraries_io_key=None)

    # Use "unknown_error" so _derive_resolution_status falls through to
    # "all_sources_failed" (not caught by the specific-error branches).
    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "unknown_error"))):
        result = await resolver.resolve(
            package="some-pkg",
            version="1.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert isinstance(result, ResolutionResult)
    assert result.publish_time is None
    assert result.resolution_status == "all_sources_failed"
    assert result.source_label == "all_sources_failed"
    assert result.source_label != "unresolved"
    assert result.last_error == "unknown_error"
    assert result.tiers_attempted == ["libraries_io", "github_releases", "github_tags"]


@pytest.mark.asyncio
async def test_resolve_rate_limited_derives_correct_label() -> None:
    """When session errors contain 'rate_limited', source_label is 'rate_limited'.

    Verifies the source_label derivation from resolution_status for the
    rate-limiting case — the most common transient failure mode.
    """
    resolver = TimestampResolver(libraries_io_key=None)
    resolver._session_errors.add("rate_limited")

    with patch.object(resolver, "_fetch_json", AsyncMock(return_value=(None, "not_found"))):
        result = await resolver.resolve(
            package="my-pkg",
            version="2.0.0",
            github_url="https://github.com/owner/repo",
            session=AsyncMock(),
            ecosystem="pypi",
        )

    assert result.publish_time is None
    assert result.resolution_status == "rate_limited"
    assert result.source_label == "rate_limited"


@pytest.mark.asyncio
async def test_session_errors_populated_on_rate_limit() -> None:
    """_session_errors is populated when _fetch_json hits a 403 rate limit.

    This is an end-to-end verification that the session-level error tracking
    still works correctly after the source_label standardization changes.
    """
    resolver = TimestampResolver(libraries_io_key=None)
    assert resolver.get_session_errors() == set(), "Session errors should start empty"

    mock_request_info = MagicMock()
    mock_exc = aiohttp.ClientResponseError(
        request_info=mock_request_info,
        history=(),
        status=403,
    )

    with patch(
        "pkg_defender.registry._timestamp.fetch_json",
        side_effect=mock_exc,
    ):
        # Call _fetch_json directly to trigger rate-limit handling
        await resolver._fetch_json(
            "https://api.github.com/repos/owner/repo/releases/tags/v1.0.0",
            MagicMock(),
            {},
        )

    errors = resolver.get_session_errors()
    assert "rate_limited" in errors, "rate_limited should be in session errors after 403"


def test_get_resolver_env_var_takes_precedence_over_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """PKGD_GITHUB_TOKEN env var takes precedence over config token."""
    _reset_timestamp_caches()  # Ensure clean singleton state
    monkeypatch.setenv("PKGD_GITHUB_TOKEN", "ghp_env_token_value")

    mock_config = MagicMock()
    mock_config.feeds.ghsa_token = "ghp_config_token_value"

    with patch("pkg_defender.config.load_config", return_value=mock_config):
        resolver = get_resolver()

    assert resolver._github_token == "ghp_env_token_value"


def test_get_resolver_reads_token_from_config_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_resolver() falls back to config.feeds.ghsa_token when PKGD_GITHUB_TOKEN is unset."""
    _reset_timestamp_caches()  # Ensure clean singleton state
    monkeypatch.delenv("PKGD_GITHUB_TOKEN", raising=False)

    mock_config = MagicMock()
    mock_config.feeds.ghsa_token = "ghp_config_token_value"

    with patch("pkg_defender.config.load_config", return_value=mock_config):
        resolver = get_resolver()

    assert resolver._github_token == "ghp_config_token_value"


def test_get_resolver_no_token_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_resolver() returns None for github_token when neither env var nor config has it."""
    _reset_timestamp_caches()  # Ensure clean singleton state
    monkeypatch.delenv("PKGD_GITHUB_TOKEN", raising=False)

    mock_config = MagicMock()
    mock_config.feeds.ghsa_token = ""

    with patch("pkg_defender.config.load_config", return_value=mock_config):
        resolver = get_resolver()

    assert resolver._github_token is None
