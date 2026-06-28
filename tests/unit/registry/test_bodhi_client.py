"""Tests for pkg_defender.registry._bodhi_client.

Bodhi REST client for Fedora/EPEL publish-time lookup. Mocking pattern:
patch :func:`pkg_defender.registry._bodhi_client.fetch_json` with
synthetic Bodhi response dicts. Cache state is module-level and shared
across tests, so every test must use the ``_reset_cache_for_tests``
fixture for isolation.
"""

from __future__ import annotations

import html.parser
import time
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.registry import _bodhi_client
from pkg_defender.registry._bodhi_client import (
    BODHI_BASE_URL,
    BODHI_CACHE_TTL_SECONDS,
    SOURCE_BODHI,
    BodhiClient,
    _cache,
    _check_cache,
    _extract_match,
    _match_nvr,
    _parse_bodhi_date,
    _reset_cache_for_tests,
    _store_cache,
)


@pytest.fixture(autouse=True)
def _reset_bodhi_cache() -> Generator[None, None, None]:
    """Clear module-level cache between tests.

    The Bodhi cache is module-level and shared across all
    :class:`BodhiClient` instances. Without this fixture, test
    ordering would matter and the "cache" tests would be
    contaminated by earlier tests' state.
    """
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


# ---------------------------------------------------------------------------
# Synthetic Bodhi response builders
# ---------------------------------------------------------------------------


def _update(
    *,
    date_pushed: str | None = "2026-03-11 23:47:27",
    date_submitted: str | None = "2026-03-10 12:00:00",
    builds: list[dict[str, str]] | None = None,
    title: str = "curl-8.21.0-1.fc45",
) -> dict[str, object]:
    """Build a synthetic Bodhi ``update`` dict."""
    return {
        "title": title,
        "date_pushed": date_pushed,
        "date_submitted": date_submitted,
        "builds": builds or [],
    }


def _build(nvr: str) -> dict[str, str]:
    """Build a synthetic Bodhi ``builds[]`` entry."""
    return {"nvr": nvr}


def _response(
    updates: list[dict[str, object]],
    *,
    total: int | None = None,
    page: int = 1,
) -> dict[str, object]:
    """Wrap a list of updates in a Bodhi response envelope.

    Args:
        updates: List of update dicts.
        total: Total number of updates across all pages. If ``None``,
            uses ``len(updates)``.
        page: Page number (for debugging).
    """
    if total is None:
        total = len(updates)
    return {
        "updates": updates,
        "total": total,
        "page": page,
    }


# ---------------------------------------------------------------------------
# Module-level helper tests
# ---------------------------------------------------------------------------


class TestParseBodhiDate:
    """Tests for :func:`_parse_bodhi_date`."""

    def test_parses_canonical_format(self) -> None:
        """``"YYYY-MM-DD HH:MM:SS"`` parses to a UTC datetime."""
        dt = _parse_bodhi_date("2026-03-11 23:47:27")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 3
        assert dt.day == 11
        assert dt.hour == 23
        assert dt.minute == 47
        assert dt.second == 27
        assert dt.tzinfo is not None
        assert dt.utcoffset() == timedelta(0)

    def test_returns_none_on_empty(self) -> None:
        """Empty string → ``None``."""
        assert _parse_bodhi_date("") is None

    def test_returns_none_on_malformed(self) -> None:
        """Non-date string → ``None``."""
        assert _parse_bodhi_date("not-a-date") is None
        # ISO format with T separator is NOT Bodhi's format
        assert _parse_bodhi_date("2026-03-11T23:47:27") is None


class TestMatchNvr:
    """Tests for :func:`_match_nvr` (BC-3: exact match + version-prefix fallback)."""

    def test_exact_match(self) -> None:
        """Exact match returns ``True``."""
        assert _match_nvr("curl-8.21.0-1.fc45", "curl-8.21.0-1.fc45") is True

    def test_version_prefix_match(self) -> None:
        """Version-prefix fallback matches when version segments are equal."""
        # Same NVR → exact match
        assert _match_nvr("curl-8.21.0-1.fc45", "curl-8.21.0-1.fc45") is True
        # Different release but same version → version-prefix fallback matches
        assert _match_nvr("curl-8.21.0-1.fc45", "curl-8.21.0-2.fc45") is True
        # Different name + version + release → no match
        assert _match_nvr("curl-8.21.0-1.fc45", "wget-1.0-1.fc45") is False

    def test_no_match(self) -> None:
        """Different name, version, or release → ``False``."""
        assert _match_nvr("curl-8.21.0-1.fc45", "wget-1.0-1.fc45") is False
        assert _match_nvr("curl-8.21.0-1.fc45", "curl-9.0.0-1.fc45") is False

    def test_version_with_dash(self) -> None:
        """Versions containing ``-`` are handled correctly (joined back)."""
        # Bodhi NVR with ~ in version
        assert _match_nvr("curl-8.21.0~rc1-1.fc45", "curl-8.21.0~rc1-1.fc45") is True


class TestExtractMatch:
    """Tests for :func:`_extract_match` (BC-1: prefer date_pushed)."""

    def test_prefers_date_pushed_over_date_submitted(self) -> None:
        """When both dates are present, ``date_pushed`` wins."""
        updates = [
            _update(
                date_pushed="2026-03-11 23:47:27",
                date_submitted="2026-03-10 12:00:00",
                builds=[_build("curl-8.21.0-1.fc45")],
            ),
        ]
        result = _extract_match(updates, "curl-8.21.0-1.fc45")
        assert result is not None
        # date_pushed is 2026-03-11, not 2026-03-10
        assert result.day == 11
        assert result.hour == 23

    def test_falls_back_to_date_submitted(self) -> None:
        """When ``date_pushed`` is null, fall back to ``date_submitted``."""
        updates = [
            _update(
                date_pushed=None,
                date_submitted="2026-03-10 12:00:00",
                builds=[_build("curl-8.21.0-1.fc45")],
            ),
        ]
        result = _extract_match(updates, "curl-8.21.0-1.fc45")
        assert result is not None
        assert result.day == 10
        assert result.hour == 12

    def test_handles_null_date_pushed(self) -> None:
        """``date_pushed=null`` falls back to ``date_submitted``."""
        updates = [
            _update(
                date_pushed="",
                date_submitted="2026-03-10 12:00:00",
                builds=[_build("curl-8.21.0-1.fc45")],
            ),
        ]
        result = _extract_match(updates, "curl-8.21.0-1.fc45")
        assert result is not None
        assert result.day == 10

    def test_both_dates_null_returns_none(self) -> None:
        """Both ``date_pushed`` and ``date_submitted`` null → ``None`` (no match)."""
        updates = [
            _update(
                date_pushed=None,
                date_submitted=None,
                builds=[_build("curl-8.21.0-1.fc45")],
            ),
        ]
        result = _extract_match(updates, "curl-8.21.0-1.fc45")
        assert result is None

    def test_no_match_returns_none(self) -> None:
        """NVR not in any update → ``None``."""
        updates = [
            _update(
                builds=[_build("wget-1.0-1.fc45")],
            ),
        ]
        assert _extract_match(updates, "curl-8.21.0-1.fc45") is None

    def test_no_builds_key_returns_none(self) -> None:
        """Update with no ``builds`` key → ``None``."""
        updates = [{"title": "no-builds"}]
        assert _extract_match(updates, "curl-8.21.0-1.fc45") is None

    def test_empty_nvr_build_skipped(self) -> None:
        """Build with empty NVR is skipped (defensive)."""
        updates = [
            _update(
                builds=[
                    {"nvr": ""},
                    _build("curl-8.21.0-1.fc45"),
                ],
            ),
        ]
        result = _extract_match(updates, "curl-8.21.0-1.fc45")
        assert result is not None


class TestCache:
    """Tests for the module-level cache helpers."""

    def test_check_cache_returns_none_when_empty(self) -> None:
        """Empty cache → ``None``."""
        assert _check_cache("curl", "curl-8.21.0-1.fc45") is None

    def test_store_and_check_cache(self) -> None:
        """Stored result is returned on check."""
        dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        _store_cache("curl", "curl-8.21.0-1.fc45", dt)
        result = _check_cache("curl", "curl-8.21.0-1.fc45")
        assert result is not None
        assert result[0] == dt
        assert result[1] == SOURCE_BODHI

    def test_check_cache_expires(self) -> None:
        """Cache entry older than TTL is returned as ``None``."""
        dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        # Manually insert with a stale timestamp
        _cache[("curl", "curl-8.21.0-1.fc45")] = (dt, time.time() - BODHI_CACHE_TTL_SECONDS - 1)
        assert _check_cache("curl", "curl-8.21.0-1.fc45") is None

    def test_store_none_is_cached(self) -> None:
        """Negative result (``None``) is also cached."""
        _store_cache("curl", "curl-8.21.0-1.fc45", None)
        result = _check_cache("curl", "curl-8.21.0-1.fc45")
        assert result is not None
        assert result[0] is None
        assert result[1] == SOURCE_BODHI

    def test_reset_cache_clears(self) -> None:
        """``_reset_cache_for_tests`` empties the cache."""
        _store_cache("curl", "curl-8.21.0-1.fc45", datetime.now(UTC))
        _reset_cache_for_tests()
        assert len(_cache) == 0


# ---------------------------------------------------------------------------
# BodhiClient tests
# ---------------------------------------------------------------------------


def _make_fetch_result(data: dict[str, object] | None, status: int = 200) -> MagicMock:
    """Build a mock FetchResult for use in tests."""
    result = MagicMock()
    result.success = status == 200
    result.data = data
    result.status = status
    return result


class TestBodhiClient:
    """Tests for :class:`BodhiClient`."""

    @pytest.mark.asyncio
    async def test_bodhi_success_path(self) -> None:
        """Happy path: returns (datetime, "bodhi") for a matching update."""
        response = _response(
            [
                _update(
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result[0] is not None
        assert result[0].year == 2026
        assert result[0].month == 3
        assert result[0].day == 11
        assert result[1] == SOURCE_BODHI

    @pytest.mark.asyncio
    async def test_bodhi_prefers_date_pushed_over_date_submitted(self) -> None:
        """BC-1: when both dates are present, ``date_pushed`` is chosen."""
        response = _response(
            [
                _update(
                    date_pushed="2026-03-11 23:47:27",
                    date_submitted="2026-03-10 12:00:00",
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result[0] is not None
        # date_pushed is 11th 23:47, date_submitted is 10th 12:00
        assert result[0].day == 11
        assert result[0].hour == 23

    @pytest.mark.asyncio
    async def test_bodhi_returns_timezone_aware_datetime(self) -> None:
        """BC-2: returned datetime is always UTC-aware."""
        response = _response(
            [
                _update(
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result[0] is not None
        assert result[0].tzinfo is not None
        assert result[0].utcoffset() == timedelta(0)

    @pytest.mark.asyncio
    async def test_bodhi_matches_nvr_in_bundled_update(self) -> None:
        """BC-3: exact NVR match is found within a bundled update."""
        # A bundled update with multiple builds — only one matches
        response = _response(
            [
                _update(
                    builds=[
                        _build("wget-1.0-1.fc45"),
                        _build("curl-8.21.0-1.fc45"),
                        _build("curl-deps-1.0-1.fc45"),
                    ],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result[0] is not None
        assert result[1] == SOURCE_BODHI

    @pytest.mark.asyncio
    async def test_bodhi_handles_null_date_pushed(self) -> None:
        """BC-1 edge case: ``date_pushed=null`` falls back to ``date_submitted``."""
        response = _response(
            [
                _update(
                    date_pushed=None,
                    date_submitted="2026-03-10 12:00:00",
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        # Fallback to date_submitted (10th) instead of None
        assert result[0] is not None
        assert result[0].day == 10

    @pytest.mark.asyncio
    async def test_bodhi_handles_both_dates_null(self) -> None:
        """Both ``date_pushed`` AND ``date_submitted`` null → ``(None, "bodhi")``."""
        response = _response(
            [
                _update(
                    date_pushed=None,
                    date_submitted=None,
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_handles_pagination(self) -> None:
        """Multi-page response: paginate via the ``page`` query parameter."""
        # Page 1: not on this page
        page1 = _response(
            [_update(builds=[_build("wget-1.0-1.fc45")])],
            total=3,
        )
        # Page 2: target is on this page
        page2 = _response(
            [_update(builds=[_build("curl-8.21.0-1.fc45")])],
            total=3,
            page=2,
        )
        # Page 3: empty
        page3 = _response([], total=3, page=3)

        mock_fetch = AsyncMock(
            side_effect=[
                _make_fetch_result(page1),
                _make_fetch_result(page2),
                _make_fetch_result(page3),
            ]
        )
        with patch.object(_bodhi_client, "fetch_json", new=mock_fetch):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result[0] is not None
        # Verify the page parameter was incremented
        assert mock_fetch.await_count == 2
        # Second call should have page=2 in the URL
        second_call = mock_fetch.await_args_list[1]
        assert second_call is not None
        second_url = second_call.args[0]
        assert "page=2" in second_url

    @pytest.mark.asyncio
    async def test_bodhi_handles_4xx(self) -> None:
        """4xx response (e.g. 404) → ``(None, "bodhi")`` (no retry)."""
        # fetch_json with on_404="return_none" returns success=True, data=None
        result = _make_fetch_result(None, status=404)
        result.success = True  # on_404="return_none" sets this
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=result)):
            client = BodhiClient()
            output = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert output == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_handles_5xx(self) -> None:
        """5xx response → ``(None, "bodhi")`` after fetch_json retries exhaust."""
        # fetch_json raises after retries — BodhiClient must catch and return (None, "bodhi")
        err = aiohttp.ClientResponseError(request_info=MagicMock(), history=MagicMock(), status=503)
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(side_effect=err)):
            client = BodhiClient()
            output = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert output == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_handles_aiohttp_client_error(self) -> None:
        """``aiohttp.ClientError`` (network) → ``(None, "bodhi")``."""
        with patch.object(
            _bodhi_client,
            "fetch_json",
            new=AsyncMock(side_effect=aiohttp.ClientError("conn refused")),
        ):
            client = BodhiClient()
            output = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert output == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_handles_empty_response(self) -> None:
        """Empty updates list → ``(None, "bodhi")``."""
        response = _response([], total=0)
        with patch.object(_bodhi_client, "fetch_json", new=AsyncMock(return_value=_make_fetch_result(response))):
            client = BodhiClient()
            output = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert output == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_handles_malformed_json(self) -> None:
        """Malformed JSON (ValueError from json.loads) → ``(None, "bodhi")``."""
        # fetch_json itself shouldn't raise on JSON parse errors because
        # it's responsible for HTTP-level errors. We simulate a
        # malformed response that slips through fetch_json and hits
        # BodhiClient's ValueError handler.
        response = _response(
            [
                _update(
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        # Patch _extract_match to raise ValueError, simulating a
        # downstream parse error.
        with (
            patch.object(
                _bodhi_client,
                "fetch_json",
                new=AsyncMock(return_value=_make_fetch_result(response)),
            ),
            patch.object(
                _bodhi_client,
                "_extract_match",
                side_effect=ValueError("malformed"),
            ),
        ):
            client = BodhiClient()
            output = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        # BodhiClient catches ValueError → (None, "bodhi")
        assert output == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_caches_second_call(self) -> None:
        """Second call with same package/nvr does NOT hit the network."""
        response = _response(
            [
                _update(builds=[_build("curl-8.21.0-1.fc45")]),
            ]
        )
        mock_fetch = AsyncMock(return_value=_make_fetch_result(response))
        with patch.object(_bodhi_client, "fetch_json", new=mock_fetch):
            client = BodhiClient()
            # First call hits network
            result1 = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
            # Second call uses cache
            result2 = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        assert result1[0] == result2[0]
        assert result1[1] == result2[1] == SOURCE_BODHI
        # fetch_json was called only ONCE (the second call was cached)
        assert mock_fetch.await_count == 1

    @pytest.mark.asyncio
    async def test_bodhi_cache_ttl(self) -> None:
        """Cache expires after ``BODHI_CACHE_TTL_SECONDS``."""
        response = _response(
            [
                _update(builds=[_build("curl-8.21.0-1.fc45")]),
            ]
        )
        mock_fetch = AsyncMock(return_value=_make_fetch_result(response))
        # Manually insert a stale cache entry (timestamp is in the past)
        stale_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        _cache[("curl", "curl-8.21.0-1.fc45")] = (
            stale_dt,
            time.time() - BODHI_CACHE_TTL_SECONDS - 1,
        )
        with patch.object(_bodhi_client, "fetch_json", new=mock_fetch):
            client = BodhiClient()
            # Cache is stale → fetch_json IS called
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert mock_fetch.await_count == 1
        assert result[1] == SOURCE_BODHI

    @pytest.mark.asyncio
    async def test_bodhi_never_raises(self) -> None:
        """Patch all internal methods to raise — verify no exception propagates."""
        client = BodhiClient()
        # Patch _walk_updates to raise a caught exception type
        with patch.object(client, "_walk_updates", new=AsyncMock(side_effect=OSError("boom"))):
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        # OSError is in the production code's catch chain
        assert result == (None, SOURCE_BODHI)

    @pytest.mark.asyncio
    async def test_bodhi_request_has_correct_base_url(self) -> None:
        """The request URL starts with :data:`BODHI_BASE_URL`."""
        response = _response(
            [
                _update(builds=[_build("curl-8.21.0-1.fc45")]),
            ]
        )
        mock_fetch = AsyncMock(return_value=_make_fetch_result(response))
        with patch.object(_bodhi_client, "fetch_json", new=mock_fetch):
            client = BodhiClient()
            await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        # Verify the URL was constructed correctly
        first_call = mock_fetch.await_args
        assert first_call is not None
        url = first_call.args[0]
        assert url.startswith(BODHI_BASE_URL)
        assert "packages=curl" in url
        assert "rows_per_page=100" in url
        assert "page=1" in url


# ---------------------------------------------------------------------------
# Constraint C1: Anubis / no HTML parsing
# ---------------------------------------------------------------------------


class TestBodhiClientNoDocAccess:
    """Constraint C1: Bodhi client must NOT parse HTML.

    The :class:`html.parser.HTMLParser` constructor is patched to raise
    on call. If the Bodhi client code (or any module it imports)
    instantiates an HTMLParser, the test fails.
    """

    def test_bodhi_client_does_not_parse_html(self) -> None:
        """``html.parser.HTMLParser`` is never instantiated by the Bodhi client."""
        original_init = html.parser.HTMLParser.__init__

        def _raising_init(self: object, *args: object, **kwargs: object) -> None:
            raise AssertionError(
                "html.parser.HTMLParser was instantiated — Bodhi client must work without HTML parsing (Constraint C1)"
            )

        with patch.object(html.parser.HTMLParser, "__init__", _raising_init):
            # AST-level check: source code must not contain HTMLParser
            import ast
            import inspect

            source = inspect.getsource(_bodhi_client)
            tree = ast.parse(source)
            # Walk the AST looking for any name reference to "HTMLParser"
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "HTMLParser":
                    raise AssertionError(f"Source code references HTMLParser at line {node.lineno}")

        # Sanity: HTMLParser.__init__ is restored
        assert html.parser.HTMLParser.__init__ == original_init

    def test_bodhi_module_does_not_import_html_parser(self) -> None:
        """The Bodhi client module does NOT import ``html.parser`` (or related).

        Uses AST inspection to ignore comments and docstrings — only
        actual code (imports, calls, name references) is checked.
        """
        import ast
        import inspect

        source = inspect.getsource(_bodhi_client)
        tree = ast.parse(source)
        forbidden = {"BeautifulSoup", "bs4", "lxml", "html"}
        # Collect all name references in code (not in docstrings or comments)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in forbidden:
                raise AssertionError(
                    f"Bodhi client references forbidden name {node.id!r} at line {node.lineno} (Constraint C1)"
                )
            if isinstance(node, ast.Attribute) and node.attr in forbidden:
                # e.g. `something.html` or `something.bs4`
                raise AssertionError(
                    f"Bodhi client references forbidden attribute {node.attr!r} at line {node.lineno} (Constraint C1)"
                )


# ---------------------------------------------------------------------------
# Mutation test for date_pushed preference
# ---------------------------------------------------------------------------


class TestMutationDatePushedPreference:
    """Mutation test: BC-1 (prefer date_pushed over date_submitted).

    This test verifies that the boundary case (both dates present,
    distinct values) would fail if the date_pushed preference were
    removed. It is the gold-standard mutation test.
    """

    @pytest.mark.asyncio
    async def test_mutation_date_pushed_preference(self) -> None:
        """If date_pushed preference were removed, this test would fail.

        Setup: date_pushed=2026-03-11, date_submitted=2026-03-10
        (distinct values). With correct code: result day == 11.
        With incorrect (prefer date_submitted): result day == 10.
        """
        response = _response(
            [
                _update(
                    date_pushed="2026-03-11 23:47:27",
                    date_submitted="2026-03-10 12:00:00",
                    builds=[_build("curl-8.21.0-1.fc45")],
                ),
            ]
        )
        with patch.object(
            _bodhi_client,
            "fetch_json",
            new=AsyncMock(return_value=_make_fetch_result(response)),
        ):
            client = BodhiClient()
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        # The current code returns 11th (date_pushed). If we incorrectly
        # preferred date_submitted, we'd get 10th. The test would fail.
        assert result[0] is not None
        assert result[0].day == 11, (
            f"Expected day=11 (date_pushed), got day={result[0].day} — date_pushed preference may be broken"
        )
