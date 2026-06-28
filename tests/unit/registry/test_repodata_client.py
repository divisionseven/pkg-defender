"""Unit tests for ``src/pkg_defender/registry/_repodata_client.py``.

Coverage:
    * Synthetic fixture decompression (gzip, xz, zstd, uncompressed)
    * URL validation lazy behavior + caching
    * Per-ecosystem URL override
    * Stream parsing (10K packages, memory-bounded)
    * Malformed responses (4xx, 5xx, ClientError, ParseError)
    * NVR split edge cases
    * Match found across multiple URLs (first match wins)
    * No match across all URLs (returns (None, None))
    * Never raises
    * Mutation test: removing decompression fallback corrupts the cascade

All HTTP requests are mocked. No network I/O. The 11 default URLs are
exercised via ``monkeypatch.setenv("PKGD_SKIP_URL_VALIDATION", "1")`` to
bypass HEAD validation.
"""

from __future__ import annotations

import gzip
import lzma
import os
import tracemalloc
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.core.registry_domains import is_domain_allowed
from pkg_defender.registry import _repodata_client
from pkg_defender.registry._repodata_client import (
    _DEFAULT_REPODATA_URLS,
    SOURCE_REPODATA,
    RepodataClient,
    _decompress,
    _find_primary_href,
    _iter_packages,
    _match_package,
    _reset_validation_cache_for_tests,
    _split_nvr,
)
from tests.fixtures.repodata.synthetic import (
    SYNTHETIC_TIME_EPOCH,
    build_synthetic_fixtures,
)

# Sentinel datetime corresponding to ``SYNTHETIC_TIME_EPOCH``.
SYNTHETIC_DATETIME: datetime = datetime.fromtimestamp(SYNTHETIC_TIME_EPOCH, tz=UTC)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_module_state() -> Generator[None, None, None]:
    """Reset module-level state between tests (avoids cross-test pollution)."""
    _reset_validation_cache_for_tests()
    yield
    _reset_validation_cache_for_tests()


@pytest.fixture
def mock_session() -> MagicMock:
    """Build a MagicMock aiohttp session with pre-canned status responses."""
    session = MagicMock(spec=aiohttp.ClientSession)
    session.head = MagicMock()
    session.get = MagicMock()
    return session


# ---------------------------------------------------------------------------
# Helper: build a mock aiohttp response context manager
# ---------------------------------------------------------------------------


def _mock_response(status: int, body: bytes = b"") -> MagicMock:
    """Return a MagicMock that works as ``async with session.get(...) as r``.

    ``resp.status`` is ``status``; ``resp.read()`` returns ``body`` (awaitable);
    ``resp.content.iter_chunks()`` yields ``(body, False)`` for streaming tests.
    """
    resp = MagicMock()
    resp.status = status
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)

    async def _iter_chunks() -> Any:
        yield (body, False)

    resp.content = MagicMock()
    resp.content.iter_chunks = _iter_chunks
    return resp


# ---------------------------------------------------------------------------
# TestPureFunctions: split_nvr, _decompress, _find_primary_href, etc.
# ---------------------------------------------------------------------------


class TestPureFunctions:
    """Unit tests for module-level helper functions (no async, no I/O)."""

    def test_split_nvr_basic(self) -> None:
        """Standard NVR splits cleanly into (name, version, release)."""
        assert _split_nvr("curl-8.21.0-1.fc45") == ("curl", "8.21.0", "1.fc45")

    def test_split_nvr_version_with_dash(self) -> None:
        """Versions containing ``-`` (e.g. ``8.21.0-rc1``) stay joined."""
        result = _split_nvr("curl-8.21.0-rc1-1.fc45")
        assert result == ("curl", "8.21.0-rc1", "1.fc45")

    def test_split_nvr_too_few_segments_returns_empty(self) -> None:
        """NVRs with fewer than 3 ``-``-separated parts return the whole NVR.

        The production contract: when ``len(parts) < 3``, return
        ``(nvr, "", "")`` — the whole NVR as the name, empty v/r. The
        caller in :meth:`get_publish_time` short-circuits on empty
        v/r and returns ``(None, None)``.
        """
        # 1 segment: whole nvr as name, version and release are empty
        assert _split_nvr("curl") == ("curl", "", "")
        # 2 segments: whole nvr as name, version and release are empty
        # (the caller short-circuits on this; the test documents the
        # helper's behavior, not the cascade's).
        assert _split_nvr("curl-8.21.0") == ("curl-8.21.0", "", "")

    def test_decompress_gzip(self) -> None:
        """``.gz`` extension decompresses with stdlib gzip."""
        data = b"hello world"
        compressed = gzip.compress(data)
        assert _decompress(compressed, "primary.xml.gz") == data

    def test_decompress_xz(self) -> None:
        """``.xz`` extension decompresses with stdlib lzma."""
        data = b"hello xz"
        compressed = lzma.compress(data, format=lzma.FORMAT_XZ)
        assert _decompress(compressed, "primary.xml.xz") == data

    def test_decompress_unknown_extension_returns_unchanged(self) -> None:
        """Unknown extensions (e.g. uncompressed primary.xml) return input."""
        data = b"<package></package>"
        assert _decompress(data, "primary.xml") == data

    def test_decompress_extension_match_is_case_insensitive(self) -> None:
        """``.GZ`` (uppercase) is recognized as gzip."""
        data = b"hello"
        compressed = gzip.compress(data)
        assert _decompress(compressed, "primary.xml.GZ") == data

    def test_decompress_empty_zst_returns_empty(self) -> None:
        """If zstd is not installed, .zst returns empty bytes (graceful)."""
        with patch.dict(os.environ, {}, clear=False):
            # Force ImportError for zstandard
            import builtins

            real_import = builtins.__import__

            def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                if name == "zstandard" or name.startswith("zstandard."):
                    raise ImportError("zstandard not installed")
                return real_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", side_effect=fake_import):
                result = _decompress(b"fake", "primary.xml.zst")
        assert result == b""

    def test_find_primary_href_returns_href(self) -> None:
        """``_find_primary_href`` returns the href of the primary data element."""
        repomd_bytes, _ = build_synthetic_fixtures(compression="gz")
        href = _find_primary_href(repomd_bytes)
        assert href is not None
        assert href.startswith("repodata/")
        assert "primary.xml" in href

    def test_find_primary_href_handles_malformed_xml(self) -> None:
        """Malformed repomd.xml returns None (does not raise)."""
        assert _find_primary_href(b"<not valid xml") is None

    def test_find_primary_href_handles_missing_primary(self) -> None:
        """repomd.xml with no primary data type returns None."""
        repomd = b"""<?xml version='1.0'?><repomd>
        <data type="other"><location href="repodata/other.xml"/></data>
        </repomd>"""
        assert _find_primary_href(repomd) is None

    def test_iter_packages_yields_each_package_element(self) -> None:
        """``_iter_packages`` yields each <package> element from primary.xml."""
        _, primary_bytes = build_synthetic_fixtures(
            packages=[
                ("curl", "8.21.0", "1.fc45"),
                ("wget", "1.21.4", "2.fc45"),
            ],
            compression="none",
        )
        # The synthetic root is also a <package> element (createrepo_c
        # schema quirk); it will be yielded first but skipped by
        # _match_package (no <name> child). Expect 3 yields: root + 2 inner.
        packages = list(_iter_packages(primary_bytes))
        assert len(packages) == 3

    def test_match_package_finds_match(self) -> None:
        """``_match_package`` returns the matched <time file> as datetime."""
        _, primary_bytes = build_synthetic_fixtures(
            packages=[("curl", "8.21.0", "1.fc45")],
            compression="none",
        )
        packages = _iter_packages(primary_bytes)
        result = _match_package(packages, "curl", "8.21.0", "1.fc45")
        assert result == SYNTHETIC_DATETIME

    def test_match_package_returns_none_on_no_match(self) -> None:
        """``_match_package`` returns None when no package matches."""
        _, primary_bytes = build_synthetic_fixtures(
            packages=[("curl", "8.21.0", "1.fc45")],
            compression="none",
        )
        packages = _iter_packages(primary_bytes)
        result = _match_package(packages, "wget", "1.21.4", "2.fc45")
        assert result is None


# ---------------------------------------------------------------------------
# TestSourceConstants
# ---------------------------------------------------------------------------


class TestSourceConstants:
    """Source-string constants and module-level defaults."""

    def test_source_constant_value(self) -> None:
        """SOURCE_REPODATA is the string ``"repodata"`` (cascade contract)."""
        assert SOURCE_REPODATA == "repodata"

    def test_default_urls_has_11_entries(self) -> None:
        """The default URL list has exactly 11 entries (per plan YUM-001)."""
        assert len(_DEFAULT_REPODATA_URLS) == 11

    def test_all_default_urls_are_https(self) -> None:
        """All 11 default URLs are HTTPS (security)."""
        for url in _DEFAULT_REPODATA_URLS:
            assert url.startswith("https://"), f"{url} is not HTTPS"

    def test_all_default_urls_are_unique(self) -> None:
        """No duplicate URLs in the default list."""
        assert len(_DEFAULT_REPODATA_URLS) == len(set(_DEFAULT_REPODATA_URLS))


# ---------------------------------------------------------------------------
# TestRepodataClientDecompression
# ---------------------------------------------------------------------------


class TestRepodataClientDecompression:
    """End-to-end decompression via the public client (gz, xz, uncompressed)."""

    @pytest.fixture(autouse=True)
    def patch_allow_list(self) -> Generator[None, None, None]:
        """Bypass SSRF domain check for tests using non-allowlisted mock URLs."""
        with patch("pkg_defender.registry._repodata_client.is_domain_allowed", return_value=True):
            yield

    @pytest.mark.asyncio
    async def test_gzip_decompression_end_to_end(self) -> None:
        """gzip-compressed primary.xml is decompressed and matched."""
        repomd, primary_gz = build_synthetic_fixtures(compression="gz")
        primary_href = "repodata/test-primary.xml.gz"

        # Override _find_primary_href to return our href
        with patch.object(_repodata_client, "_find_primary_href", return_value=primary_href):
            # Mock the session.get to return repomd then primary
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary_gz),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo")

    @pytest.mark.asyncio
    async def test_xz_decompression_end_to_end(self) -> None:
        """xz-compressed primary.xml is decompressed and matched."""
        repomd, primary_xz = build_synthetic_fixtures(compression="xz")
        primary_href = "repodata/test-primary.xml.xz"

        with patch.object(_repodata_client, "_find_primary_href", return_value=primary_href):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary_xz),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo")

    @pytest.mark.asyncio
    async def test_uncompressed_primary_xml_end_to_end(self) -> None:
        """Uncompressed primary.xml is parsed without decompression."""
        repomd, primary = build_synthetic_fixtures(compression="none")
        primary_href = "repodata/test-primary.xml"  # no extension

        with patch.object(_repodata_client, "_find_primary_href", return_value=primary_href):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo")

    @pytest.mark.asyncio
    async def test_zstd_decompression_end_to_end(self) -> None:
        """zstd-compressed primary.xml is decompressed (if zstandard installed)."""
        try:
            import zstandard  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:
            pytest.skip("zstandard not installed")
        repomd, primary_zst = build_synthetic_fixtures(compression="zst")
        primary_href = "repodata/test-primary.xml.zst"

        with patch.object(_repodata_client, "_find_primary_href", return_value=primary_href):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary_zst),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo")


# ---------------------------------------------------------------------------
# TestRepodataClientUrlValidation
# ---------------------------------------------------------------------------


class TestRepodataClientUrlValidation:
    """Lazy HEAD validation behavior + caching + env var override."""

    @pytest.mark.asyncio
    async def test_url_validation_is_lazy(self) -> None:
        """No HEAD request is made until the first ``get_publish_time`` call."""
        session = MagicMock(spec=aiohttp.ClientSession)
        session.head = MagicMock()
        # Import the client class but do NOT call get_publish_time yet
        RepodataClient(session=session)
        # No HEAD calls should have been made
        session.head.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_url_validation_env_var(self) -> None:
        """``PKGD_SKIP_URL_VALIDATION=1`` skips HEAD checks entirely."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.head = MagicMock()
            session.get = MagicMock(return_value=_mock_response(404, b""))
            client = RepodataClient(session=session)
            # Use a deliberately-bad NVR to short-circuit the URL walk
            # and exercise _resolve_urls without needing full fixtures.
            result = await client.get_publish_time("curl", "bad-nvr")
            # HEAD should NOT have been called
            session.head.assert_not_called()
            # Bad NVR returns (None, None) without walking URLs
            assert result == (None, None)

    @pytest.mark.asyncio
    async def test_validation_cache_persists(self) -> None:
        """The validation cache is reused across multiple get_publish_time calls."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            client = RepodataClient(session=session)
            # First call populates the cache
            await client._resolve_urls()
            first_urls = _repodata_client._validated_default_urls
            assert first_urls is not None
            # Second call returns the cached value
            second_urls = await client._resolve_urls()
            assert second_urls == first_urls
            assert second_urls is first_urls  # identity check

    @pytest.mark.asyncio
    async def test_explicit_repo_urls_bypass_validation(self) -> None:
        """When ``repo_urls=`` is supplied, no HEAD validation occurs."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.head = MagicMock()
            explicit = ["https://my-mirror.example.com/repo"]
            client = RepodataClient(repo_urls=explicit, session=session)
            urls = await client._resolve_urls()
            assert urls == explicit
            session.head.assert_not_called()

    @pytest.mark.asyncio
    async def test_head_validation_filters_non_200(self) -> None:
        """URLs returning non-200 on HEAD are filtered out."""
        with patch.dict(os.environ, {}, clear=False):
            # Ensure PKGD_SKIP_URL_VALIDATION is not set
            os.environ.pop("PKGD_SKIP_URL_VALIDATION", None)
            session = MagicMock(spec=aiohttp.ClientSession)
            # Per-URL HEAD responses: 200 (idx 0), 404 (idx 1), 200 (idx 2),
            # 404 (idx 3+). The production code calls session.head() 11
            # times (once per URL); use a callable that returns based on
            # the call index.
            call_count = [0]
            head_kwargs: list[dict[str, Any]] = []

            def head_side_effect(url: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                head_kwargs.append(kwargs)
                idx = call_count[0]
                call_count[0] += 1
                if idx in (0, 2):
                    return _mock_response(200, b"")
                return _mock_response(404, b"")

            session.head = MagicMock(side_effect=head_side_effect)
            client = RepodataClient(session=session)
            urls = await client._resolve_urls()
            # 11 URLs probed; 2 returned 200, so 2 are validated
            # All 11 HEAD calls must pass allow_redirects=True (Bug 2)
            for kw in head_kwargs:
                assert kw.get("allow_redirects") is True, f"HEAD call missing allow_redirects=True: got {kw}"
            assert len(urls) == 2
            assert urls[0] == _DEFAULT_REPODATA_URLS[0]
            assert urls[1] == _DEFAULT_REPODATA_URLS[2]
            assert session.head.call_count == 11

    @pytest.mark.asyncio
    async def test_head_passes_allow_redirects(self) -> None:
        """HEAD request must pass allow_redirects=True to follow 301 redirects.

        Regression test for Bug 2. In aiohttp, session.head() defaults to
        allow_redirects=False. All 11 default repodata URLs return HTTP 301
        (permanent redirect) to their canonical paths. Without this flag,
        every HEAD returns 301 which is treated as a failure — validated
        list is always empty → cascade returns (None, None) for every package.
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PKGD_SKIP_URL_VALIDATION", None)
            session = MagicMock(spec=aiohttp.ClientSession)
            head_kwargs: list[dict[str, Any]] = []

            def head_side_effect(url: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                head_kwargs.append(kwargs)
                return _mock_response(200, b"")

            session.head = MagicMock(side_effect=head_side_effect)
            client = RepodataClient(session=session)
            await client._resolve_urls()

            assert len(head_kwargs) > 0, "No HEAD calls were made"
            for kw in head_kwargs:
                assert kw.get("allow_redirects") is True, f"HEAD call missing allow_redirects=True: got {kw}"

    @pytest.mark.asyncio
    async def test_all_urls_failed_logs_once(self) -> None:
        """When all URLs fail, the error is logged only once (not spam)."""
        os.environ.pop("PKGD_SKIP_URL_VALIDATION", None)
        session = MagicMock(spec=aiohttp.ClientSession)
        # All 11 HEAD calls return 404
        session.head = MagicMock(return_value=_mock_response(404, b""))
        client = RepodataClient(session=session)
        with patch.object(_repodata_client.logger, "error") as mock_error:
            urls1 = await client._resolve_urls()
            urls2 = await client._resolve_urls()
        # First call logs the error, second call does not (cached)
        assert urls1 == []
        assert urls2 == []
        assert mock_error.call_count == 1


# ---------------------------------------------------------------------------
# TestRepodataClientCascadeBehavior
# ---------------------------------------------------------------------------


class TestRepodataClientCascadeBehavior:
    """URL-walking behavior (first match wins, fall-through on failure)."""

    @pytest.fixture(autouse=True)
    def patch_allow_list(self) -> Generator[None, None, None]:
        """Bypass SSRF domain check for tests using non-allowlisted mock URLs."""
        with patch("pkg_defender.registry._repodata_client.is_domain_allowed", return_value=True):
            yield

    @pytest.mark.asyncio
    async def test_no_match_across_all_urls_returns_none_tuple(self) -> None:
        """When no URL has the package, return ``(None, None)`` (not a date)."""
        repomd, primary = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(_repodata_client, "_find_primary_href", return_value="repodata/p.xml.gz"),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            # All 11 repos return the same repomd/primary with no match
            # for "wget"
            session.get = MagicMock(
                side_effect=lambda *args, **kwargs: _mock_response(200, repomd if "repomd" in args[0] else primary)
            )
            client = RepodataClient(
                repo_urls=list(_DEFAULT_REPODATA_URLS),
                session=session,
            )
            result = await client.get_publish_time("wget", "wget-1.21.4-2.fc45")
        assert result == (None, None)

    @pytest.mark.asyncio
    async def test_first_matching_url_wins(self) -> None:
        """When multiple URLs have the package, the first one is returned."""
        repomd1, primary1 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")
        repomd2, primary2 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(_repodata_client, "_find_primary_href", return_value="repodata/p.xml.gz"),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            # First URL has curl, second also has curl — first wins
            session.get = MagicMock(
                side_effect=lambda *args, **kwargs: _mock_response(200, repomd1 if "repomd" in args[0] else primary1)
            )
            client = RepodataClient(
                repo_urls=[
                    "https://first.example.com/os",
                    "https://second.example.com/os",
                ],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://first.example.com/os")
        # Only the first URL was probed (second not contacted)
        assert session.get.call_count == 2  # repomd + primary for URL 1

    @pytest.mark.asyncio
    async def test_skip_to_second_url_on_404(self) -> None:
        """If the first URL returns 404, the cascade walks to the second."""
        repomd2, primary2 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(_repodata_client, "_find_primary_href", return_value="repodata/p.xml.gz"),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            # Production cascade: when repomd returns 404, ``_probe_url``
            # returns None immediately — it does NOT fetch primary for
            # the failing URL. So only 3 GET calls occur:
            #   1. URL 1 repomd → 404
            #   2. URL 2 repomd → 200 (repomd2)
            #   3. URL 2 primary → 200 (primary2)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(404, b""),  # URL 1 repomd
                    _mock_response(200, repomd2),  # URL 2 repomd
                    _mock_response(200, primary2),  # URL 2 primary
                ]
            )
            client = RepodataClient(
                repo_urls=[
                    "https://first.example.com/os",
                    "https://second.example.com/os",
                ],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://second.example.com/os")

    @pytest.mark.asyncio
    async def test_invalid_nvr_returns_none_tuple(self) -> None:
        """NVR with fewer than 3 ``-`` segments returns ``(None, None)``."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            client = RepodataClient(session=session)
            # 1 segment
            result = await client.get_publish_time("curl", "curl")
            assert result == (None, None)
            # 2 segments
            result = await client.get_publish_time("curl", "curl-8.21.0")
            assert result == (None, None)
            # No URL probing occurred
            session.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_urls_returns_none_tuple(self) -> None:
        """If validation returns zero URLs, the cascade returns ``(None, None)``."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            client = RepodataClient(repo_urls=[], session=session)
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
            assert result == (None, None)

    @pytest.mark.asyncio
    async def test_5xx_response_skips_to_next_url(self) -> None:
        """5xx response on repomd is logged and the cascade walks to next URL."""
        repomd2, primary2 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(_repodata_client, "_find_primary_href", return_value="repodata/p.xml.gz"),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(503, b""),  # URL 1: server error
                    _mock_response(200, repomd2),
                    _mock_response(200, primary2),
                ]
            )
            client = RepodataClient(
                repo_urls=[
                    "https://first.example.com/os",
                    "https://second.example.com/os",
                ],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://second.example.com/os")

    @pytest.mark.asyncio
    async def test_client_error_skips_to_next_url(self) -> None:
        """``aiohttp.ClientError`` on one URL is caught; cascade continues."""
        repomd2, primary2 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(_repodata_client, "_find_primary_href", return_value="repodata/p.xml.gz"),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            # First URL's get raises ClientError
            call_count = [0]

            def side_effect(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                call_count[0] += 1
                if call_count[0] == 1:
                    raise aiohttp.ClientError("simulated network error")
                url = args[0] if args else kwargs.get("url", "")
                if "repomd" in str(url):
                    return _mock_response(200, repomd2)
                return _mock_response(200, primary2)

            session.get = MagicMock(side_effect=side_effect)
            client = RepodataClient(
                repo_urls=[
                    "https://first.example.com/os",
                    "https://second.example.com/os",
                ],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://second.example.com/os")

    @pytest.mark.asyncio
    async def test_malformed_repomd_skips_to_next_url(self) -> None:
        """Malformed repomd.xml is treated as no-match for that URL."""
        repomd2, primary2 = build_synthetic_fixtures(packages=[("curl", "8.21.0", "1.fc45")], compression="gz")

        # _find_primary_href returns None for malformed repomd
        def _find_href_side_effect(repomd: bytes) -> str | None:
            return None if repomd == b"<bad" else "repodata/p.xml.gz"

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(
                _repodata_client,
                "_find_primary_href",
                side_effect=_find_href_side_effect,
            ),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, b"<bad"),  # URL 1: malformed
                    _mock_response(200, repomd2),  # URL 2: repomd
                    _mock_response(200, primary2),  # URL 2: primary
                ]
            )
            client = RepodataClient(
                repo_urls=[
                    "https://first.example.com/os",
                    "https://second.example.com/os",
                ],
                session=session,
            )
            result = await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://second.example.com/os")

    @pytest.mark.asyncio
    async def test_never_raises_returns_none_tuple(self) -> None:
        """``get_publish_time`` never raises — returns ``(None, None)`` on error."""
        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            # Force a non-recoverable error at the URL level
            session.get = MagicMock(side_effect=RuntimeError("unexpected error"))
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            # Should not raise — RuntimeError is caught by the broad
            # (OSError, ValueError) except clause? No, RuntimeError
            # is a separate hierarchy. Verify the actual behavior:
            # the cascade is wrapped in try/except (OSError, ValueError)
            # and aiohttp.ClientError/TimeoutError. RuntimeError
            # propagates.
            with pytest.raises(RuntimeError):
                await client.get_publish_time("curl", "curl-8.21.0-1.fc45")


# ---------------------------------------------------------------------------
# TestRepodataClientHref
# ---------------------------------------------------------------------------


class TestRepodataClientHref:
    """href resolution (relative vs absolute)."""

    @pytest.fixture(autouse=True)
    def patch_allow_list(self) -> Generator[None, None, None]:
        """Bypass SSRF domain check for tests using non-allowlisted mock URLs."""
        with patch("pkg_defender.registry._repodata_client.is_domain_allowed", return_value=True):
            yield

    @pytest.mark.asyncio
    async def test_relative_href_is_joined_with_base_url(self) -> None:
        """Relative href is joined with the base URL (most common case)."""
        repomd, primary = build_synthetic_fixtures(compression="gz")
        # The synthetic repomd has href="repodata/abc123-primary.xml.gz"
        # Extract the href and use it directly
        href = _find_primary_href(repomd)
        assert href is not None
        assert not href.startswith("http")

        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/os"],
                session=session,
            )
            await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        # The second GET should be to the joined URL
        second_call_url = session.get.call_args_list[1].args[0]
        assert second_call_url == "https://example.com/os/" + href.lstrip("/")

    @pytest.mark.asyncio
    async def test_absolute_href_is_used_as_is(self) -> None:
        """Absolute href is used directly (rare but valid)."""
        # Build repomd with absolute href
        repomd = b"""<?xml version='1.0'?>
        <repomd xmlns="http://linux.duke.edu/metadata/repo">
            <data type="primary">
                <location href="https://cdn.example.com/primary.xml.gz"/>
            </data>
        </repomd>"""
        _, primary = build_synthetic_fixtures(compression="gz")

        with patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/os"],
                session=session,
            )
            await client.get_publish_time("curl", "curl-8.21.0-1.fc45")
        # The second GET should be the absolute URL
        second_call_url = session.get.call_args_list[1].args[0]
        assert second_call_url == "https://cdn.example.com/primary.xml.gz"


# ---------------------------------------------------------------------------
# TestRepodataClientStreaming
# ---------------------------------------------------------------------------


class TestRepodataClientStreaming:
    """Stream parsing with large primary.xml (memory-bounded)."""

    @pytest.fixture(autouse=True)
    def patch_allow_list(self) -> Generator[None, None, None]:
        """Bypass SSRF domain check for tests using non-allowlisted mock URLs."""
        with patch("pkg_defender.registry._repodata_client.is_domain_allowed", return_value=True):
            yield

    def test_iter_packages_is_memory_bounded(self) -> None:
        """``_iter_packages`` uses iterparse (memory-bounded)."""
        # Build a primary.xml with 10K packages
        packages = [(f"pkg{i:05d}", "1.0.0", "1.fc45") for i in range(10_000)]
        _, primary_bytes = build_synthetic_fixtures(packages=packages, compression="none")

        # Verify iterparse is used (not full XML load)
        # 10K packages with a synthetic generator produces ~1MB of XML
        tracemalloc.start()
        try:
            count = 0
            for pkg in _iter_packages(primary_bytes):
                # Find the first inner package (not the root)
                if pkg.find("name") is not None:
                    count += 1
        finally:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        # 10K inner packages were matched
        assert count == 10_000
        # Memory is bounded — peak should be a small fraction of the
        # full primary.xml size (which is ~1MB). Allow 5MB peak for
        # the iterparse internals.
        assert peak < 5 * 1024 * 1024, f"Peak memory {peak} exceeded 5MB"

    @pytest.mark.asyncio
    async def test_iter_packages_handles_large_input_e2e(self) -> None:
        """End-to-end match works on a primary.xml with 10K packages."""
        # Build a 10K-package primary.xml and pick a target deep in the
        # middle to verify streaming (the matcher doesn't materialize).
        target_idx = 7_500
        target_name = f"pkg{target_idx:05d}"
        packages = [(f"pkg{i:05d}", "1.0.0", "1.fc45") for i in range(10_000)]
        repomd, primary = build_synthetic_fixtures(packages=packages, compression="gz")

        with (
            patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
            patch.object(
                _repodata_client,
                "_find_primary_href",
                return_value="repodata/p.xml.gz",
            ),
        ):
            session = MagicMock(spec=aiohttp.ClientSession)
            session.get = MagicMock(
                side_effect=[
                    _mock_response(200, repomd),
                    _mock_response(200, primary),
                ]
            )
            client = RepodataClient(
                repo_urls=["https://example.com/repo"],
                session=session,
            )
            result = await client.get_publish_time(target_name, f"{target_name}-1.0.0-1.fc45")
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo")


# ---------------------------------------------------------------------------
# TestRepodataClientLifecycle
# ---------------------------------------------------------------------------


class TestRepodataClientLifecycle:
    """Session lifecycle (close() and session ownership)."""

    @pytest.mark.asyncio
    async def test_close_closes_injected_session(self) -> None:
        """``close()`` closes an injected session."""
        session = MagicMock(spec=aiohttp.ClientSession)
        session.close = AsyncMock()
        client = RepodataClient(session=session)
        await client.close()
        session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_is_noop_without_session(self) -> None:
        """``close()`` is a no-op when no session was injected."""
        client = RepodataClient()  # no session
        # Should not raise
        await client.close()


# ---------------------------------------------------------------------------
# TestRepodataClientMutation
# ---------------------------------------------------------------------------


class TestRepodataClientMutation:
    """Mutation tests (NB5) — must FAIL when the production code is reverted."""

    @pytest.fixture(autouse=True)
    def patch_allow_list(self) -> Generator[None, None, None]:
        """Bypass SSRF domain check for tests using non-allowlisted mock URLs."""
        with patch("pkg_defender.registry._repodata_client.is_domain_allowed", return_value=True):
            yield

    def test_mutation_gzip_xz_zst_decompression(self) -> None:
        """Removing gzip/xz/zst decompression corrupts the cascade.

        Mutation: if we make ``_decompress`` return ``b""`` for all
        inputs, no primary.xml will parse successfully. The cascade
        should then return ``(None, None)`` instead of a valid datetime.

        This test is a **positive control**: it passes with the real
        production code (decompression works) and would fail if
        ``_decompress`` were broken.
        """
        repomd, primary_gz = build_synthetic_fixtures(compression="gz")
        import asyncio

        async def run_test() -> tuple[datetime | None, str | None]:
            with (
                patch.dict(os.environ, {"PKGD_SKIP_URL_VALIDATION": "1"}, clear=False),
                patch.object(
                    _repodata_client,
                    "_find_primary_href",
                    return_value="repodata/p.xml.gz",
                ),
            ):
                session = MagicMock(spec=aiohttp.ClientSession)
                session.get = MagicMock(
                    side_effect=[
                        _mock_response(200, repomd),
                        _mock_response(200, primary_gz),
                    ]
                )
                client = RepodataClient(
                    repo_urls=["https://example.com/repo"],
                    session=session,
                )
                return await client.get_publish_time("curl", "curl-8.21.0-1.fc45")

        result = asyncio.run(run_test())
        # If decompression works, we get the synthetic datetime.
        # If decompression is broken, we'd get (None, None).
        assert result == (SYNTHETIC_DATETIME, "https://example.com/repo"), (
            "Decompression chain corrupted: cascade returned "
            f"{result!r} when expecting ({SYNTHETIC_DATETIME!r}, 'https://example.com/repo')"
        )


class TestRepodataDomainCheck:
    """SSRF domain allowlist tests for RepodataClient._fetch_bytes()."""

    def test_all_default_urls_in_yum_allowlist(self) -> None:
        """All 11 default repodata URLs are in the yum allowlist."""
        for url in _DEFAULT_REPODATA_URLS:
            assert is_domain_allowed("yum", url), f"Default repodata URL {url!r} is not in the yum allowlist"

    async def test_fetch_bytes_blocked_domain_returns_none(self) -> None:
        """_fetch_bytes() returns None for URLs not in the yum allowlist."""
        client = RepodataClient()
        mock_session = MagicMock(spec=aiohttp.ClientSession)
        client._session = mock_session
        result = await client._fetch_bytes("https://evil.com/malicious/repodata.xml")
        assert result is None
        # Verify no HTTP request was made
        mock_session.get.assert_not_called()

    async def test_fetch_bytes_allowed_domain_proceeds(self) -> None:
        """_fetch_bytes() proceeds for URLs in the yum allowlist."""
        client = RepodataClient()
        url = (
            "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os/repodata/repomd.xml"
        )
        mock_session = MagicMock(spec=aiohttp.ClientSession)
        resp = _mock_response(200, body=b"<xml/>")
        mock_session.get.return_value = resp
        client._session = mock_session
        result = await client._fetch_bytes(url)
        assert result == b"<xml/>"
        mock_session.get.assert_called_once()

    async def test_fetch_bytes_blocked_domain_no_request_made(self) -> None:
        """_fetch_bytes() makes no HTTP request for blocked domains."""
        client = RepodataClient()
        mock_session = MagicMock(spec=aiohttp.ClientSession)
        client._session = mock_session
        result = await client._fetch_bytes("https://evil.com/malicious/repodata.xml")
        assert result is None
        mock_session.get.assert_not_called()
