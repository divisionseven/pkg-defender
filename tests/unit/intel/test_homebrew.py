"""Tests for Homebrew feed adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from pkg_defender.intel.feeds.homebrew import _normalize_brew_version, _parse_brew_formula
from pkg_defender.registry import brew as brew_module
from pkg_defender.registry._timestamp import ResolutionResult


class TestNormalizeBrewVersion:
    """Tests for _normalize_brew_version()."""

    def test_strip_rebuild_suffix(self) -> None:
        """Version with underscore rebuild suffix gets stripped."""
        assert _normalize_brew_version("1.9.2_1") == "1.9.2"
        assert _normalize_brew_version("1.5.7_1") == "1.5.7"
        assert _normalize_brew_version("2.0.0_3") == "2.0.0"

    def test_preserve_plain_version(self) -> None:
        """Version without underscore suffix is unchanged."""
        assert _normalize_brew_version("1.9.2") == "1.9.2"
        assert _normalize_brew_version("2.0.0") == "2.0.0"

    def test_preserve_digit_after_underscore_not_rebuild(self) -> None:
        """Underscore followed by non-digit is preserved."""
        # This shouldn't normally happen but we preserve it for safety
        assert _normalize_brew_version("1.9.2_beta") == "1.9.2_beta"

    def test_multiple_underscores_only_last_stripped(self) -> None:
        """If multiple underscores, only trailing underscore digit suffix stripped."""
        # Edge case: "1.0_1_2" would become "1.0_1" - but this is unlikely
        assert _normalize_brew_version("1.0_1_2") == "1.0_1"

    def test_empty_and_edge_cases(self) -> None:
        """Empty and edge case inputs handled."""
        assert _normalize_brew_version("") == ""
        assert _normalize_brew_version("1") == "1"
        assert _normalize_brew_version("_1") == "_1"  # No digits before underscore


class TestParseBrewFormula:
    """Tests for _parse_brew_formula()."""

    def test_extracts_homepage_url(self) -> None:
        """When homepage field present, use it as upstream URL."""
        formula = {
            "name": "python",
            "homepage": "https://www.python.org/",
            "installed": [{"version": "3.12.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        name, repo_url, version = result
        assert name == "python"
        assert repo_url == "https://www.python.org/"
        assert version == "3.12.0"

    def test_fallback_to_repository_url(self) -> None:
        """When no homepage, use repository_url field as fallback."""
        formula = {
            "name": "some-package",
            "repository_url": "https://github.com/example/some-package",
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        _, repo_url, _ = result
        assert repo_url == "https://github.com/example/some-package"

    def test_fallback_to_urls_stable_url(self) -> None:
        """When no homepage, use urls.stable.url as fallback."""
        formula = {
            "name": "some-package",
            "urls": {"stable": {"url": "https://example.com/source.tar.gz"}},
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        _, repo_url, _ = result
        assert repo_url == "https://example.com/source.tar.gz"

    def test_fallback_to_tap_url(self) -> None:
        """When no homepage, use tap-constructed URL."""
        formula = {
            "name": "some-tap-package",
            "tap": "homebrew/core",
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        _, repo_url, _ = result
        assert repo_url == "https://github.com/Homebrew/homebrew-core"

    def test_rejects_relative_homepage(self) -> None:
        """Relative homepage URLs are rejected, falls back to tap."""
        formula = {
            "name": "package",
            "homepage": "../relative-path",
            "tap": "homebrew/core",
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is not None
        _, repo_url, _ = result
        # Should fall back to tap URL, not relative path
        assert repo_url == "https://github.com/Homebrew/homebrew-core"

    def test_handles_missing_url(self) -> None:
        """When no URL source available, return None."""
        formula = {
            "name": "unknown-package",
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is None

    def test_handles_none_homepage(self) -> None:
        """None homepage is treated as missing."""
        formula = {
            "name": "package",
            "homepage": None,
            "installed": [{"version": "1.0.0"}],
        }
        result = _parse_brew_formula(formula)
        assert result is None
        assert result is None


class TestBrewAdapterPublishTime:
    """Tests for BrewAdapter.get_publish_time() warning behavior."""

    def _make_mock_resolve_ts(self, dt: datetime | None = None, source: str = "unresolved") -> AsyncMock:
        """Create a mock resolve_timestamp that returns the given datetime/source."""
        status = "resolved" if dt is not None else "all_sources_failed"
        return AsyncMock(
            return_value=ResolutionResult(
                publish_time=dt,
                source_label=source,
                resolution_status=status,
                last_error=None,
            )
        )

    def test_brew_get_publish_time_returns_proxy_silently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """BrewAdapter.get_publish_time returns resolver result WITHOUT emitting UserWarning."""
        import warnings

        async def mock_brew_fetch(url: str, session: object = None) -> dict[str, Any]:
            return {
                "name": "testpkg",
                "versions": {"stable": "1.0.0"},
                "generated_date": "2025-01-15",
            }

        monkeypatch.setattr(brew_module, "_brew_fetch", mock_brew_fetch)

        expected_dt = datetime(2025, 1, 15, tzinfo=UTC)
        mock_resolve_ts = self._make_mock_resolve_ts(dt=expected_dt, source="registry_proxy")

        with (
            patch("pkg_defender.registry.brew.resolve_timestamp", mock_resolve_ts),
            warnings.catch_warnings(record=True) as w,
        ):
            warnings.simplefilter("always")
            adapter = brew_module.BrewAdapter()
            result, source = asyncio.run(adapter.get_publish_time("testpkg", "1.0.0"))

            # Function returns the resolver result
            assert result is not None
            assert result.year == 2025 and result.month == 1 and result.day == 15
            assert source == "registry_proxy"
            # Verify no warning leaks
            user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            assert len(user_warnings) == 0

    def test_brew_get_publish_time_no_warning_on_repeated_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated calls return the resolver result without any warning."""
        import warnings

        async def mock_brew_fetch(url: str, session: object = None) -> dict[str, Any]:
            return {
                "name": "testpkg",
                "versions": {"stable": "1.0.0"},
                "generated_date": "2025-01-15",
            }

        monkeypatch.setattr(brew_module, "_brew_fetch", mock_brew_fetch)

        expected_dt = datetime(2025, 1, 15, tzinfo=UTC)
        mock_resolve_ts = self._make_mock_resolve_ts(dt=expected_dt, source="registry_proxy")

        adapter = brew_module.BrewAdapter()

        with patch("pkg_defender.registry.brew.resolve_timestamp", mock_resolve_ts):
            # First call: returns the resolver result, no warning
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result1, source1 = asyncio.run(adapter.get_publish_time("testpkg", "1.0.0"))

            assert result1 is not None
            assert source1 == "registry_proxy"
            first_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            assert len(first_warnings) == 0

        with patch("pkg_defender.registry.brew.resolve_timestamp", mock_resolve_ts):
            # Second call: also returns the resolver result, no warning
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result2, source2 = asyncio.run(adapter.get_publish_time("testpkg", "1.0.0"))

            assert result2 is not None
            assert source2 == "registry_proxy"
            second_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            assert len(second_warnings) == 0

    def test_brew_get_publish_time_no_warning_for_mismatched_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No warning fires; TimestampResolver is called even when version doesn't match stable."""
        import warnings
        from unittest.mock import patch

        async def mock_brew_fetch(url: str, session: object = None) -> dict[str, Any]:
            return {
                "name": "testpkg",
                "versions": {"stable": "1.0.0"},
                "repository": "https://github.com/owner/testpkg",
                "generated_date": "2025-01-15",
            }

        monkeypatch.setattr(brew_module, "_brew_fetch", mock_brew_fetch)

        adapter = brew_module.BrewAdapter()
        expected_dt = datetime(2025, 1, 15, tzinfo=UTC)
        mock_resolve_ts = self._make_mock_resolve_ts(dt=expected_dt, source="github_tags")

        with (
            patch("pkg_defender.registry.brew.resolve_timestamp", mock_resolve_ts),
            warnings.catch_warnings(record=True) as w,
        ):
            warnings.simplefilter("always")
            result, source = asyncio.run(adapter.get_publish_time("testpkg", "0.9.0"))

            # Resolver result is returned even when version doesn't match stable
            assert result is not None
            assert source == "github_tags"
            # No warning should be emitted
            user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
            assert len(user_warnings) == 0
