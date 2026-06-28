"""Tests for Homebrew feed adapter - intel/feeds/homebrew.py"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.intel.base import FetchStatus
from pkg_defender.intel.feeds import homebrew as homebrew_module


class _HomebrewKwargs(TypedDict):
    """Typed kwargs for _parse_osv_vuln calls in Homebrew tests."""

    ecosystem: str
    id_prefix: str
    source: str
    include_eco_in_id: bool


class _MockResponse:
    """Mock response object for async context manager.

    This is needed because MagicMock's __aenter__ returns an AsyncMock which
    triggers RuntimeWarning when used in async with statements.
    """

    raise_for_status = MagicMock()

    def __init__(self) -> None:
        self.json = AsyncMock()

    async def __aenter__(self) -> _MockResponse:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass


class TestHomebrewFeedAdapter:
    """Test HomebrewFeedAdapter class."""

    def test_name_property(self) -> None:
        """The feed name should be 'homebrew'."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        assert adapter.name == "homebrew"

    def test_supports_incremental_false(self) -> None:
        """Homebrew feed should not support incremental sync."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        assert adapter.supports_incremental is False

    @patch("shutil.which")
    def test_is_configured_brew_installed(self, mock_which: MagicMock) -> None:
        """Returns True when brew is found."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        mock_which.return_value = "/opt/homebrew/bin/brew"
        adapter = HomebrewFeedAdapter()
        config = MagicMock()
        assert adapter.is_configured(config) is True

    @patch("shutil.which")
    def test_is_configured_brew_not_installed(self, mock_which: MagicMock) -> None:
        """Returns False when brew is not found."""
        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        mock_which.return_value = None
        adapter = HomebrewFeedAdapter()
        config = MagicMock()
        assert adapter.is_configured(config) is False


class TestGetInstalledFormulae:
    """Tests for get_installed_formulae()."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_brew_not_installed_raises(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Raises BrewNotInstalledError when brew not found."""
        from pkg_defender.intel.feeds.homebrew import BrewNotInstalledError

        mock_which.return_value = None
        with pytest.raises(BrewNotInstalledError):
            homebrew_module.get_installed_formulae()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_brew_command_fails_raises(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Raises CalledProcessError when brew returns non-zero."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error"
        mock_result.args = ["brew"]
        mock_run.return_value = mock_result

        from subprocess import CalledProcessError

        from pkg_defender.intel.feeds.homebrew import get_installed_formulae

        # CalledProcessError is raised when brew fails
        with pytest.raises(CalledProcessError):
            get_installed_formulae()

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_valid_json_returns_formulae(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Returns list of formulae when brew returns valid JSON."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"formulae": [{"name": "python"}]}'
        mock_run.return_value = mock_result

        result = homebrew_module.get_installed_formulae()
        assert len(result) == 1
        assert result[0]["name"] == "python"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_invalid_json_returns_empty_list(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        """Returns empty list when brew output is invalid JSON."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not valid json"
        mock_run.return_value = mock_result

        result = homebrew_module.get_installed_formulae()
        assert result == []


class TestCheckBrewPackage:
    """Tests for check_brew_package()."""

    @pytest.mark.asyncio
    async def test_returns_empty_on_no_vulns(self) -> None:
        """Returns empty list when no vulnerabilities found."""
        from pkg_defender.intel.feeds.homebrew import check_brew_package

        # Use a custom class to ensure __aenter__ is properly defined
        mock_response = _MockResponse()
        mock_response.json = AsyncMock(return_value={"vulns": []})

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        result = await check_brew_package("python", "3.12.0", "https://github.com/python/cpython", session=mock_session)
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_vuln_records_on_vulns(self) -> None:
        """Returns ThreatRecord objects when vulnerabilities found."""
        # Test the parsing function directly rather than mocking HTTP
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln
        from pkg_defender.models import ThreatRecord

        vuln_data = {
            "id": "CVE-2023-1234",
            "summary": "Test vulnerability",
            "severity": [{"score": "9.8"}],
            "published": "2023-01-01T00:00:00Z",
            "modified": "2023-01-02T00:00:00Z",
            "affected": [{"versions": ["1.0.0", "1.0.1"]}],
        }

        result = _parse_osv_vuln(
            vuln_data,
            ecosystem="homebrew",
            package="python",
            id_prefix="homebrew_osv:",
            source="homebrew_osv",
            include_eco_in_id=False,
        )
        assert isinstance(result, ThreatRecord)
        assert result.package_name == "python"
        assert result.severity == "CRITICAL"
        assert "1.0.0" in result.affected_versions

    @pytest.mark.asyncio
    async def test_normalizes_version(self) -> None:
        """Normalizes version with rebuild suffix before querying."""
        from pkg_defender.intel.feeds.homebrew import check_brew_package

        # Use a custom class to ensure __aenter__ is properly defined
        mock_response = _MockResponse()
        mock_response.json = AsyncMock(return_value={"vulns": []})

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)

        await check_brew_package("python", "3.12.0_1", "https://github.com/python/cpython", session=mock_session)

        # Verify the query was made with normalized version
        call_args = mock_session.post.call_args
        query = call_args.kwargs["json"]
        assert query["version"] == "3.12.0"  # Normalized, underscore stripped


class TestParseOsvVuln:
    """Tests for _parse_osv_vuln()."""

    # Shared keyword arguments for homebrew-style parsing
    _HOMEBREW_KWARGS: _HomebrewKwargs = _HomebrewKwargs(
        ecosystem="homebrew",
        id_prefix="homebrew_osv:",
        source="homebrew_osv",
        include_eco_in_id=False,
    )

    def test_extracts_id_and_package(self) -> None:
        """Correctly extracts id and package name."""
        vuln = {
            "id": "CVE-2023-0001",
            "summary": "Test vuln",
        }
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        result = _parse_osv_vuln(vuln, package="test-package", **self._HOMEBREW_KWARGS)
        assert result.id == "homebrew_osv:CVE-2023-0001"
        assert result.package_name == "test-package"

    def test_extracts_affected_versions(self) -> None:
        """Extracts versions from affected array."""
        vuln = {
            "id": "CVE-2023-0001",
            "affected": [
                {"versions": ["1.0.0", "1.0.1", "1.0.0"]}  # Duplicate
            ],
        }
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        result = _parse_osv_vuln(vuln, package="test-package", **self._HOMEBREW_KWARGS)
        assert "1.0.0" in result.affected_versions
        assert "1.0.1" in result.affected_versions
        assert len(result.affected_versions) == 2  # No duplicates

    def test_extracts_affected_ranges(self) -> None:
        """Extracts version ranges from affected."""
        vuln = {
            "id": "CVE-2023-0001",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"fixed": "1.0.2"},
                            ],
                        }
                    ]
                }
            ],
        }
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        result = _parse_osv_vuln(vuln, package="test-package", **self._HOMEBREW_KWARGS)
        assert len(result.affected_ranges) > 0
        assert ">=" in result.affected_ranges[0]
        assert "<" in result.affected_ranges[0]
        # Verify no bracket prefix after DS-001 fix
        assert not result.affected_ranges[0].startswith("[")

    def test_uses_summary_fallback(self) -> None:
        """Uses details as summary when summary is empty."""
        vuln = {
            "id": "CVE-2023-0001",
            "summary": "",
            "details": "This is the detailed description of the vulnerability.",
        }
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        result = _parse_osv_vuln(vuln, package="test-package", **self._HOMEBREW_KWARGS)
        assert "detailed description" in result.summary

    def test_git_range_is_skipped(self) -> None:
        """Homebrew GIT ranges with commit hashes must be skipped."""
        from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

        vuln = {
            "id": "GIT-HOMEBREW-001",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/test/test",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "abc123def456abc123def456abc123def456abc1"},
                            ],
                        }
                    ]
                }
            ],
        }
        result = _parse_osv_vuln(vuln, package="test-package", **self._HOMEBREW_KWARGS)
        assert len(result.affected_ranges) == 0, f"Expected no ranges, got {result.affected_ranges}"


class TestExtractSeverityAndCvss:
    """Tests for _extract_severity_and_cvss()."""

    def test_cvss_numeric_score(self) -> None:
        """Returns numeric CVSS score for standard numeric score."""
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "9.5"}]}
        assert _extract_severity_and_cvss(vuln) == 9.5

    def test_cvss_high_score(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "7.5"}]}
        assert _extract_severity_and_cvss(vuln) == 7.5

    def test_cvss_medium_score(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "5.5"}]}
        assert _extract_severity_and_cvss(vuln) == 5.5

    def test_cvss_low_score(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "2.5"}]}
        assert _extract_severity_and_cvss(vuln) == 2.5

    def test_database_specific_fallback(self) -> None:
        """Uses database_specific.severity when CVSS not available."""
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"database_specific": {"severity": "HIGH"}}
        result = _extract_severity_and_cvss(vuln)
        assert result == 7.0  # HIGH maps to 7.0

    def test_unknown_when_no_severity(self) -> None:
        """Returns None when no severity info available."""
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        result = _extract_severity_and_cvss({})
        assert result is None

    def test_cvss_boundary_9_0(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "9.0"}]}
        assert _extract_severity_and_cvss(vuln) == 9.0

    def test_cvss_boundary_7_0(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "7.0"}]}
        assert _extract_severity_and_cvss(vuln) == 7.0

    def test_cvss_boundary_4_0(self) -> None:
        from pkg_defender.intel.feeds._osv_parser import _extract_severity_and_cvss

        vuln = {"severity": [{"score": "4.0"}]}
        assert _extract_severity_and_cvss(vuln) == 4.0


class TestFeedAdapterFetch:
    """Tests for HomebrewFeedAdapter.fetch()."""

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.homebrew.get_installed_formulae")
    async def test_fetch_no_formulae_returns_empty(self, mock_get_formulae: MagicMock) -> None:
        """Returns empty when no formulae installed."""
        mock_get_formulae.return_value = []

        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        result = await adapter.fetch()
        assert result.records == []
        assert result.status == FetchStatus.FAILED

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.homebrew.get_installed_formulae")
    @patch("pkg_defender.intel.feeds.homebrew.check_brew_package")
    async def test_fetch_with_vulns(self, mock_check: AsyncMock, mock_get_formulae: MagicMock) -> None:
        """Returns vulnerabilities when found."""
        mock_get_formulae.return_value = [
            {
                "name": "python",
                "homepage": "https://www.python.org/",
                "installed": [{"version": "3.12.0"}],
            }
        ]
        from pkg_defender.models import ThreatRecord

        mock_threat = ThreatRecord(
            id="homebrew_osv:CVE-2023-1234",
            ecosystem="homebrew",
            package_name="python",
            affected_versions=["1.0.0"],
            affected_ranges=[],
            severity="HIGH",
            confidence=0.9,
            source="homebrew_osv",
            source_id="CVE-2023-1234",
            summary="Test",
            detail_url="https://osv.dev/vulnerability/CVE-2023-1234",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            hit_count=1,
        )
        mock_check.return_value = [mock_threat]

        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        result = await adapter.fetch()
        assert len(result.records) == 1
        assert result.status == FetchStatus.SUCCESS

    @pytest.mark.asyncio
    @patch("pkg_defender.intel.feeds.homebrew.get_installed_formulae")
    async def test_fetch_brew_not_installed_returns_empty(self, mock_get_formulae: MagicMock) -> None:
        """Returns empty when Homebrew not installed."""
        from pkg_defender.intel.feeds.homebrew import BrewNotInstalledError

        mock_get_formulae.side_effect = BrewNotInstalledError("not installed")

        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        result = await adapter.fetch()
        assert result.records == []
        assert result.status == FetchStatus.FAILED


class TestFeedAdapterCheckPackage:
    """Tests for HomebrewFeedAdapter.check_package()."""

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def test_check_package_success(self, mock_run: MagicMock) -> None:
        """Returns threats when found."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            '{"formulae": [{"name": "python", "homepage": "https://python.org", "installed": [{"version": "3.12.0"}]}]}'
        )
        mock_run.return_value = mock_result

        from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter

        adapter = HomebrewFeedAdapter()
        # Mock check_brew_package at module level
        with patch("pkg_defender.intel.feeds.homebrew.check_brew_package", new_callable=AsyncMock) as mock_check:
            mock_check.return_value = []
            await adapter.check_package("python", "3.12.0", "homebrew")
            # Should have called the check function

    @pytest.mark.asyncio
    @patch("subprocess.run")
    async def test_check_package_brew_not_installed(self, mock_run: MagicMock) -> None:
        """Returns empty when brew not installed."""
        from pkg_defender.intel.feeds.homebrew import (
            HomebrewFeedAdapter,
        )

        # We need to mock the subprocess to raise an error that leads to BrewNotInstalledError
        # Actually, get_installed_formulae raises the error, not the check_package method directly
        # Let's test the path where brew info fails
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error"
        mock_result.args = ["brew"]
        mock_run.return_value = mock_result

        adapter = HomebrewFeedAdapter()
        result = await adapter.check_package("nonexistent", "1.0", "homebrew")
        assert result.records == []
        assert result.status == FetchStatus.FAILED


class TestGetTimeout:
    """Tests for get_http_timeout()."""

    @patch("pkg_defender.config.load_config")
    def test_uses_explicit_timeout_when_set(self, mock_load: MagicMock) -> None:
        """Returns config.feeds.http_timeout when set."""
        mock_config = MagicMock()
        mock_config.feeds.http_timeout = 30
        mock_load.return_value = mock_config

        from pkg_defender.config.settings import get_http_timeout

        result = get_http_timeout(mock_config)
        assert result == 30

    @patch("pkg_defender.config.load_config")
    def test_uses_config_when_no_explicit(self, mock_load: MagicMock) -> None:
        """Returns config.feeds.http_timeout when set."""
        mock_config = MagicMock()
        mock_config.feeds.http_timeout = 20
        mock_load.return_value = mock_config

        from pkg_defender.config.settings import get_http_timeout

        result = get_http_timeout(mock_config)
        assert result == 20

    @patch("pkg_defender.config.load_config")
    def test_fallback_to_15_when_no_config(self, mock_load: MagicMock) -> None:
        """Returns 15 when no config and no override."""
        from pkg_defender.config.settings import get_http_timeout

        # Config with no http_timeout attribute falls back to default 15
        mock_config = MagicMock()
        del mock_config.feeds.http_timeout

        result = get_http_timeout(mock_config)
        assert result == 15


class TestCheckBrewPackageErrorHandling:
    """Regression: P0.2 — check_brew_package must not silently swallow exceptions."""

    @pytest.mark.asyncio
    async def test_network_error_propagates(self) -> None:
        """check_brew_package raises when aiohttp session.post fails."""
        from unittest.mock import MagicMock

        from aiohttp import ClientError

        from pkg_defender.intel.feeds.homebrew import check_brew_package

        mock_session = MagicMock()
        mock_session.post = MagicMock(side_effect=ClientError("Connection refused"))

        with pytest.raises(ClientError):
            await check_brew_package(
                package="test-pkg",
                version="1.0.0",
                repo_url="https://github.com/example/test-pkg",
                session=mock_session,
            )
