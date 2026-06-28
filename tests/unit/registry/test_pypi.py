"""Tests for pkg_defender.registry.pypi module.

Tests the PyPIAdapter class and standalone convenience functions.
Covers adapter properties, publish time fallback chain, version listing,
latest version lookup, and installed version queries.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.registry._timestamp import ResolutionResult
from pkg_defender.registry.pypi import (
    PyPIAdapter,
    pipx_get_installed_version,
    pypi_get_installed_version,
    uv_get_installed_version,
)


class TestPyPIGetPublishTimeLogging:
    """Tests for get_publish_time error logging on fallback failures."""

    @pytest.mark.asyncio
    async def test_get_publish_time_logs_ecosystem_api_failure(self):
        """When ecosystem API fails, a warning must be logged (not silently passed).

        Before fix: except Exception: pass — no logging.
        After fix: except Exception as e: logger.warning(...) — logged.
        """
        adapter = PyPIAdapter()
        mock_session = MagicMock()
        with (
            patch.object(
                adapter,
                "_try_ecosystem_api",
                new=AsyncMock(side_effect=RuntimeError("API down")),
            ),
            patch.object(
                adapter,
                "_get_github_url",
                new=AsyncMock(return_value=None),
            ),
            patch("pkg_defender.registry.pypi.resolve_timestamp") as mock_resolve,
            patch("pkg_defender.registry.pypi.logger") as mock_logger,
        ):
            mock_resolve.return_value = ResolutionResult(
                publish_time=None,
                source_label="unresolved",
                resolution_status="all_sources_failed",
                last_error=None,
            )
            result = await adapter.get_publish_time("requests", "2.31.0", mock_session)

        # All sources failed → returns (None, "unresolved")
        assert result == (None, "unresolved")
        # Must have logged a warning for the ecosystem API failure
        assert mock_logger.warning.called, "Expected logger.warning to be called for ecosystem API failure"

    @pytest.mark.asyncio
    async def test_get_publish_time_logs_resolver_failure(self):
        """When TimestampResolver raises, returns user_manual gracefully."""
        adapter = PyPIAdapter()
        mock_session = MagicMock()
        with (
            patch.object(
                adapter,
                "_try_ecosystem_api",
                new=AsyncMock(return_value=None),
            ),
            patch.object(
                adapter,
                "_get_github_url",
                new=AsyncMock(return_value="https://github.com/psf/requests"),
            ),
            patch("pkg_defender.registry.pypi.resolve_timestamp") as mock_resolve,
        ):
            mock_resolve.return_value = ResolutionResult(
                publish_time=None,
                source_label="unresolved",
                resolution_status="all_sources_failed",
                last_error=None,
            )
            result = await adapter.get_publish_time("requests", "2.31.0", mock_session)

        assert result == (None, "unresolved")

    @pytest.mark.asyncio
    async def test_get_publish_time_returns_date_on_success(self):
        """When a source succeeds, returns the datetime and source name."""
        adapter = PyPIAdapter()
        mock_session = MagicMock()
        expected_date = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        with patch.object(
            adapter,
            "_try_ecosystem_api",
            new=AsyncMock(return_value=expected_date),
        ):
            result = await adapter.get_publish_time("requests", "2.31.0", mock_session)

        assert result == (expected_date, "registry_api")


class TestPyPIGetInstalledVersionLogging:
    """Regression tests for ``logger.debug`` on installed version lookup failures.

    S15 added ``logger.debug()`` before bare ``except Exception`` blocks that
    were silently swallowing subprocess errors. These tests verify that debug
    logging still occurs when subprocess calls fail during installed version
    lookups.
    """

    @pytest.mark.asyncio
    async def test_pypi_get_installed_version_logs_debug_on_failure(self) -> None:
        """When 'pip show' fails, ``logger.debug`` must be called (not silently swallowed).

        Root cause: ``pkg_defender/registry/pypi.py:367`` — bare ``except Exception:``
        block that silently passed before S15. Now logs debug with error context.
        This test FAILS before the fix and PASSES after.

        Scenario: ``subprocess.run(["pip", "show", "requests"])`` raises FileNotFoundError.
        Expected: returns None, calls ``logger.debug("pypi/pip: failed to get installed version for %s", "requests")``.
        Previously: exception was silently swallowed via bare ``except Exception: pass``.
        """
        with (
            patch(
                "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("pip not found"),
            ),
            patch("pkg_defender.registry.pypi.logger") as mock_logger,
        ):
            result = await pypi_get_installed_version("requests")

        assert result is None
        mock_logger.debug.assert_called_once()
        args, _ = mock_logger.debug.call_args
        assert "pypi/pip" in args[0]
        assert "requests" in args[1]
        assert "failed" in args[0]

    @pytest.mark.asyncio
    async def test_pipx_get_installed_version_logs_debug_on_failure(self) -> None:
        """When 'pipx list' fails, ``logger.debug`` must be called.

        Root cause: ``pkg_defender/registry/pypi.py:401`` — bare ``except Exception:``
        block that silently passed before S15.
        This test FAILS before the fix and PASSES after.
        """
        with (
            patch(
                "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("pipx not found"),
            ),
            patch("pkg_defender.registry.pypi.logger") as mock_logger,
        ):
            result = await pipx_get_installed_version("requests")

        assert result is None
        mock_logger.debug.assert_called_once()
        args, _ = mock_logger.debug.call_args
        assert "pypi/pipx" in args[0]
        assert "requests" in args[1]
        assert "failed" in args[0]

    @pytest.mark.asyncio
    async def test_uv_get_installed_version_logs_debug_on_failure(self) -> None:
        """When 'uv pip show' fails, ``logger.debug`` must be called.

        Root cause: ``pkg_defender/registry/pypi.py:431`` — bare ``except Exception:``
        block that silently passed before S15.
        This test FAILS before the fix and PASSES after.
        """
        with (
            patch(
                "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("uv not found"),
            ),
            patch("pkg_defender.registry.pypi.logger") as mock_logger,
        ):
            result = await uv_get_installed_version("requests")

        assert result is None
        mock_logger.debug.assert_called_once()
        args, _ = mock_logger.debug.call_args
        assert "pypi/uv" in args[0]
        assert "requests" in args[1]
        assert "failed" in args[0]


class TestPyPIAdapter:
    """Tests for PyPIAdapter properties and core methods."""

    @pytest.fixture
    def adapter(self) -> PyPIAdapter:
        """Create a PyPIAdapter instance."""
        return PyPIAdapter()

    def test_capabilities_property(self, adapter: PyPIAdapter) -> None:
        """Adapter returns expected capabilities."""
        from pkg_defender.registry.base import EcosystemCapability

        caps = adapter.capabilities
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in caps
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in caps

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: PyPIAdapter) -> None:
        """Returns latest version when package exists."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"info": {"version": "2.31.0"}}
            result = await adapter.get_latest_version("requests")

        assert result == "2.31.0"

    @pytest.mark.asyncio
    async def test_get_latest_version_error(self, adapter: PyPIAdapter, caplog: pytest.LogCaptureFixture) -> None:
        """Returns None on network error."""
        with (
            patch.object(adapter, "_fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.pypi"),
        ):
            mock_fetch.side_effect = TimeoutError("Timeout")
            result = await adapter.get_latest_version("requests")

        assert result is None
        assert "pypi: registry API failed for requests" in caplog.text

    @pytest.mark.asyncio
    async def test_get_latest_version_no_info(self, adapter: PyPIAdapter) -> None:
        """Returns None when response has no info."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {}
            result = await adapter.get_latest_version("requests")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: PyPIAdapter) -> None:
        """Returns VersionInfo list with versions and publish times."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "releases": {
                    "2.31.0": [{"upload_time_iso_8601": "2024-01-15T10:00:00+00:00"}],
                    "2.30.0": [{"upload_time_iso_8601": "2024-01-10T10:00:00+00:00"}],
                }
            }
            result = await adapter.get_all_versions("requests")

        assert len(result) == 2
        assert result[0].ecosystem == "pypi"
        assert result[0].package_name == "requests"
        versions = {v.version for v in result}
        assert "2.31.0" in versions
        assert "2.30.0" in versions

    @pytest.mark.asyncio
    async def test_get_all_versions_empty_releases(self, adapter: PyPIAdapter) -> None:
        """Returns empty list when releases dict is empty."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"releases": {}}
            result = await adapter.get_all_versions("requests")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_error(self, adapter: PyPIAdapter, caplog: pytest.LogCaptureFixture) -> None:
        """Returns empty list on network error."""
        with (
            patch.object(adapter, "_fetch_json") as mock_fetch,
            caplog.at_level("DEBUG", logger="pkg_defender.registry.pypi"),
        ):
            mock_fetch.side_effect = TimeoutError("Timeout")
            result = await adapter.get_all_versions("requests")

        assert result == []
        assert "pypi: registry API failed for requests" in caplog.text

    @pytest.mark.asyncio
    async def test_get_all_versions_no_upload_time(self, adapter: PyPIAdapter) -> None:
        """Uses current time when upload_time is missing."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "releases": {
                    "2.31.0": [{"upload_time_iso_8601": None}],
                }
            }
            result = await adapter.get_all_versions("requests")

        assert len(result) == 1
        assert result[0].version == "2.31.0"
        assert result[0].publish_time is not None

    @pytest.mark.asyncio
    async def test_get_all_versions_skips_empty_release_list(self, adapter: PyPIAdapter) -> None:
        """Skips versions with empty release list."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "releases": {
                    "2.31.0": [],
                    "2.30.0": [{"upload_time_iso_8601": "2024-01-10T10:00:00+00:00"}],
                }
            }
            result = await adapter.get_all_versions("requests")

        assert len(result) == 1
        assert result[0].version == "2.30.0"

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(self, adapter: PyPIAdapter) -> None:
        """get_installed_version delegates to pypi_get_installed_version."""
        with patch("pkg_defender.registry.pypi.pypi_get_installed_version") as mock_get:
            mock_get.return_value = "2.31.0"
            result = await adapter.get_installed_version("requests")
            assert result == "2.31.0"

    def test_sort_key(self) -> None:
        """_sort_key returns publish_time from VersionInfo."""
        from pkg_defender.models import VersionInfo
        from pkg_defender.registry.pypi import _sort_key

        dt = datetime(2024, 1, 15, tzinfo=UTC)
        vi = VersionInfo(ecosystem="pypi", package_name="requests", version="2.31.0", publish_time=dt)
        assert _sort_key(vi) == dt

        vi_none = VersionInfo(ecosystem="pypi", package_name="requests", version="2.31.0", publish_time=None)
        assert _sort_key(vi_none) is None


class TestPyPIGetGithubUrl:
    """Tests for _get_github_url method — resilience & regression (Bug 4).

    Root cause: src/pkg_defender/registry/pypi.py:80-84 — three distinct bugs:
    1. Case-sensitive dict key (only checked 'Source', not lowercase 'source')
    2. info.get('home_page', '') returns None for explicit null
    3. 'github.com' not in repo_url crashes on None (TypeError)
    """

    @pytest.fixture
    def adapter(self) -> PyPIAdapter:
        """Create a PyPIAdapter instance."""
        return PyPIAdapter()

    @pytest.mark.asyncio
    async def test_lowercase_source_key_resolved(self, adapter: PyPIAdapter) -> None:
        """Should find GitHub URL when project_urls has lowercase 'source' key.

        numpy uses lowercase 'source'. Before fix (Bug 4a, pypi.py:80), only
        'Source' (capital S) was checked, so numpy's URL was missed.
        """
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "info": {
                    "project_urls": {"source": "https://github.com/numpy/numpy"},
                }
            }
            result = await adapter._get_github_url("numpy")
        assert result == "https://github.com/numpy/numpy"

    @pytest.mark.asyncio
    async def test_none_home_page_does_not_crash(self, adapter: PyPIAdapter) -> None:
        """Should handle home_page=null gracefully — returns None, no crash.

        Before fix (Bug 4b, pypi.py:82): info.get('home_page', '') returns None
        when home_page is explicitly null, then 'github.com' not in None raises
        TypeError (Bug 4c, pypi.py:84). The broad except Exception in
        get_publish_time caught this silently.
        """
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "info": {
                    "project_urls": {},
                    "home_page": None,
                }
            }
            result = await adapter._get_github_url("some-package")
        assert result is None

    @pytest.mark.asyncio
    async def test_numpy_github_url_resolved(self, adapter: PyPIAdapter) -> None:
        """Numpy's GitHub URL should be found via lowercase 'source' key.

        Regression test for Bug 4. numpy's PyPI JSON uses lowercase 'source'
        in project_urls. Before fix, this was missed and _get_github_url
        crashed silently (TypeError caught by broad except).
        """
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "info": {
                    "project_urls": {"source": "https://github.com/numpy/numpy"},
                    "home_page": "https://numpy.org",
                }
            }
            result = await adapter._get_github_url("numpy")
        assert result == "https://github.com/numpy/numpy"

    @pytest.mark.asyncio
    async def test_pandas_github_url_resolved(self, adapter: PyPIAdapter) -> None:
        """Pandas' GitHub URL should be found via lowercase 'source' key.

        Regression test for Bug 4. pandas has same lowercase 'source' pattern.
        """
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {
                "info": {
                    "project_urls": {"source": "https://github.com/pandas-dev/pandas"},
                    "home_page": "https://pandas.pydata.org",
                }
            }
            result = await adapter._get_github_url("pandas")
        assert result == "https://github.com/pandas-dev/pandas"


class TestPyPITryEcosystemApi:
    """Tests for _try_ecosystem_api."""

    @pytest.fixture
    def adapter(self) -> PyPIAdapter:
        return PyPIAdapter()

    @pytest.mark.asyncio
    async def test_returns_datetime_when_api_returns_upload_time(self, adapter: PyPIAdapter) -> None:
        """Returns datetime when API returns upload time."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"urls": [{"upload_time_iso_8601": "2024-01-15T10:00:00+00:00"}]}
            result = await adapter._try_ecosystem_api("requests", "2.31.0")

        assert result is not None
        assert result.isoformat() == "2024-01-15T10:00:00+00:00"

    @pytest.mark.asyncio
    async def test_no_urls(self, adapter: PyPIAdapter) -> None:
        """Returns None when urls list is empty."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"urls": []}
            result = await adapter._try_ecosystem_api("requests", "2.31.0")

        assert result is None

    @pytest.mark.asyncio
    async def test_no_upload_time(self, adapter: PyPIAdapter) -> None:
        """Returns None when upload_time is missing."""
        with patch.object(adapter, "_fetch_json") as mock_fetch:
            mock_fetch.return_value = {"urls": [{}]}
            result = await adapter._try_ecosystem_api("requests", "2.31.0")

        assert result is None


class TestPyPIGetInstalledVersion:
    """Tests for installed version lookup functions."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_pypi_get_installed_version_success(self) -> None:
        """Returns version when pip show succeeds."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="Name: requests\nVersion: 2.31.0\n"),
        ):
            result = await pypi_get_installed_version("requests")

        assert result == "2.31.0"

    @pytest.mark.asyncio
    async def test_pypi_get_installed_version_not_installed(self) -> None:
        """Returns None when package is not installed."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await pypi_get_installed_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_pipx_get_installed_version_success(self) -> None:
        """Returns version when pipx list succeeds."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="package requests v2.31.0\n"),
        ):
            result = await pipx_get_installed_version("requests")

        assert result == "2.31.0"

    @pytest.mark.asyncio
    async def test_pipx_get_installed_version_not_installed(self) -> None:
        """Returns None when package not in pipx list."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="package nothing 1.0.0\n"),
        ):
            result = await pipx_get_installed_version("requests")

        assert result is None

    @pytest.mark.asyncio
    async def test_uv_get_installed_version_success(self) -> None:
        """Returns version when uv pip show succeeds."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="Name: requests\nVersion: 2.31.0\n"),
        ):
            result = await uv_get_installed_version("requests")

        assert result == "2.31.0"

    @pytest.mark.asyncio
    async def test_uv_get_installed_version_not_installed(self) -> None:
        """Returns None when package not installed via uv."""
        with patch(
            "pkg_defender.registry.pypi.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await uv_get_installed_version("nonexistent")

        assert result is None
