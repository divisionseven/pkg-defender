"""Tests for pkg_defender.registry.apt module.

Tests the APTAdapter class and standalone convenience functions.
Covers all public methods: get_publish_time, get_all_versions, get_latest_version.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.config.settings import INTEL_FEED_MAX_RETRIES
from pkg_defender.registry import apt
from pkg_defender.registry._timestamp import ResolutionResult


class TestAPTAdapter:
    """Tests for APTAdapter class."""

    @pytest.fixture
    def adapter(self) -> apt.APTAdapter:
        """Create an APTAdapter instance."""
        return apt.APTAdapter()

    def test_capabilities_property(self, adapter: apt.APTAdapter) -> None:
        """Returns capabilities including VERIFIED_PUBLISH_TIMESTAMPS."""
        from pkg_defender.registry.base import EcosystemCapability

        caps = adapter.capabilities
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS in caps
        assert EcosystemCapability.THREAT_INTEL_SUPPORT in caps

    @pytest.mark.asyncio
    async def test_get_latest_version_success(self, adapter: apt.APTAdapter) -> None:
        """Returns latest version when apt-cache policy succeeds."""
        with patch("pkg_defender.registry.apt._apt_get_latest_version") as mock_apt:
            mock_apt.return_value = "1.2.3-4ubuntu1"
            result = await adapter.get_latest_version("python3")

        assert result == "1.2.3-4ubuntu1"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self, adapter: apt.APTAdapter) -> None:
        """Returns None when package not found."""
        with patch("pkg_defender.registry.apt._apt_get_latest_version") as mock_apt:
            mock_apt.return_value = None
            result = await adapter.get_latest_version("nonexistent-package")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self, adapter: apt.APTAdapter) -> None:
        """Returns VersionInfo list with versions."""
        with patch("pkg_defender.registry.apt._apt_get_all_versions") as mock_versions:
            mock_versions.return_value = ["1.2.3-4ubuntu1", "1.2.2-3ubuntu1"]
            result = await adapter.get_all_versions("python3")

        assert len(result) == 2
        assert result[0].ecosystem == "apt"
        assert result[0].package_name == "python3"
        assert result[0].version == "1.2.3-4ubuntu1"
        assert result[1].version == "1.2.2-3ubuntu1"

    @pytest.mark.asyncio
    async def test_get_all_versions_empty(self, adapter: apt.APTAdapter) -> None:
        """Returns empty list when no versions found."""
        with patch("pkg_defender.registry.apt._apt_get_all_versions") as mock_versions:
            mock_versions.return_value = []
            result = await adapter.get_all_versions("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_publish_time_always_none(self, adapter: apt.APTAdapter) -> None:
        """APT doesn't expose publish times, always returns None."""
        result = await adapter.get_publish_time("python3", "1.2.3")

        assert result[0] is None
        assert result[1] == "no_github_url"

    @pytest.mark.asyncio
    async def test_get_publish_time_ecosystem_api_exception(self, adapter: apt.APTAdapter) -> None:
        """Catches exception from _try_ecosystem_api."""
        with patch.object(adapter, "_try_ecosystem_api", side_effect=RuntimeError("API error")):
            result = await adapter.get_publish_time("test-pkg", "1.0.0")

        assert result[0] is None
        assert result[1] == "no_github_url"

    @pytest.mark.asyncio
    async def test_get_publish_time_resolver_exception(self, adapter: apt.APTAdapter) -> None:
        """Catches exception from TimestampResolver, returns user_manual."""
        from unittest.mock import AsyncMock, patch

        with (
            patch.object(adapter, "_try_ecosystem_api", return_value=None),
            patch(
                "pkg_defender.registry.apt.resolve_timestamp",
                new_callable=AsyncMock,
                side_effect=RuntimeError("Resolver error"),
            ),
        ):
            result = await adapter.get_publish_time("test-pkg", "1.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"

    @pytest.mark.asyncio
    async def test_get_publish_time_resolver_success(self, adapter: apt.APTAdapter) -> None:
        """Returns result from TimestampResolver when it succeeds."""
        from datetime import datetime
        from unittest.mock import AsyncMock, patch

        with (
            patch.object(adapter, "_try_ecosystem_api", return_value=None),
            patch(
                "pkg_defender.registry.apt.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=datetime(2026, 3, 15),
                    source_label="libraries_io",
                    resolution_status="resolved",
                    last_error=None,
                ),
            ),
        ):
            result = await adapter.get_publish_time("test-pkg", "1.0.0", is_latest=True)

        assert result[0] is not None
        assert result[1] == "libraries_io"

    @pytest.mark.asyncio
    async def test_get_publish_time_registry_api_success(self, adapter: apt.APTAdapter) -> None:
        """Returns result from _try_ecosystem_api when it succeeds."""
        from datetime import datetime

        with patch.object(adapter, "_try_ecosystem_api", return_value=datetime(2026, 1, 15)):
            result = await adapter.get_publish_time("test-pkg", "1.0.0")

        assert result[0] is not None
        assert result[1] == "registry_api"

    @pytest.mark.asyncio
    async def test_get_publish_time_fallback_resolver_user_manual(self, adapter: apt.APTAdapter) -> None:
        """Returns user_manual when ecosystem API fails and resolver returns None."""
        from unittest.mock import AsyncMock, patch

        with (
            patch.object(adapter, "_try_ecosystem_api", return_value=None),
            patch(
                "pkg_defender.registry.apt.resolve_timestamp",
                new_callable=AsyncMock,
                return_value=ResolutionResult(
                    publish_time=None,
                    source_label="user_manual",
                    resolution_status="all_sources_failed",
                    last_error=None,
                ),
            ),
        ):
            result = await adapter.get_publish_time("test-pkg", "1.0.0")

        assert result[0] is None
        assert result[1] == "user_manual"

    @pytest.mark.asyncio
    async def test_get_installed_version(self, adapter: apt.APTAdapter) -> None:
        """get_installed_version delegates to apt_get_installed_version."""
        with patch("pkg_defender.registry.apt.apt_get_installed_version", new_callable=AsyncMock) as mock_apt:
            mock_apt.return_value = "7.88.1-1"
            result = await adapter.get_installed_version("curl")

        assert result == "7.88.1-1"


class TestRunAptCommand:
    """Tests for _run_apt_command helper function."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_run_apt_command_success(self) -> None:
        """Returns stdout on successful command."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="Candidate: 1.2.3-4ubuntu1"),
        ):
            result = await apt._run_apt_command(["apt-cache", "policy", "python3"])

        assert result == "Candidate: 1.2.3-4ubuntu1"

    @pytest.mark.asyncio
    async def test_run_apt_command_failure(self) -> None:
        """Returns None on non-zero return code."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(returncode=1),
        ):
            result = await apt._run_apt_command(["apt-cache", "policy", "nonexistent"])

        assert result is None

    @pytest.mark.asyncio
    async def test_run_apt_command_timeout(self) -> None:
        """Returns None on timeout after retries."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
        ) as mock_exec:
            mock_exec.side_effect = [
                self._mock_proc(stdout=""),
                self._mock_proc(stdout=""),
                self._mock_proc(stdout=""),
            ]

            # Mock asyncio.wait_for to raise TimeoutError
            async def _wait_for_always_timeout(coro: object, timeout: float | None = None) -> None:
                if asyncio.iscoroutine(coro):
                    coro.close()
                raise TimeoutError("timed out")

            with patch(
                "pkg_defender.registry.apt.asyncio.wait_for",
                side_effect=_wait_for_always_timeout,
            ):
                result = await apt._run_apt_command(["apt-cache", "policy", "python3"])

        assert result is None

    @pytest.mark.asyncio
    async def test_run_apt_command_not_found(self) -> None:
        """Returns None when apt-cache command not found."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("apt-cache not found"),
        ):
            result = await apt._run_apt_command(["apt-cache", "policy", "python3"])

        assert result is None

    @pytest.mark.asyncio
    async def test_run_apt_command_os_error(self) -> None:
        """Returns None on OS error after retries."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            side_effect=OSError("Permission denied"),
        ):
            result = await apt._run_apt_command(["apt-cache", "policy", "python3"])

        assert result is None

    @pytest.mark.asyncio
    async def test_run_apt_command_no_retries_fallthrough(self) -> None:
        """Returns None when max_retries=0."""
        with (
            patch("pkg_defender.registry.apt.get_max_retries", return_value=0),
        ):
            result = await apt._run_apt_command(["apt-cache", "policy", "python3"])

        assert result is None


class TestAptGetLatestVersion:
    """Tests for _apt_get_latest_version function."""

    @pytest.mark.asyncio
    async def test_get_latest_version_with_candidate(self) -> None:
        """Returns version from Candidate line."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Installed: (none)
  Candidate: 1.2.3-4ubuntu1
  Version table:
      1.2.3-4ubuntu1 500
"""
            result = await apt._apt_get_latest_version("python3")

        assert result == "1.2.3-4ubuntu1"

    @pytest.mark.asyncio
    async def test_get_latest_version_none_installed(self) -> None:
        """Returns version when nothing is installed."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Installed: (none)
  Candidate: 1.2.3-4ubuntu1
"""
            result = await apt._apt_get_latest_version("python3")

        assert result == "1.2.3-4ubuntu1"

    @pytest.mark.asyncio
    async def test_get_latest_version_already_installed(self) -> None:
        """Returns candidate version even when something is installed."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Installed: 1.0.0-1ubuntu1
  Candidate: 1.2.3-4ubuntu1
"""
            result = await apt._apt_get_latest_version("python3")

        assert result == "1.2.3-4ubuntu1"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self) -> None:
        """Returns None when package not found."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = None
            result = await apt._apt_get_latest_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_no_candidate(self) -> None:
        """Returns None when no candidate version available."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Installed: (none)
  Candidate: (none)
"""
            result = await apt._apt_get_latest_version("python3")

        assert result is None


class TestAptGetAllVersions:
    """Tests for _apt_get_all_versions function."""

    @pytest.mark.asyncio
    async def test_get_all_versions_success(self) -> None:
        """Returns versions from version table."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Installed: (none)
  Candidate: 1.2.3-4ubuntu1
  Version table:
      1.2.3-4ubuntu1 500
          http://archive.ubuntu.com/ubuntu jammy/main amd64 Packages
      1.2.2-3ubuntu1 100
          http://archive.ubuntu.com/ubuntu jammy/main amd64 Packages
"""
            result = await apt._apt_get_all_versions("python3")

        assert len(result) == 2
        assert "1.2.3-4ubuntu1" in result
        assert "1.2.2-3ubuntu1" in result

    @pytest.mark.asyncio
    async def test_get_all_versions_empty(self) -> None:
        """Returns empty list when no versions found."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = None
            result = await apt._apt_get_all_versions("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_deduplicates(self) -> None:
        """Deduplicates duplicate versions."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Version table:
      1.2.3-4ubuntu1 500
      1.2.3-4ubuntu1 500
"""
            result = await apt._apt_get_all_versions("python3")

        assert result.count("1.2.3-4ubuntu1") == 1

    @pytest.mark.asyncio
    async def test_get_all_versions_skips_empty_parts(self) -> None:
        """Skips lines with empty parts (branch 273->261)."""
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = """Package: python3
  Version table:
      version_with_no_dash 500
      1.2.3-4ubuntu1 500
"""
            result = await apt._apt_get_all_versions("python3")

        # "version_with_no_dash" has no "-" so it's skipped
        assert result == ["1.2.3-4ubuntu1"]


class TestConstants:
    """Tests for module-level constants."""

    def test_timeout_seconds_constant(self) -> None:
        """TIMEOUT_SECONDS is set to 30."""
        assert apt.TIMEOUT_SECONDS == 30

    def test_max_retries_constant(self) -> None:
        """INTEL_FEED_MAX_RETRIES is set to 3."""
        assert INTEL_FEED_MAX_RETRIES == 3


class TestAPTPublishTimeWarning:
    """Regression tests for Gap 6: APT publish time warnings."""

    def test_apt_get_publish_time_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """Regression: APT get_publish_time must emit log warning when fileinfo is empty."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache to ensure warning is emitted
        apt._warned_apt_packages.clear()

        import asyncio

        # Mock successful API response with empty fileinfo (triggers warning)
        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_fetch:
            mock_fetch.return_value = {"fileinfo": {}}

            adapter = apt.APTAdapter()
            result = asyncio.run(adapter.get_publish_time("nonexistent-package-xyz-123", "1.0.0"))

        assert result[0] is None
        assert result[1] == "no_github_url"
        assert any("APT does not expose" in record.message for record in caplog.records)

    def test_apt_adapter_get_publish_time_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """Regression: APTAdapter.get_publish_time emits log warning when fileinfo is empty."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache to ensure warning is emitted
        apt._warned_apt_packages.clear()

        adapter = apt.APTAdapter()

        # Mock successful API response with empty fileinfo (triggers warning)
        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_fetch:
            mock_fetch.return_value = {"fileinfo": {}}

            import asyncio

            result = asyncio.run(adapter.get_publish_time("test-package-abc", "2.0.0"))

        assert result[0] is None
        assert result[1] == "no_github_url"
        assert any("APT does not expose" in record.message for record in caplog.records)

    def test_apt_warning_only_emits_once_per_package(self, caplog: pytest.LogCaptureFixture) -> None:
        """Warning should only be emitted once per package to avoid spam."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache
        apt._warned_apt_packages.clear()

        import asyncio

        # Mock successful API response with empty fileinfo
        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_fetch:
            mock_fetch.return_value = {"fileinfo": {}}

            adapter = apt.APTAdapter()
            for _ in range(3):
                asyncio.run(adapter.get_publish_time("same-package", "1.0.0"))

        # Should only have one warning for the same package
        apt_warnings = [r for r in caplog.records if "APT does not expose" in r.message]
        assert len(apt_warnings) == 1

    def test_apt_warning_different_packages(self, caplog: pytest.LogCaptureFixture) -> None:
        """Warning should be emitted for different packages."""
        caplog.set_level(logging.WARNING)

        # Clear the warning cache
        apt._warned_apt_packages.clear()

        import asyncio

        # Mock successful API response with empty fileinfo
        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_fetch:
            mock_fetch.return_value = {"fileinfo": {}}

            adapter = apt.APTAdapter()
            asyncio.run(adapter.get_publish_time("package-a", "1.0.0"))
            asyncio.run(adapter.get_publish_time("package-b", "1.0.0"))

        # Should have two warnings for different packages
        apt_warnings = [r for r in caplog.records if "APT does not expose" in r.message]
        assert len(apt_warnings) == 2


class TestSnapshotFetch:
    """Tests for _snapshot_fetch and _get_publish_time_snapshot functions."""

    def test_snapshot_fetch_error_path(self) -> None:
        """_snapshot_fetch raises RuntimeError when fetch fails."""
        mock_result = MagicMock(success=False, data=None, error="Not found")
        with patch("pkg_defender._http.fetch_json", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_result
            with pytest.raises(RuntimeError, match="Failed to fetch"):
                import asyncio

                asyncio.run(apt._snapshot_fetch("https://test.url/"))

    def test_snapshot_fetch_success_path(self) -> None:
        """_snapshot_fetch returns dict when fetch succeeds."""
        import asyncio

        mock_result = MagicMock(success=True, data={"fileinfo": {"key": "val"}})
        with patch("pkg_defender._http.fetch_json", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_result
            result = asyncio.run(apt._snapshot_fetch("https://test.url/"))

        assert result == {"fileinfo": {"key": "val"}}

    def test_get_publish_time_snapshot_parses_fileinfo(self) -> None:
        """Parses fileinfo with valid first_seen timestamp."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {
                "fileinfo": {
                    "sha256hash1": [
                        {"first_seen": "20221015T220129Z", "archive_name": "debian"},
                    ]
                }
            }
            result = asyncio.run(apt._get_publish_time_snapshot("curl", "7.88.1-1"))

        assert result is not None
        assert result.year == 2022
        assert result.month == 10
        assert result.day == 15

    def test_get_publish_time_snapshot_empty_fileinfo(self) -> None:
        """Returns None when fileinfo is empty (warning path)."""
        import asyncio

        apt._warned_apt_packages.clear()
        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": {}}
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

    def test_get_publish_time_snapshot_no_fileinfo_key(self) -> None:
        """Returns None when fileinfo key is missing."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": None}  # fileinfo is None
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {}  # no fileinfo key
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

    def test_get_publish_time_snapshot_empty_entries(self) -> None:
        """Returns None when fileinfo entries list is empty."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": {"sha256hash1": []}}
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

    def test_get_publish_time_snapshot_no_first_seen(self) -> None:
        """Returns None when entry has no first_seen."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": {"sha256hash1": [{"archive_name": "debian"}]}}
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

    def test_get_publish_time_snapshot_bad_date_format(self) -> None:
        """Returns None when first_seen has unparseable format."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": {"sha256hash1": [{"first_seen": "not-a-date"}]}}
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None

    def test_get_publish_time_snapshot_fetch_raises(self) -> None:
        """Returns None when _snapshot_fetch raises TransportError."""
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.side_effect = TimeoutError("timeout")
            result = asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

        assert result is None


class TestSnapshotUrl:
    """Regression tests for APT snapshot URL containing /binfiles (Bug 1).

    Root cause: src/pkg_defender/registry/apt.py:84 — the URL was missing
    the /binfiles path segment. All 172+ HTTP interactions were mocked with
    aioresponses matching the *wrong* URL, so all tests passed.
    This test FAILS before the fix and PASSES after.
    """

    def test_snapshot_url_includes_binfiles(self) -> None:
        """URL passed to _snapshot_fetch must include /binfiles path segment.

        Before fix: /mr/binary/{pkg}/{ver}/?fileinfo=1 (missing /binfiles)
        After fix:  /mr/binary/{pkg}/{ver}/binfiles?fileinfo=1
        """
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {"fileinfo": {}}
            asyncio.run(apt._get_publish_time_snapshot("test-pkg", "1.0.0"))

            call_url: str = mock_snap.call_args[0][0]
            assert "/binfiles" in call_url, f"Snapshot URL missing /binfiles: {call_url}"
            assert call_url.endswith("?fileinfo=1") or "?fileinfo=1" in call_url

    def test_get_publish_time_snapshot_returns_datetime_for_valid_data(
        self,
    ) -> None:
        """When snapshot returns valid fileinfo, returns a datetime (not None).

        Regression test: the wrong URL caused every production call to 404,
        making _get_publish_time_snapshot always return None.
        """
        import asyncio

        with patch("pkg_defender.registry.apt._snapshot_fetch") as mock_snap:
            mock_snap.return_value = {
                "fileinfo": {
                    "sha256hash1": [
                        {"first_seen": "20221015T220129Z", "archive_name": "debian"},
                    ]
                }
            }
            result = asyncio.run(apt._get_publish_time_snapshot("curl", "7.88.1-1"))

        assert result is not None
        assert isinstance(result, datetime)
        assert result.year == 2022
        assert result.month == 10
        assert result.day == 15


class TestAPTGetInstalledVersion:
    """Tests for apt_get_installed_version."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> AsyncMock:
        proc = AsyncMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate.return_value = (stdout.encode(), b"")
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_package_installed(self) -> None:
        """Returns version when package is installed."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="7.88.1-1"),
        ):
            result = await apt.apt_get_installed_version("curl")
        assert result == "7.88.1-1"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout=""),
        ):
            result = await apt.apt_get_installed_version("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.apt.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("apt not found"),
        ):
            result = await apt.apt_get_installed_version("curl")
        assert result is None


class TestAPTGetLatestVersion:
    """Tests for APTAdapter.get_latest_version."""

    @pytest.mark.asyncio
    async def test_returns_latest_version_when_available(self) -> None:
        """Returns latest version when available."""
        adapter = apt.APTAdapter()
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = "Package: curl\n  Candidate: 2.0.0\n"
            result = await adapter.get_latest_version("curl")
        assert result == "2.0.0"

    @pytest.mark.asyncio
    async def test_empty_result(self) -> None:
        """Returns None when apt command returns nothing."""
        adapter = apt.APTAdapter()
        with patch(
            "pkg_defender.registry.apt._run_apt_command",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = None
            result = await adapter.get_latest_version("curl")
        assert result is None
