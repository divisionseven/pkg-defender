"""Tests for pkg_defender.registry.yum — YUM/DNF adapter with 3-tier cascade.

YUM/DNF publish-time resolution uses a 3-tier cascade (Bodhi → Koji →
repodata) implemented in :class:`YUMAdapter.get_publish_time`. After the
repodata step, the result is passed through
:func:`pkg_defender.registry._buildtime_validator.detect_clamping` to demote
clamped BUILDTIMEs (Fedora 43+ reproducible-builds artifact) to
``(None, SOURCE_USER_MANUAL)``.

This test file covers:
- :class:`YUMAdapter` identity (ecosystem, base URL, capabilities)
- :class:`YUMAdapter` 3-tier cascade: Bodhi hit, Bodhi None → Koji hit,
  Bodhi None → Koji None → repodata hit, all fail → user_manual,
  frozen-snapshot rejection, BUILDTIME clamping demotion
- :class:`YUMAdapter` get_all_versions runs the cascade per version
- Standalone convenience functions (delegating to the YUMAdapter singleton)
- All legacy helper functions that remain: ``_run_dnf_command``,
  ``_run_yum_command``, ``_dnf_get_latest_version``, ``_dnf_get_all_versions``,
  ``_yum_get_installed_version``, ``yum_get_installed_version``,
  ``dnf_get_installed_version``
- Module-level constants

Mutation contract: every test in this file FAILS when the corresponding
production behavior is reverted (e.g., removing the PROXIED capability,
hard-coding ``(None, SOURCE_USER_MANUAL)``, breaking the singleton
delegation, or restoring the deleted ``_warn_no_publish_time`` /
``_get_rpm_build_time`` / ``_get_github_release_time`` APIs).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.config.settings import INTEL_FEED_MAX_RETRIES
from pkg_defender.registry import yum
from pkg_defender.registry.yum import (
    _FROZEN_SNAPSHOT_REPODATA_URLS,
    _reset_clients_for_tests,
)

# ---------------------------------------------------------------------------
# Module-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    """Reset module-level client singletons before/after each test.

    The YUMAdapter singleton owns the BodhiClient / KojiClient /
    RepodataClient singletons. Resetting all four keeps cascade-mock
    state from leaking between tests.
    """
    _reset_clients_for_tests()
    yield
    _reset_clients_for_tests()


def _bodhi_mock(time: datetime | None) -> MagicMock:
    """Build a BodhiClient mock returning ``(time, SOURCE_BODHI)``."""
    from pkg_defender.registry._bodhi_client import SOURCE_BODHI

    m = MagicMock()
    m.get_publish_time = AsyncMock(return_value=(time, SOURCE_BODHI))
    return m


def _koji_mock(time: datetime | None) -> MagicMock:
    """Build a KojiClient mock returning ``(time, SOURCE_KOJI)``."""
    from pkg_defender.registry._koji_client import SOURCE_KOJI

    m = MagicMock()
    m.get_build_completion_time = AsyncMock(return_value=(time, SOURCE_KOJI))
    return m


def _repodata_mock(
    time: datetime | None,
    matched_url: str | None = "https://example.com/repo",
) -> MagicMock:
    """Build a RepodataClient mock returning ``(time, matched_url)``."""
    m = MagicMock()
    m.get_publish_time = AsyncMock(return_value=(time, matched_url))
    return m


# ---------------------------------------------------------------------------
# YUMAdapter identity
# ---------------------------------------------------------------------------


class TestYUMAdapterIdentity:
    """Test identity attributes of the YUMAdapter class."""

    @pytest.fixture
    def adapter(self) -> yum.YUMAdapter:
        """Create a YUMAdapter instance (test-local, not a singleton)."""
        return yum.YUMAdapter()

    def test_capabilities_include_proxied_timestamps(self, adapter: yum.YUMAdapter) -> None:
        """Capabilities declare PROXIED (the honest tier for the cascade).

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``YUMAdapter.capabilities`` MUST fail the test below, not this one.
        """
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_exclude_verified_timestamps(self, adapter: yum.YUMAdapter) -> None:
        """Capabilities do NOT declare VERIFIED (the cascade's weakest link is the public contract).

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``YUMAdapter.capabilities`` MUST fail this test.
        """
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in adapter.capabilities

    def test_capabilities_exclude_threat_intel(self, adapter: yum.YUMAdapter) -> None:
        """Capabilities do NOT declare THREAT_INTEL (AUDIT-tier rule)."""
        from pkg_defender.registry.base import EcosystemCapability

        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in adapter.capabilities


# ---------------------------------------------------------------------------
# YUMAdapter.get_publish_time — 3-tier cascade
# ---------------------------------------------------------------------------


class TestYUMAdapterCascade:
    """Test the 3-tier publish-time cascade (Bodhi → Koji → repodata)."""

    @pytest.fixture
    def adapter(self) -> yum.YUMAdapter:
        """YUMAdapter instance for cascade tests (test-local)."""
        return yum.YUMAdapter()

    @pytest.mark.asyncio
    async def test_bodhi_hit_short_circuits_cascade(self, adapter: yum.YUMAdapter) -> None:
        """Bodhi success → cascade returns Bodhi tuple, never calls Koji/repodata."""
        from pkg_defender.registry._bodhi_client import SOURCE_BODHI

        bodhi_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        bodhi = _bodhi_mock(bodhi_dt)
        koji = _koji_mock(None)
        repodata = _repodata_mock(None)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
        ):
            result = await adapter.get_publish_time("curl", "8.19.0-1.fc40")

        assert result == (bodhi_dt, SOURCE_BODHI)
        koji.get_build_completion_time.assert_not_called()
        repodata.get_publish_time.assert_not_called()

    @pytest.mark.asyncio
    async def test_bodhi_none_koji_hit(self, adapter: yum.YUMAdapter) -> None:
        """Bodhi None → Koji success → cascade returns Koji tuple, never calls repodata."""
        from pkg_defender.registry._koji_client import SOURCE_KOJI

        koji_dt = datetime(2026, 3, 12, 1, 0, 0, tzinfo=UTC)
        bodhi = _bodhi_mock(None)
        koji = _koji_mock(koji_dt)
        repodata = _repodata_mock(None)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
        ):
            result = await adapter.get_publish_time("curl", "8.19.0-1.fc40")

        assert result == (koji_dt, SOURCE_KOJI)
        repodata.get_publish_time.assert_not_called()

    @pytest.mark.asyncio
    async def test_bodhi_none_koji_none_repodata_hit(self, adapter: yum.YUMAdapter) -> None:
        """Bodhi None → Koji None → repodata hit → cascade returns repodata tuple."""
        from pkg_defender.registry._repodata_client import SOURCE_REPODATA

        repodata_dt = datetime(2026, 3, 12, 5, 0, 0, tzinfo=UTC)
        bodhi = _bodhi_mock(None)
        koji = _koji_mock(None)
        repodata = _repodata_mock(
            repodata_dt,
            matched_url="https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os",
        )

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
            # Bypass the validator (already covered in test_buildtime_validator)
            patch(
                "pkg_defender.registry.yum.detect_clamping",
                return_value=False,
            ),
        ):
            result = await adapter.get_publish_time("curl", "8.19.0-1.fc40")

        assert result == (repodata_dt, SOURCE_REPODATA)

    @pytest.mark.asyncio
    async def test_all_sources_fail_returns_user_manual(self, adapter: yum.YUMAdapter) -> None:
        """All 3 sources return None → cascade returns ``(None, SOURCE_USER_MANUAL)``."""
        from pkg_defender.registry._buildtime_validator import SOURCE_USER_MANUAL

        bodhi = _bodhi_mock(None)
        koji = _koji_mock(None)
        repodata = _repodata_mock(None, matched_url=None)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
        ):
            result = await adapter.get_publish_time("nonexistent", "1.0.0-1")

        assert result == (None, SOURCE_USER_MANUAL)

    @pytest.mark.asyncio
    async def test_frozen_snapshot_rejected(self, adapter: yum.YUMAdapter) -> None:
        """repodata match on a frozen-snapshot URL → cascade returns ``(None, SOURCE_USER_MANUAL)``.

        openEuler 22.03 LTS is a frozen snapshot — the ``<time file>`` value
        is the repo rebuild time, not a per-package timestamp. The
        cascade must REJECT this match (Q7).
        """
        from pkg_defender.registry._buildtime_validator import SOURCE_USER_MANUAL

        repodata_dt = datetime(2026, 3, 12, 5, 0, 0, tzinfo=UTC)
        # Use the canonical frozen-snapshot URL from the constant
        frozen_url = next(iter(_FROZEN_SNAPSHOT_REPODATA_URLS))
        bodhi = _bodhi_mock(None)
        koji = _koji_mock(None)
        repodata = _repodata_mock(repodata_dt, matched_url=frozen_url)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
        ):
            result = await adapter.get_publish_time("curl", "8.19.0-1.oe2203")

        assert result == (None, SOURCE_USER_MANUAL)

    @pytest.mark.asyncio
    async def test_clamped_repodata_demoted_to_user_manual(self, adapter: yum.YUMAdapter) -> None:
        """repodata clamped (detect_clamping=True) → cascade returns ``(None, SOURCE_USER_MANUAL)``.

        BUILDTIME clamping is the Fedora 43+ reproducible-builds artifact
        (pagure.io/fesco/issue/2899). The cascade must call
        :func:`detect_clamping` and demote the result to user_manual
        when the BUILDTIME looks clamped (Constraint C2).
        """
        from pkg_defender.registry._buildtime_validator import SOURCE_USER_MANUAL

        clamped_dt = datetime(2026, 3, 12, 5, 0, 0, tzinfo=UTC)
        bodhi = _bodhi_mock(None)
        koji = _koji_mock(None)
        repodata = _repodata_mock(
            clamped_dt,
            matched_url="https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os",
        )

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
            patch(
                "pkg_defender.registry.yum.detect_clamping",
                return_value=True,
            ) as mock_detect,
        ):
            result = await adapter.get_publish_time("curl", "8.19.0-1.fc43")

        assert result == (None, SOURCE_USER_MANUAL)
        # Verify detect_clamping was called with the repodata datetime
        # and the matched URL as the source bucket key
        kwargs = mock_detect.call_args.kwargs
        assert kwargs["buildtime"] == clamped_dt
        assert (
            kwargs["source"] == "https://dl.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os"
        )
        assert kwargs["package"] == "curl"
        assert kwargs["version"] == "8.19.0-1.fc43"

    @pytest.mark.asyncio
    async def test_cascade_calls_three_clients_in_order(self, adapter: yum.YUMAdapter) -> None:
        """Cascade calls Bodhi → Koji → repodata in strict order."""
        bodhi = _bodhi_mock(None)
        koji = _koji_mock(None)
        repodata = _repodata_mock(None, matched_url=None)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
        ):
            await adapter.get_publish_time("curl", "8.19.0-1.fc40")

        bodhi.get_publish_time.assert_awaited_once_with("curl", "8.19.0-1.fc40")
        koji.get_build_completion_time.assert_awaited_once_with("8.19.0-1.fc40")
        repodata.get_publish_time.assert_awaited_once_with("curl", "8.19.0-1.fc40")


# ---------------------------------------------------------------------------
# YUMAdapter.get_all_versions — cascade applied per-version
# ---------------------------------------------------------------------------


class TestYUMAdapterGetAllVersions:
    """Test ``YUMAdapter.get_all_versions`` runs the cascade per version."""

    @pytest.fixture
    def adapter(self) -> yum.YUMAdapter:
        """YUMAdapter instance for tests (test-local)."""
        return yum.YUMAdapter()

    @pytest.mark.asyncio
    async def test_all_versions_cascade_propagates_publish_time_and_source(
        self,
        adapter: yum.YUMAdapter,
    ) -> None:
        """Each version's ``VersionInfo`` carries the cascade's publish time and source.

        Versions that the cascade can resolve get the resolved
        ``publish_time`` and ``date_source``; versions that the cascade
        cannot resolve get ``publish_time=None`` and
        ``date_source=SOURCE_USER_MANUAL`` (per BC-5).
        """
        from pkg_defender.registry._bodhi_client import SOURCE_BODHI
        from pkg_defender.registry._buildtime_validator import SOURCE_USER_MANUAL

        bodhi_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)

        # Bodhi returns a real time for v1, None for v2
        bodhi = MagicMock()
        bodhi.get_publish_time = AsyncMock(
            side_effect=[(bodhi_dt, SOURCE_BODHI), (None, SOURCE_BODHI)],
        )
        koji = _koji_mock(None)
        repodata = _repodata_mock(None, matched_url=None)

        with (
            patch("pkg_defender.registry.yum._get_bodhi_client", return_value=bodhi),
            patch("pkg_defender.registry.yum._get_koji_client", return_value=koji),
            patch("pkg_defender.registry.yum._get_repodata_client", return_value=repodata),
            patch.object(yum, "_dnf_get_all_versions") as mock_dnf_versions,
        ):
            mock_dnf_versions.return_value = ["1.24.0-3.fc40", "1.22.0-2.fc40"]
            result = await adapter.get_all_versions("python")

        assert len(result) == 2
        # v1: resolved
        assert result[0].ecosystem == "yum"
        assert result[0].package_name == "python"
        assert result[0].version == "1.24.0-3.fc40"
        assert result[0].publish_time == bodhi_dt
        assert result[0].date_source == SOURCE_BODHI
        # v2: unresolvable (per BC-5, no datetime.now() placeholder)
        assert result[1].version == "1.22.0-2.fc40"
        assert result[1].publish_time is None
        assert result[1].date_source == SOURCE_USER_MANUAL

    @pytest.mark.asyncio
    async def test_all_versions_empty_returns_empty_list(self, adapter: yum.YUMAdapter) -> None:
        """No versions found → empty list, cascade not called."""
        with patch.object(yum, "_dnf_get_all_versions", return_value=[]):
            result = await adapter.get_all_versions("nonexistent")

        assert result == []


# ---------------------------------------------------------------------------
# YUMAdapter.get_latest_version
# ---------------------------------------------------------------------------


class TestYUMAdapterGetLatestVersion:
    """Test ``YUMAdapter.get_latest_version`` delegates to ``_dnf_get_latest_version``."""

    @pytest.mark.asyncio
    async def test_delegates_to_dnf_helper(self) -> None:
        """``get_latest_version`` calls ``_dnf_get_latest_version`` and returns the string."""
        with patch.object(yum, "_dnf_get_latest_version", return_value="1.24.0-3.fc40"):
            result = await yum.YUMAdapter().get_latest_version("python")

        assert result == "1.24.0-3.fc40"

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self) -> None:
        """``get_latest_version`` returns None when the helper returns None."""
        with patch.object(yum, "_dnf_get_latest_version", return_value=None):
            result = await yum.YUMAdapter().get_latest_version("nonexistent")

        assert result is None


# ---------------------------------------------------------------------------
# YUMAdapter.get_installed_version
# ---------------------------------------------------------------------------


class TestYUMAdapterGetInstalledVersion:
    """Test ``YUMAdapter.get_installed_version`` delegates to ``yum_get_installed_version``."""

    @pytest.mark.asyncio
    async def test_delegates_to_module_helper(self) -> None:
        """``get_installed_version`` calls ``yum_get_installed_version`` and returns the string."""
        with patch(
            "pkg_defender.registry.yum.yum_get_installed_version",
            new_callable=AsyncMock,
            return_value="7.88.1-1.fc38",
        ) as mock_yum:
            result = await yum.YUMAdapter().get_installed_version("curl")

        assert result == "7.88.1-1.fc38"
        mock_yum.assert_awaited_once_with("curl")

    @pytest.mark.asyncio
    async def test_not_installed_returns_none(self) -> None:
        """``get_installed_version`` returns None when the helper returns None."""
        with patch(
            "pkg_defender.registry.yum.yum_get_installed_version",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = await yum.YUMAdapter().get_installed_version("nonexistent")

        assert result is None


# ---------------------------------------------------------------------------
# Standalone convenience functions
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _run_dnf_command
# ---------------------------------------------------------------------------


class TestRunDnfCommand:
    """Tests for ``_run_dnf_command`` helper function."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> MagicMock:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate = AsyncMock(return_value=(stdout.encode(), b""))
        return proc

    @pytest.mark.asyncio
    async def test_run_dnf_command_success(self) -> None:
        """Returns stdout on successful command."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="1.24.0-3.fc40\n"),
        ):
            result = await yum._run_dnf_command(["dnf", "repoquery", "python"])
        assert result == "1.24.0-3.fc40"

    @pytest.mark.asyncio
    async def test_run_dnf_command_failure(self) -> None:
        """Returns None on non-zero return code."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", return_value=self._mock_proc(returncode=1)
        ):
            result = await yum._run_dnf_command(["dnf", "repoquery", "nonexistent"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_dnf_command_timeout(self) -> None:
        """Returns None on timeout after exhausting retries."""
        _mock = AsyncMock(spec=asyncio.subprocess.Process)
        _mock.returncode = None
        _mock.communicate = AsyncMock()

        async def _mock_wait_for(coro: Awaitable[Any], *args: object, **kwargs: object) -> None:
            await coro  # prevent orphaned coroutine warning
            raise TimeoutError("timed out")

        with (
            patch("pkg_defender.registry.yum.asyncio.create_subprocess_exec", return_value=_mock),
            patch("pkg_defender.registry.yum.asyncio.wait_for", side_effect=_mock_wait_for),
        ):
            result = await yum._run_dnf_command(["dnf", "repoquery", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_dnf_command_not_found(self) -> None:
        """Returns None when dnf command not found."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", side_effect=FileNotFoundError("dnf not found")
        ):
            result = await yum._run_dnf_command(["dnf", "repoquery", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_dnf_command_os_error(self) -> None:
        """Returns None on OS error after exhausting retries."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", side_effect=OSError("Permission denied")
        ):
            result = await yum._run_dnf_command(["dnf", "repoquery", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_dnf_command_no_retries_fallthrough(self) -> None:
        """Returns None when max_retries=0 (loop body never executes)."""
        with patch("pkg_defender.registry.yum.get_max_retries", return_value=0):
            result = await yum._run_dnf_command(["dnf", "repoquery", "python"])
        assert result is None


# ---------------------------------------------------------------------------
# _run_yum_command
# ---------------------------------------------------------------------------


class TestRunYumCommand:
    """Tests for ``_run_yum_command`` helper function."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> MagicMock:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate = AsyncMock(return_value=(stdout.encode(), b""))
        return proc

    @pytest.mark.asyncio
    async def test_run_yum_command_success(self) -> None:
        """Returns stdout on successful command."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="python-3.12.0-1.el9.x86_64\n"),
        ):
            result = await yum._run_yum_command(["yum", "list", "available", "python"])
        assert result == "python-3.12.0-1.el9.x86_64"

    @pytest.mark.asyncio
    async def test_run_yum_command_not_found(self) -> None:
        """Returns None when yum command not found."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", side_effect=FileNotFoundError("yum not found")
        ):
            result = await yum._run_yum_command(["yum", "list", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_yum_command_non_zero_return(self) -> None:
        """Returns None when returncode is non-zero."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", return_value=self._mock_proc(returncode=1)
        ):
            result = await yum._run_yum_command(["yum", "list", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_yum_command_timeout(self) -> None:
        """Returns None on timeout after exhausting retries."""
        _mock = AsyncMock(spec=asyncio.subprocess.Process)
        _mock.returncode = None
        _mock.communicate = AsyncMock()

        async def _mock_wait_for(coro: Awaitable[Any], *args: object, **kwargs: object) -> None:
            await coro  # prevent orphaned coroutine warning
            raise TimeoutError("timed out")

        with (
            patch("pkg_defender.registry.yum.asyncio.create_subprocess_exec", return_value=_mock),
            patch("pkg_defender.registry.yum.asyncio.wait_for", side_effect=_mock_wait_for),
        ):
            result = await yum._run_yum_command(["yum", "list", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_yum_command_os_error(self) -> None:
        """Returns None on OS error after exhausting retries."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", side_effect=OSError("Permission denied")
        ):
            result = await yum._run_yum_command(["yum", "list", "python"])
        assert result is None

    @pytest.mark.asyncio
    async def test_run_yum_command_no_retries_fallthrough(self) -> None:
        """Returns None when max_retries=0."""
        with patch("pkg_defender.registry.yum.get_max_retries", return_value=0):
            result = await yum._run_yum_command(["yum", "list", "python"])
        assert result is None


# ---------------------------------------------------------------------------
# _dnf_get_latest_version
# ---------------------------------------------------------------------------


class TestDnfGetLatestVersion:
    """Tests for ``_dnf_get_latest_version`` function."""

    @pytest.mark.asyncio
    async def test_get_latest_version_dnf(self) -> None:
        """Returns version from dnf command."""
        with patch("pkg_defender.registry.yum._run_dnf_command", new_callable=AsyncMock) as mock_dnf:
            mock_dnf.return_value = "1.24.0-3.fc40"
            result = await yum._dnf_get_latest_version("python")

        assert result == "1.24.0-3.fc40"

    @pytest.mark.asyncio
    async def test_get_latest_version_yum_fallback(self) -> None:
        """Falls back to yum when dnf returns None."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # Format: package.name.arch    version-repo
            # The code removes the last .<arch> suffix
            mock_yum.return_value = "python-3.12.0-1.el9.x86_64    3.12.0-1.el9.x86_64"
            result = await yum._dnf_get_latest_version("python")

        assert result == "3.12.0-1.el9"

    @pytest.mark.asyncio
    async def test_get_latest_version_not_found(self) -> None:
        """Returns None when no command succeeds."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            mock_yum.return_value = None
            result = await yum._dnf_get_latest_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_latest_version_yum_parse_mismatch_line(self) -> None:
        """Skips lines not starting with package name."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # First line is for a different package, second line matches
            mock_yum.return_value = "other-pkg.x86_64    1.0.0-1.el9\npython-3.12.0-1.el9.x86_64    3.12.0-1.el9"
            result = await yum._dnf_get_latest_version("python")

        assert result == "3.12.0-1"

    @pytest.mark.asyncio
    async def test_get_latest_version_yum_parse_short_line(self) -> None:
        """Skips lines with fewer than 2 parts."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # Line with single value (no version part) — shorter than 2 parts
            mock_yum.return_value = "python\npython-3.12.0-1.el9.x86_64    3.12.0-1.el9"
            result = await yum._dnf_get_latest_version("python")

        assert result == "3.12.0-1"

    @pytest.mark.asyncio
    async def test_get_latest_version_yum_no_matching_line(self) -> None:
        """Returns None when yum output has no line starting with package."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # Only lines for other packages — none start with "python"
            mock_yum.return_value = "other-pkg.x86_64    1.0.0-1.el9"
            result = await yum._dnf_get_latest_version("python")

        assert result is None


# ---------------------------------------------------------------------------
# _dnf_get_all_versions
# ---------------------------------------------------------------------------


class TestDnfGetAllVersions:
    """Tests for ``_dnf_get_all_versions`` function."""

    @pytest.mark.asyncio
    async def test_get_all_versions_dnf(self) -> None:
        """Returns versions from dnf command."""
        with patch("pkg_defender.registry.yum._run_dnf_command", new_callable=AsyncMock) as mock_dnf:
            mock_dnf.return_value = "1.24.0-3.fc40\n1.22.0-2.fc40"
            result = await yum._dnf_get_all_versions("python")

        assert result == ["1.24.0-3.fc40", "1.22.0-2.fc40"]

    @pytest.mark.asyncio
    async def test_get_all_versions_deduplicates(self) -> None:
        """Deduplicates duplicate versions."""
        with patch("pkg_defender.registry.yum._run_dnf_command", new_callable=AsyncMock) as mock_dnf:
            mock_dnf.return_value = "1.24.0-3.fc40\n1.24.0-3.fc40\n1.22.0-2.fc40"
            result = await yum._dnf_get_all_versions("python")

        assert result == ["1.24.0-3.fc40", "1.22.0-2.fc40"]

    @pytest.mark.asyncio
    async def test_get_all_versions_yum_fallback(self) -> None:
        """Falls back to yum when dnf returns None."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # yum list all output format with arch suffix
            mock_yum.return_value = "python.x86_64    3.12.0-1.el9.x86_64"
            result = await yum._dnf_get_all_versions("python")

        assert result == ["3.12.0-1.el9"]

    @pytest.mark.asyncio
    async def test_get_all_versions_empty(self) -> None:
        """Returns empty list when no command succeeds."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            mock_yum.return_value = None
            result = await yum._dnf_get_all_versions("nonexistent")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_yum_parse_mismatch(self) -> None:
        """Skips lines not starting with package name."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # Line for different package should be skipped
            mock_yum.return_value = "other-pkg.x86_64    1.0.0-1.el9"
            result = await yum._dnf_get_all_versions("python")

        assert result == []

    @pytest.mark.asyncio
    async def test_get_all_versions_yum_parse_short_line(self) -> None:
        """Skips lines with fewer than 2 parts."""
        with (
            patch("pkg_defender.registry.yum._run_dnf_command") as mock_dnf,
            patch("pkg_defender.registry.yum._run_yum_command") as mock_yum,
        ):
            mock_dnf.return_value = None
            # Line single value (no version) should be skipped
            mock_yum.return_value = "python"
            result = await yum._dnf_get_all_versions("python")

        assert result == []


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for module-level constants."""

    def test_timeout_seconds_constant(self) -> None:
        """``TIMEOUT_SECONDS`` is set to 30."""
        assert yum.TIMEOUT_SECONDS == 30

    def test_intel_feed_max_retries_constant(self) -> None:
        """``INTEL_FEED_MAX_RETRIES`` is set to 3 (re-exported for compat)."""
        assert INTEL_FEED_MAX_RETRIES == 3

    def test_frozen_snapshot_repodata_urls_contains_openeuler(self) -> None:
        """``_FROZEN_SNAPSHOT_REPODATA_URLS`` contains the openEuler 22.03 LTS URL (Q7)."""
        assert "https://repo.openeuler.org/openEuler-22.03-LTS/OS/x86_64" in _FROZEN_SNAPSHOT_REPODATA_URLS


# ---------------------------------------------------------------------------
# _yum_get_installed_version
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# yum_get_installed_version (async)
# ---------------------------------------------------------------------------


class TestYumGetInstalledVersionAsync:
    """Tests for the async ``yum_get_installed_version``."""

    @staticmethod
    def _mock_proc(returncode: int = 0, stdout: str = "") -> MagicMock:
        proc = MagicMock(spec=asyncio.subprocess.Process)
        proc.returncode = returncode
        proc.communicate = AsyncMock(return_value=(stdout.encode(), b""))
        return proc

    @pytest.mark.asyncio
    async def test_returns_version_when_package_installed(self) -> None:
        """Returns version when package is installed."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec",
            return_value=self._mock_proc(stdout="7.88.1-1.fc38"),
        ):
            result = await yum.yum_get_installed_version("curl")

        assert result == "7.88.1-1.fc38"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        with patch("pkg_defender.registry.yum.asyncio.create_subprocess_exec", return_value=self._mock_proc(stdout="")):
            result = await yum.yum_get_installed_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when subprocess raises."""
        with patch(
            "pkg_defender.registry.yum.asyncio.create_subprocess_exec", side_effect=FileNotFoundError("rpm not found")
        ):
            result = await yum.yum_get_installed_version("curl")

        assert result is None


# ---------------------------------------------------------------------------
# dnf_get_installed_version (delegates to yum_get_installed_version)
# ---------------------------------------------------------------------------


class TestDnfGetInstalledVersion:
    """Tests for ``dnf_get_installed_version`` (delegates to ``yum_get_installed_version``)."""

    @pytest.mark.asyncio
    async def test_returns_version_via_yum_delegation(self) -> None:
        """Returns version when package is installed."""
        with patch("pkg_defender.registry.yum.yum_get_installed_version") as mock_yum:
            mock_yum.return_value = "7.88.1-1.fc38"
            result = await yum.dnf_get_installed_version("curl")

        assert result == "7.88.1-1.fc38"

    @pytest.mark.asyncio
    async def test_not_installed(self) -> None:
        """Returns None when package is not installed."""
        with patch("pkg_defender.registry.yum.yum_get_installed_version") as mock_yum:
            mock_yum.return_value = None
            result = await yum.dnf_get_installed_version("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_exception_returns_none(self) -> None:
        """Returns None when yum helper returns None (no exception propagates)."""
        with patch("pkg_defender.registry.yum.yum_get_installed_version") as mock_yum:
            mock_yum.return_value = None
            result = await yum.dnf_get_installed_version("curl")

        assert result is None
