"""Tests for DnfUnifiedAdapter — YUM alias in the unified registry.

DnfUnifiedAdapter inherits all behavior from YumUnifiedAdapter.
The only differences are ``manager_name="dnf"`` and ``ecosystem="dnf"``.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.dnf_unified import DnfUnifiedAdapter
from pkg_defender.registry.yum import _reset_clients_for_tests


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    """Reset the YUM-side client singletons to prevent cascade-mock leakage.

    The DnfUnifiedAdapter inherits from YumUnifiedAdapter, which owns
    the BodhiClient / KojiClient / RepodataClient singletons in the
    ``yum`` module.
    """
    _reset_clients_for_tests()
    yield
    _reset_clients_for_tests()


@pytest.fixture
def adapter() -> DnfUnifiedAdapter:
    """Create a DnfUnifiedAdapter for testing."""
    return DnfUnifiedAdapter()


class TestDnfUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_proxied_timestamps(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        """Capabilities declare PROXIED (the honest tier for the cascade)."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_exclude_verified_timestamps(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        """Capabilities do NOT declare VERIFIED (was a false claim for non-Fedora).

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``DnfUnifiedAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in adapter.capabilities

    def test_capabilities_exclude_threat_intel(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        """Capabilities do NOT declare THREAT_INTEL (AUDIT-tier rule)."""
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in adapter.capabilities


class TestDnfUnifiedAdapterParse:
    """Test parse() — dnf command parsing."""

    def test_parse_install_with_package(self, adapter: DnfUnifiedAdapter) -> None:
        result = adapter.parse(["install", "httpd"])
        assert result.manager == "dnf"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "httpd"
        assert result.is_global is True

    def test_parse_update_update_intent(self, adapter: DnfUnifiedAdapter) -> None:
        result = adapter.parse(["update", "httpd"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_upgrade_update_intent(self, adapter: DnfUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_localinstall_install_intent(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["localinstall", "package.rpm"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_group_install_intent(self, adapter: DnfUnifiedAdapter) -> None:
        result = adapter.parse(["group", "install", "Development Tools"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_remove_remove_intent(self, adapter: DnfUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "httpd"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_autoremove_remove_intent(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["autoremove"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestDnfUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: DnfUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "httpd"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "dnf"
        assert "install" in result
        assert "httpd" in result

    def test_build_exec_args_with_flags(self, adapter: DnfUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "-y", "httpd"])
        result = adapter.build_exec_args(parsed)
        assert "-y" in result
        assert "httpd" in result


class TestDnfUnifiedAdapterCascadeDelegation:
    """Verify the unified wrapper reaches the underlying YUM cascade.

    These tests mock the YUM cascade clients directly to confirm the
    DNF unified wrapper's ``get_publish_time`` call propagates
    through ``dnf.dnf_get_publish_time`` → ``_get_yum_adapter`` →
    YUMAdapter.get_publish_time → 3-tier cascade.
    """

    @pytest.mark.asyncio
    async def test_cascade_bodhi_hit_propagates_to_unified(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        """Bodhi cascade hit → DNF unified wrapper returns the same tuple."""
        from pkg_defender.registry._bodhi_client import SOURCE_BODHI

        bodhi_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        bodhi_mock = MagicMock()
        bodhi_mock.get_publish_time = AsyncMock(
            return_value=(bodhi_dt, SOURCE_BODHI),
        )
        koji_mock = MagicMock()
        koji_mock.get_build_completion_time = AsyncMock()
        repodata_mock = MagicMock()
        repodata_mock.get_publish_time = AsyncMock()

        with (
            patch(
                "pkg_defender.registry.yum._get_bodhi_client",
                return_value=bodhi_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_koji_client",
                return_value=koji_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_repodata_client",
                return_value=repodata_mock,
            ),
        ):
            result = await adapter.get_publish_time("curl", "8.21.0-1.fc45")

        assert result == (bodhi_dt, SOURCE_BODHI)
        koji_mock.get_build_completion_time.assert_not_called()
        repodata_mock.get_publish_time.assert_not_called()

    @pytest.mark.asyncio
    async def test_cascade_falls_through_to_repodata_propagates_to_unified(
        self,
        adapter: DnfUnifiedAdapter,
    ) -> None:
        """Bodhi+Koji None → repodata hit → DNF unified wrapper returns the repodata tuple."""
        from pkg_defender.registry._repodata_client import SOURCE_REPODATA

        repodata_dt = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        bodhi_mock = MagicMock()
        bodhi_mock.get_publish_time = AsyncMock(return_value=(None, "bodhi"))
        koji_mock = MagicMock()
        koji_mock.get_build_completion_time = AsyncMock(return_value=(None, "koji"))
        repodata_mock = MagicMock()
        repodata_mock.get_publish_time = AsyncMock(
            return_value=(repodata_dt, "https://dl.fedoraproject.org/..."),
        )

        with (
            patch(
                "pkg_defender.registry.yum._get_bodhi_client",
                return_value=bodhi_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_koji_client",
                return_value=koji_mock,
            ),
            patch(
                "pkg_defender.registry.yum._get_repodata_client",
                return_value=repodata_mock,
            ),
        ):
            result = await adapter.get_publish_time("curl", "8.21.0-1.fc45")

        assert result == (repodata_dt, SOURCE_REPODATA)
        bodhi_mock.get_publish_time.assert_awaited_once()
        koji_mock.get_build_completion_time.assert_awaited_once()
        repodata_mock.get_publish_time.assert_awaited_once()
