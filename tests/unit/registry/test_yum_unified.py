"""Tests for YumUnifiedAdapter — combined YUM registry + yum command parsing.

Phase 2: capabilities now declare PROXIED (not VERIFIED) per the
timestamp-reliability cascade refactor. The unified wrapper still
delegates to the underlying cascade via the module-level helpers in
``pkg_defender.registry.yum``.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.base import EcosystemCapability
from pkg_defender.registry.yum import _reset_clients_for_tests
from pkg_defender.registry.yum_unified import YumUnifiedAdapter


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    """Reset module-level YUM adapter singletons between tests.

    Both the YUMAdapter singleton and the underlying BodhiClient /
    KojiClient / RepodataClient singletons are shared across tests.
    Without this fixture, the singleton would leak the mock state
    set up in one test into the next.
    """
    _reset_clients_for_tests()
    yield
    _reset_clients_for_tests()


@pytest.fixture
def adapter() -> YumUnifiedAdapter:
    """Create a YumUnifiedAdapter for testing."""
    return YumUnifiedAdapter()


class TestYumUnifiedAdapterIdentity:
    """Test identity attributes (ecosystem, manager_name)."""

    def test_capabilities_include_proxied_timestamps(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Capabilities declare PROXIED (the honest tier for the cascade)."""
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS in adapter.capabilities

    def test_capabilities_exclude_verified_timestamps(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Capabilities do NOT declare VERIFIED (was a false claim for non-Fedora).

        MUTATION CONTRACT: re-adding ``VERIFIED_PUBLISH_TIMESTAMPS`` to
        ``YumUnifiedAdapter.capabilities`` MUST fail this test.
        """
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS not in adapter.capabilities

    def test_capabilities_exclude_threat_intel(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Capabilities do NOT declare THREAT_INTEL (AUDIT-tier rule)."""
        assert EcosystemCapability.THREAT_INTEL_SUPPORT not in adapter.capabilities


class TestYumUnifiedAdapterParse:
    """Test parse() — yum command parsing."""

    def test_parse_install_with_package(self, adapter: YumUnifiedAdapter) -> None:
        result = adapter.parse(["install", "httpd"])
        assert result.manager == "yum"
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "httpd"
        assert result.is_global is True

    def test_parse_update_update_intent(self, adapter: YumUnifiedAdapter) -> None:
        result = adapter.parse(["update", "httpd"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_upgrade_update_intent(self, adapter: YumUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade"])
        assert result.intent == CommandIntent.UPDATE
        assert result.is_global is True

    def test_parse_localinstall_install_intent(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["localinstall", "package.rpm"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_group_install_intent(self, adapter: YumUnifiedAdapter) -> None:
        result = adapter.parse(["group", "install", "Development Tools"])
        assert result.intent == CommandIntent.INSTALL

    def test_parse_remove_remove_intent(self, adapter: YumUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "httpd"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_autoremove_remove_intent(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["autoremove"])
        assert result.intent == CommandIntent.REMOVE

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_unknown_subcommand_safe(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestYumUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_install(self, adapter: YumUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "httpd"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "yum"
        assert "install" in result
        assert "httpd" in result

    def test_build_exec_args_with_flags(self, adapter: YumUnifiedAdapter) -> None:
        parsed = adapter.parse(["install", "-y", "httpd"])
        result = adapter.build_exec_args(parsed)
        assert "-y" in result
        assert "httpd" in result


class TestYumUnifiedAdapterRegistryDelegation:
    """Test registry method delegation to YUMAdapter (via class composition)."""

    @pytest.mark.asyncio
    async def test_get_latest_version_delegates(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._yum_delegate,
            "get_latest_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "2.4.58"
            result = await adapter.get_latest_version("httpd")
            assert result == "2.4.58"
            mock.assert_called_once_with("httpd", None)

    @pytest.mark.asyncio
    async def test_get_publish_time_delegates_to_module_helper(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """``get_publish_time`` calls the YUMAdapter cascade method."""
        expected_dt = datetime(2026, 3, 11, 23, 47, 27, tzinfo=UTC)
        with patch.object(
            adapter._yum_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "bodhi")
            dt, source = await adapter.get_publish_time("httpd", "2.4.58-1.fc40")
            assert dt == expected_dt
            assert source == "bodhi"
            mock.assert_called_once_with("httpd", "2.4.58-1.fc40", None, is_latest=False)

    @pytest.mark.asyncio
    async def test_get_publish_time_propagates_user_manual(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """When the cascade falls through to ``user_manual``, the wrapper propagates it."""
        with patch.object(
            adapter._yum_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (None, "unresolved")
            dt, source = await adapter.get_publish_time("httpd", "2.4.58-1.fc40")
            assert dt is None
            assert source == "unresolved"

    @pytest.mark.asyncio
    async def test_get_publish_time_propagates_repodata(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """When the cascade returns a ``repodata`` source, the wrapper propagates it."""
        expected_dt = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        with patch.object(
            adapter._yum_delegate,
            "get_publish_time",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = (expected_dt, "repodata")
            dt, source = await adapter.get_publish_time("httpd", "2.4.58-1.el9")
            assert dt == expected_dt
            assert source == "repodata"

    @pytest.mark.asyncio
    async def test_get_all_versions_delegates(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        with patch.object(
            adapter._yum_delegate,
            "get_all_versions",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = []
            result = await adapter.get_all_versions("httpd")
            assert result == []
            mock.assert_called_once_with("httpd", None)

    @pytest.mark.asyncio
    async def test_get_installed_version_delegates(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        with patch(
            "pkg_defender.registry.yum.yum_get_installed_version",
            new_callable=AsyncMock,
        ) as mock:
            mock.return_value = "2.4.58-1.fc40"
            result = await adapter.get_installed_version("httpd")
            assert result == "2.4.58-1.fc40"
            mock.assert_called_once_with("httpd")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_latest_version."""
        with patch.object(adapter, "get_latest_version", new_callable=AsyncMock) as mock:
            mock.return_value = "2.4.58"
            result = await adapter.resolve_latest_version("httpd")
            assert result == "2.4.58"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Bridge method delegates through get_publish_time."""
        expected_dt = datetime(2024, 6, 1, tzinfo=UTC)
        with patch.object(adapter, "get_publish_time", new_callable=AsyncMock) as mock:
            mock.return_value = (expected_dt, "bodhi")
            result = await adapter.get_release_date("httpd", "2.4.58-1.fc40")
            assert result == expected_dt


class TestYumUnifiedAdapterCascadeDelegation:
    """Verify the unified wrapper calls the underlying YUM cascade.

    These tests mock the underlying cascade clients directly (the same
    pattern used in :file:`test_registry_yum.py`) to confirm the
    unified wrapper's ``get_publish_time`` call propagates through
    the module-level helper to the cascade.
    """

    @pytest.mark.asyncio
    async def test_cascade_bodhi_hit_propagates_to_unified(
        self,
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Bodhi cascade hit → unified wrapper returns the same tuple."""
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
        adapter: YumUnifiedAdapter,
    ) -> None:
        """Bodhi+Koji None → repodata hit → unified wrapper returns the repodata tuple."""
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
