"""Tests for pkg_defender.registry.base module.

Tests the HTTPMixin, RegistryAdapter abstract base,
UnifiedRegistryAdapter bridge methods, and PipelineAdapter wrapper.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import ParsedCommand
from pkg_defender.registry.base import (
    CoverageTier,
    EcosystemCapability,
    PipelineAdapter,
    RegistryAdapter,
    UnifiedRegistryAdapter,
)


class TestEcosystemCapability:
    """Tests for EcosystemCapability enum."""

    def test_values(self) -> None:
        """Enum has expected values."""
        assert EcosystemCapability.VERIFIED_PUBLISH_TIMESTAMPS.value == "verified_timestamps"
        assert EcosystemCapability.PROXIED_PUBLISH_TIMESTAMPS.value == "proxied_timestamps"
        assert EcosystemCapability.NO_PUBLISH_TIMESTAMPS.value == "no_timestamps"
        assert EcosystemCapability.THREAT_INTEL_SUPPORT.value == "threat_intel"


class TestCoverageTier:
    """Tests for CoverageTier enum."""

    def test_values(self) -> None:
        """Enum has expected values."""
        assert CoverageTier.FULL.value == "full"
        assert CoverageTier.PARTIAL.value == "partial"
        assert CoverageTier.AUDIT.value == "audit"

    def test_str(self) -> None:
        """__str__ returns the string value."""
        assert str(CoverageTier.FULL) == "full"
        assert str(CoverageTier.PARTIAL) == "partial"
        assert str(CoverageTier.AUDIT) == "audit"


class TestPipelineAdapter:
    """Tests for PipelineAdapter wrapper."""

    @pytest.fixture
    def registry_adapter(self) -> RegistryAdapter:
        """Create a minimal mock RegistryAdapter."""
        from unittest.mock import MagicMock

        adapter = MagicMock(spec=RegistryAdapter)
        adapter.ecosystem = "test-ecosystem"
        return adapter

    @pytest.mark.asyncio
    async def test_ecosystem_property(self) -> None:
        """ecosystem returns the requested ecosystem, not the adapter's."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.ecosystem = "bun"
        pa = PipelineAdapter(adapter, requested_ecosystem="npm")
        assert pa.ecosystem == "npm"

    @pytest.mark.asyncio
    async def test_adapter_ecosystem_property(self) -> None:
        """adapter_ecosystem returns the wrapped adapter's ecosystem."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.ecosystem = "bun"
        pa = PipelineAdapter(adapter, requested_ecosystem="npm")
        assert pa.adapter_ecosystem == "bun"

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(self, registry_adapter: RegistryAdapter) -> None:
        """resolve_latest_version delegates to adapter.get_latest_version."""
        with patch.object(registry_adapter, "get_latest_version", AsyncMock(return_value="1.0.0")):
            pa = PipelineAdapter(registry_adapter, requested_ecosystem="test")
            result = await pa.resolve_latest_version("pkg")
        assert result == "1.0.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(self, registry_adapter: RegistryAdapter) -> None:
        """get_release_date delegates to adapter.get_publish_time."""
        from datetime import datetime

        with patch.object(
            registry_adapter, "get_publish_time", AsyncMock(return_value=(datetime(2024, 1, 15), "registry"))
        ):
            pa = PipelineAdapter(registry_adapter, requested_ecosystem="test")
            result = await pa.get_release_date("pkg", "1.0.0")
        assert result == datetime(2024, 1, 15)

    @pytest.mark.asyncio
    async def test_resolve_latest_version_timeout_error(self) -> None:
        """TimeoutError from adapter is converted to PipelineTimeoutError."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.get_latest_version = AsyncMock(side_effect=TimeoutError("timeout"))
        adapter.ecosystem = "test"
        pa = PipelineAdapter(adapter, requested_ecosystem="test")

        from pkg_defender.audit.errors import TimeoutError as PipelineTimeoutError

        with pytest.raises(PipelineTimeoutError):
            await pa.resolve_latest_version("pkg")

    @pytest.mark.asyncio
    async def test_resolve_latest_version_client_error(self) -> None:
        """ClientError from adapter is converted to NetworkError."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.get_latest_version = AsyncMock(side_effect=aiohttp.ClientError("network down"))
        adapter.ecosystem = "test"
        pa = PipelineAdapter(adapter, requested_ecosystem="test")

        from pkg_defender.audit.errors import NetworkError

        with pytest.raises(NetworkError):
            await pa.resolve_latest_version("pkg")

    @pytest.mark.asyncio
    async def test_get_release_date_timeout_error(self) -> None:
        """TimeoutError from get_publish_time is converted to PipelineTimeoutError."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.get_publish_time = AsyncMock(side_effect=TimeoutError("timeout"))
        adapter.ecosystem = "test"
        pa = PipelineAdapter(adapter, requested_ecosystem="test")

        from pkg_defender.audit.errors import TimeoutError as PipelineTimeoutError

        with pytest.raises(PipelineTimeoutError):
            await pa.get_release_date("pkg", "1.0.0")

    @pytest.mark.asyncio
    async def test_get_release_date_client_error(self) -> None:
        """ClientError from get_publish_time is converted to NetworkError."""
        adapter = MagicMock(spec=RegistryAdapter)
        adapter.get_publish_time = AsyncMock(side_effect=aiohttp.ClientError("network down"))
        adapter.ecosystem = "test"
        pa = PipelineAdapter(adapter, requested_ecosystem="test")

        from pkg_defender.audit.errors import NetworkError

        with pytest.raises(NetworkError):
            await pa.get_release_date("pkg", "1.0.0")


class TestUnifiedRegistryAdapterBridge:
    """Tests for UnifiedRegistryAdapter bridge methods."""

    @pytest.fixture
    def adapter(self) -> UnifiedRegistryAdapter:
        """Create a minimal concrete UnifiedRegistryAdapter for testing."""
        from pkg_defender.models.command import CommandIntent

        class ConcreteAdapter(UnifiedRegistryAdapter):
            ecosystem = "test"
            registry_base_url = "https://test.example.com"
            manager_name = "test"
            coverage_tier = CoverageTier.FULL
            COMMAND_INTENT_MAP = {"install": CommandIntent.INSTALL, "remove": CommandIntent.REMOVE}
            VALUE_FLAGS = frozenset({"--version", "--output"})
            PKGD_FLAGS = frozenset(
                {
                    "--dry-run",
                    "--cooldown",
                    "--force",
                    "--json",
                    "--verbose",
                    "-v",
                    "--ci",
                    "--non-interactive",
                    "--explain",
                    "--allow-once",
                    "--bypass-cooldown",
                    "--bypass-threat",
                }
            )

            @property
            def capabilities(self) -> list[EcosystemCapability]:
                return [EcosystemCapability.THREAT_INTEL_SUPPORT]

            async def get_publish_time(
                self,
                package: str,
                version: str,
                session: aiohttp.ClientSession | None = None,
                is_latest: bool = False,
            ) -> tuple[datetime | None, str]:
                return (None, "unresolved")

            async def get_all_versions(
                self,
                package: str,
                session: aiohttp.ClientSession | None = None,
            ) -> list[VersionInfo]:
                return []

            async def get_latest_version(
                self,
                package: str,
                session: aiohttp.ClientSession | None = None,
            ) -> str | None:
                return None

            async def get_installed_version(self, package: str) -> str | None:
                return None

            def parse(self, manager_args: list[str]) -> ParsedCommand:
                return ParsedCommand(
                    manager=self.manager_name,
                    intent=CommandIntent.SAFE_PASSTHROUGH,
                    packages=[],
                    raw_args=manager_args,
                    ecosystem=self.ecosystem,
                )

            def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
                return []

        return ConcreteAdapter()

    @pytest.mark.asyncio
    async def test_resolve_latest_version_delegates(self, adapter: UnifiedRegistryAdapter) -> None:
        """resolve_latest_version calls get_latest_version."""
        with patch.object(adapter, "get_latest_version", AsyncMock(return_value="1.0.0")):
            result = await adapter.resolve_latest_version("pkg")
        assert result == "1.0.0"

    @pytest.mark.asyncio
    async def test_get_release_date_delegates(self, adapter: UnifiedRegistryAdapter) -> None:
        """get_release_date calls get_publish_time."""
        from datetime import datetime

        with patch.object(adapter, "get_publish_time", AsyncMock(return_value=(datetime(2024, 1, 15), "registry"))):
            result = await adapter.get_release_date("pkg", "1.0.0")
        assert result == datetime(2024, 1, 15)

    @pytest.mark.asyncio
    async def test_fetch_release_date_delegates(self, adapter: UnifiedRegistryAdapter) -> None:
        """fetch_release_date calls get_publish_time."""
        from datetime import datetime

        with patch.object(adapter, "get_publish_time", AsyncMock(return_value=(datetime(2024, 1, 15), "registry"))):
            result = await adapter.fetch_release_date("pkg", "1.0.0")
        assert result == datetime(2024, 1, 15)

    @pytest.mark.asyncio
    async def test_resolve_latest_version_timeout_error(self, adapter: UnifiedRegistryAdapter) -> None:
        """TimeoutError is converted to PipelineTimeoutError."""
        with patch.object(adapter, "get_latest_version", AsyncMock(side_effect=TimeoutError("timeout"))):
            from pkg_defender.audit.errors import TimeoutError as PipelineTimeoutError

            with pytest.raises(PipelineTimeoutError):
                await adapter.resolve_latest_version("pkg")

    @pytest.mark.asyncio
    async def test_get_release_date_client_error(self, adapter: UnifiedRegistryAdapter) -> None:
        """ClientError is converted to NetworkError."""
        with patch.object(adapter, "get_publish_time", AsyncMock(side_effect=aiohttp.ClientError("down"))):
            from pkg_defender.audit.errors import NetworkError

            with pytest.raises(NetworkError):
                await adapter.get_release_date("pkg", "1.0.0")

    def test_classify_intent_install(self, adapter: UnifiedRegistryAdapter) -> None:
        """classify_intent returns INSTALL for install subcommand."""
        from pkg_defender.models.command import CommandIntent

        assert adapter.classify_intent("install") == CommandIntent.INSTALL

    def test_classify_intent_remove(self, adapter: UnifiedRegistryAdapter) -> None:
        """classify_intent returns REMOVE for remove subcommand."""
        from pkg_defender.models.command import CommandIntent

        assert adapter.classify_intent("remove") == CommandIntent.REMOVE

    def test_classify_intent_safe(self, adapter: UnifiedRegistryAdapter) -> None:
        """classify_intent returns SAFE_PASSTHROUGH for unknown subcommand."""
        from pkg_defender.models.command import CommandIntent

        assert adapter.classify_intent("list") == CommandIntent.SAFE_PASSTHROUGH

    def test_split_pkgd_flags_dry_run(self, adapter: UnifiedRegistryAdapter) -> None:
        """--dry-run is extracted from args."""
        clean, flags = adapter.split_pkgd_flags(["--dry-run", "install", "pkg"])
        assert clean == ["install", "pkg"]
        assert flags == {"dry_run": True}

    def test_split_pkgd_flags_cooldown_with_value(self, adapter: UnifiedRegistryAdapter) -> None:
        """--cooldown with value is extracted."""
        clean, flags = adapter.split_pkgd_flags(["--cooldown", "7", "install", "pkg"])
        assert clean == ["install", "pkg"]
        assert flags == {"cooldown": "7"}

    def test_split_pkgd_flags_verbose(self, adapter: UnifiedRegistryAdapter) -> None:
        """--verbose and -v are extracted."""
        clean, flags = adapter.split_pkgd_flags(["--verbose", "install"])
        assert flags == {"verbose": True}
        clean, flags = adapter.split_pkgd_flags(["-v", "install"])
        assert flags == {"verbose": True}

    def test_split_pkgd_flags_equals_form(self, adapter: UnifiedRegistryAdapter) -> None:
        """--flag=value form is parsed."""
        clean, flags = adapter.split_pkgd_flags(["--cooldown=5", "install"])
        assert clean == ["install"]
        assert flags == {"cooldown": "5"}

    def test_split_pkgd_flags_non_pkgd_equals(self, adapter: UnifiedRegistryAdapter) -> None:
        """--flag=value where flag is not a PKGD flag stays in clean."""
        clean, flags = adapter.split_pkgd_flags(["--format=json", "install"])
        assert "--format=json" in clean

    def test_tokenize_args_with_value_flags(self, adapter: UnifiedRegistryAdapter) -> None:
        """VALUE_FLAGS are tokenized as tuples."""
        tokens = adapter.tokenize_args(["--version", "3", "install"])
        assert ("--version", "3") in tokens
        assert "install" in tokens

    def test_tokenize_args_value_flag_without_value(self, adapter: UnifiedRegistryAdapter) -> None:
        """VALUE_FLAG at end of args stays as string."""
        tokens = adapter.tokenize_args(["--version"])
        assert "--version" in tokens

    def test_tokenize_args_value_flag_equals_form(self, adapter: UnifiedRegistryAdapter) -> None:
        """VALUE_FLAG in --flag=value form is tokenized."""
        tokens = adapter.tokenize_args(["--version=3", "install"])
        assert ("--version", "3") in tokens

    def test_tokenize_args_unknown_flag(self, adapter: UnifiedRegistryAdapter) -> None:
        """Non-VALUE_FLAG flags stay as strings."""
        tokens = adapter.tokenize_args(["--unknown", "value", "install"])
        assert "--unknown" in tokens
        assert "value" in tokens
        assert "install" in tokens

    def test_extract_packages_and_flags(self, adapter: UnifiedRegistryAdapter) -> None:
        """Separates package strings from manager flags.

        Non-tuple tokens (both subcommands and package names) are
        included in the packages list.
        """
        tokens: list[tuple[str, str] | str] = [("--version", "3"), "install", "lodash"]
        packages, flags = adapter.extract_packages_and_flags(tokens)
        assert packages == ["install", "lodash"]
        assert "--version" in flags
        assert "3" in flags

    def test_safe_passthrough_basic(self, adapter: UnifiedRegistryAdapter) -> None:
        """_safe_passthrough returns correct ParsedCommand."""
        cmd = adapter._safe_passthrough(["install", "pkg"], {"dry_run": True}, subcommand="install")
        from pkg_defender.models.command import CommandIntent

        assert cmd.manager == "test"
        assert cmd.intent == CommandIntent.SAFE_PASSTHROUGH
        assert cmd.packages == []
        assert cmd.manager_subcommand == "install"
        assert cmd.pkgd_flags == {"dry_run": True}
        assert cmd.ecosystem == "test"

    def test_safe_passthrough_with_remaining(self, adapter: UnifiedRegistryAdapter) -> None:
        """_safe_passthrough includes remaining args as manager_flags."""
        cmd = adapter._safe_passthrough(["install"], {}, remaining=["--flag"])
        assert "--flag" in cmd.manager_flags
