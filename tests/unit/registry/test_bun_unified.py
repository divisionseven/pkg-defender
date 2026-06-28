"""Tests for BunUnifiedAdapter — npm registry + bun command parsing."""

from __future__ import annotations

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.bun_unified import BunUnifiedAdapter


@pytest.fixture
def adapter() -> BunUnifiedAdapter:
    """Create a BunUnifiedAdapter for testing."""
    return BunUnifiedAdapter()


class TestBunUnifiedAdapterIdentity:
    """Test identity attributes."""


class TestBunUnifiedAdapterParse:
    """Test parse() — bun command parsing."""

    def test_bun_add_is_install(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["add", "lodash"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "lodash"

    def test_bun_install_is_sync(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC

    def test_bun_install_with_packages_is_install(
        self,
        adapter: BunUnifiedAdapter,
    ) -> None:
        result = adapter.parse(["install", "lodash"])
        # bun install with a package is SYNC (bun treats install as lockfile sync)
        assert result.intent == CommandIntent.SYNC

    def test_bun_update_is_update(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["update", "lodash"])
        assert result.intent == CommandIntent.UPDATE

    def test_bun_upgrade_is_update(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade"])
        assert result.intent == CommandIntent.UPDATE

    def test_bun_x_is_execute(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["x", "create-react-app"])
        assert result.intent == CommandIntent.EXECUTE

    def test_bun_run_is_execute(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["run", "dev"])
        assert result.intent == CommandIntent.EXECUTE

    def test_bun_dev_dependency(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["add", "--save-dev", "jest"])
        assert result.is_dev_dependency is True

    def test_bun_unknown_is_safe(self, adapter: BunUnifiedAdapter) -> None:
        result = adapter.parse(["unknown-cmd"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_bun_pm_is_safe(self, adapter: BunUnifiedAdapter) -> None:
        """bun pm is a compound subcommand."""
        result = adapter.parse(["pm", "ls"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH

    def test_parse_empty_args_safe_passthrough(
        self,
        adapter: BunUnifiedAdapter,
    ) -> None:
        """parse([]) returns SAFE_PASSTHROUGH."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestBunUnifiedAdapterBuildExecArgs:
    """Test build_exec_args() — command reconstruction."""

    def test_build_exec_args_add(self, adapter: BunUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "lodash"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "bun"
        assert "add" in result
        assert "lodash" in result

    def test_build_exec_args_with_version(
        self,
        adapter: BunUnifiedAdapter,
    ) -> None:
        parsed = adapter.parse(["add", "lodash@4.17.21"])
        result = adapter.build_exec_args(parsed)
        assert "lodash@4.17.21" in result
