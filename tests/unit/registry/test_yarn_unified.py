"""Tests for YarnUnifiedAdapter — npm registry + yarn command parsing."""

from __future__ import annotations

import pytest

from pkg_defender.models.command import CommandIntent
from pkg_defender.registry.yarn_unified import YarnUnifiedAdapter


@pytest.fixture
def adapter() -> YarnUnifiedAdapter:
    return YarnUnifiedAdapter()


class TestYarnUnifiedAdapterParse:
    def test_bare_yarn_is_sync(self, adapter: YarnUnifiedAdapter) -> None:
        """Bare 'yarn' with no args = SYNC."""
        result = adapter.parse([])
        assert result.intent == CommandIntent.SYNC
        assert result.manager_subcommand == "install"

    def test_yarn_install_is_sync(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["install"])
        assert result.intent == CommandIntent.SYNC

    def test_yarn_add_is_install(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["add", "lodash"])
        assert result.intent == CommandIntent.INSTALL
        assert len(result.packages) == 1
        assert result.packages[0].name == "lodash"

    def test_yarn_upgrade_is_update(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["upgrade", "lodash"])
        assert result.intent == CommandIntent.UPDATE

    def test_yarn_remove_is_remove(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["remove", "lodash"])
        assert result.intent == CommandIntent.REMOVE

    def test_yarn_dlx_is_execute(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["dlx", "create-react-app"])
        assert result.intent == CommandIntent.EXECUTE

    def test_yarn_dev_dependency(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["add", "--dev", "jest"])
        assert result.is_dev_dependency is True

    def test_yarn_dev_d_shorthand(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["add", "-D", "jest"])
        assert result.is_dev_dependency is True

    def test_yarn_set_is_install(self, adapter: YarnUnifiedAdapter) -> None:
        """yarn set version X installs a specific yarn version."""
        result = adapter.parse(["set", "version", "berry"])
        assert result.intent == CommandIntent.INSTALL

    def test_yarn_link_is_safe(self, adapter: YarnUnifiedAdapter) -> None:
        result = adapter.parse(["link"])
        assert result.intent == CommandIntent.SAFE_PASSTHROUGH


class TestYarnUnifiedAdapterBuildExecArgs:
    def test_build_exec_args_add(self, adapter: YarnUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "lodash"])
        result = adapter.build_exec_args(parsed)
        assert result[0] == "yarn"
        assert "add" in result
        assert "lodash" in result

    def test_build_exec_args_with_version(self, adapter: YarnUnifiedAdapter) -> None:
        parsed = adapter.parse(["add", "lodash@4.17.21"])
        result = adapter.build_exec_args(parsed)
        assert "lodash@4.17.21" in result
