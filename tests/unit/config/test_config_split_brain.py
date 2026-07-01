"""Regression tests for config file write path consistency (PKGD_CONFIG_PATH, --config).

Verifies that all config write operations (setup, config set, config reset)
use the same path resolution as the read path (load_config()):

    --config flag > PKGD_CONFIG_PATH env var > get_default_config_path()

Also verifies:
- TOML round-trip consistency (_write_toml_fallback → load_config)
- Immediate stderr emission on write failure
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_PARTIAL_FAILURE as _EXIT_PARTIAL_FAILURE
from pkg_defender.cli.main import cli

pytestmark = pytest.mark.unit


class TestConfigSplitBrain:
    """Tests for config write path consistency."""

    def test_setup_writes_to_pkgd_config_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """setup writes to PKGD_CONFIG_PATH when env var is set."""
        custom_config = tmp_path / "custom" / "config.toml"
        monkeypatch.setenv("PKGD_CONFIG_PATH", str(custom_config))

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        assert custom_config.exists(), f"Config should have been written to PKGD_CONFIG_PATH: {custom_config}"

    def test_config_set_writes_to_pkgd_config_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """config set writes to PKGD_CONFIG_PATH when env var is set."""
        custom_config = tmp_path / "custom" / "config.toml"
        custom_config.parent.mkdir(parents=True)
        custom_config.write_text("[cooldown]\ndefault_days = 3\n")
        monkeypatch.setenv("PKGD_CONFIG_PATH", str(custom_config))

        result = runner.invoke(cli, ["config", "set", "cooldown.default_days", "7"])

        assert result.exit_code == 0
        # Verify the value was written to the custom path
        with open(custom_config, "rb") as f:
            data = tomllib.load(f)
        assert data.get("cooldown", {}).get("default_days") == 7

    def test_config_set_respects_cli_flag(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Regression: --config flag takes precedence over PKGD_CONFIG_PATH in config_set.

        This is a precedence regression test — it verifies that the
        --config flag still wins even though new PKGD_CONFIG_PATH-aware
        code paths have been added nearby. Without this regression guard,
        an accidentally reordered precedence chain could silently start
        writing to the env-var path instead of the flag path.
        """
        flag_config = tmp_path / "flag" / "config.toml"
        flag_config.parent.mkdir(parents=True)
        flag_config.write_text("[cooldown]\ndefault_days = 3\n")

        env_config = tmp_path / "env" / "config.toml"
        env_config.parent.mkdir(parents=True)
        env_config.write_text("[cooldown]\ndefault_days = 3\n")

        monkeypatch.setenv("PKGD_CONFIG_PATH", str(env_config))

        result = runner.invoke(cli, ["--config", str(flag_config), "config", "set", "cooldown.default_days", "7"])

        assert result.exit_code == 0
        # Verify value was written to flag path, not env path
        with open(flag_config, "rb") as f:
            flag_data = tomllib.load(f)
        with open(env_config, "rb") as f:
            env_data = tomllib.load(f)
        assert flag_data.get("cooldown", {}).get("default_days") == 7
        assert env_data.get("cooldown", {}).get("default_days") == 3  # unchanged

    def test_config_reset_respects_pkgd_config_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """config reset deletes config at PKGD_CONFIG_PATH, not the default path.

        Regression test: without PKGD_CONFIG_PATH awareness in config_reset(),
        the command would only look at the default config path. This test
        ensures that when PKGD_CONFIG_PATH is set, the custom path is deleted
        and the default path is left untouched.

        T1: This would fail on old code where config_reset() didn't check
        PKGD_CONFIG_PATH.
        """

        # Create a custom config path and a marker at the default path
        custom_config = tmp_path / "custom" / "config.toml"
        custom_config.parent.mkdir(parents=True)
        custom_config.write_text("[cooldown]\ndefault_days = 3\n")

        # Mock get_default_config_path so we can verify it's not touched
        default_marker = tmp_path / "default" / "pkgd.toml"
        default_marker.parent.mkdir(parents=True)
        default_marker.write_text("[cooldown]\ndefault_days = 7\n")

        with mock.patch(
            "pkg_defender.cli.commands.config.get_default_config_path",
            return_value=default_marker,
        ):
            monkeypatch.setenv("PKGD_CONFIG_PATH", str(custom_config))

            result = runner.invoke(cli, ["--force", "config", "reset"])

        assert result.exit_code == 0, f"Expected 0, got {result.exit_code}: {result.output}"
        # Custom config should be deleted
        assert not custom_config.exists(), "Config at PKGD_CONFIG_PATH should have been deleted"
        # Default config should still exist (config_reset should not touch it)
        assert default_marker.exists(), "Default config path should not have been deleted"

    def test_setup_writes_to_cli_flag_path(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """setup writes to --config path when flag is provided."""
        custom_config = tmp_path / "custom" / "config.toml"
        monkeypatch.setenv("PKGD_CONFIG_PATH", str(tmp_path / "should_not_be_used" / "config.toml"))

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "--config", str(custom_config), "setup"])

        assert result.exit_code == 0
        assert custom_config.exists(), f"Config should have been written to --config path: {custom_config}"

    def test_setup_write_failure_emits_warning_immediately(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Config write failure emits warning immediately (not buried in warnings list)."""
        config_path = tmp_path / "missing" / "pkgd.toml"

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch(
                "pkg_defender.cli.commands.setup.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch(
                "pkg_defender.cli.commands.setup._write_config_toml",
                side_effect=PermissionError("denied"),
            ),
            mock.patch("pkg_defender.cli.commands.setup.init_db"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "--config", str(config_path), "setup"])

        assert result.exit_code == _EXIT_PARTIAL_FAILURE
        # Should have the warning as immediate output
        assert "Config file write failed" in result.output

    def test_load_config_roundtrip_consistency(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """TOML roundtrip preserves non-default values through template.

        Using non-default values proves the template is structurally valid
        and that values survive a write→load cycle.
        """
        from tomlkit import dumps

        from pkg_defender.cli.common import _generate_config_template, _write_config_toml
        from pkg_defender.config.settings import load_config

        config_path = tmp_path / "config" / "pkgd.toml"
        config_path.parent.mkdir(parents=True)

        # Generate template and override with non-default values
        doc = _generate_config_template()
        doc["command_timeout_seconds"] = 45
        doc["fail_on_threat_enabled"] = False
        _write_config_toml(config_path, dumps(doc))

        # Read it back
        config = load_config(config_path)

        # Verify non-default values survive the round-trip
        assert config.command_timeout_seconds == 45, f"Expected 45, got {config.command_timeout_seconds}"
        assert config.fail_on_threat_enabled is False

        # Verify a section field still has its default
        assert config.cooldown.default_days == 7
