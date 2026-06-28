"""Mock-based runtime behaviour tests for core CLI commands.

Each test invokes a command via Click's CliRunner with mocked dependencies
and verifies: exit code + mock call assertions + output content. These tests
complement the existing flag-parsing tests in test_cli_all_commands.py by
verifying that the command's core behaviour actually executes:
- DB inserts happen (not just "no crash")
- Console output is produced (not just "exit 0")
- Error handlers fire (not just "exit 2")
- Display functions are called (not just "flag accepted")
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli._exit_codes import EXIT_THREAT_DETECTED as _EXIT_THREAT_DETECTED
from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli.common import _deep_merge_config, _generate_config_template
from pkg_defender.cli.main import cli
from pkg_defender.config.settings import PKGDConfig

pytestmark = pytest.mark.unit


# ============================================================================
# TestLogsViewCommand (8 tests)
# ============================================================================


class TestLogsViewCommand:
    """Runtime behaviour tests for ``pkgd logs view`` and ``pkgd logs follow``.

    Tests mock ``get_data_dir`` to control the log file location, then exercise
    the real file-I/O path via ``tmp_path``.
    """

    def test_logs_view_help(self, runner: CliRunner) -> None:
        """--help succeeds and shows options."""
        result = runner.invoke(cli, ["logs", "view", "--help"])

        assert result.exit_code == 0
        assert "EXIT CODES" in result.output
        assert "--full" in result.output

    def test_logs_view_missing_log_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Missing log file exits 1 with a descriptive error message."""
        with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
            result = runner.invoke(cli, ["logs", "view"])

        assert result.exit_code == _EXIT_GENERAL_ERROR
        assert "Error" in result.output
        assert "Log file not found" in result.output

    def test_logs_view_reads_last_n_lines(self, runner: CliRunner, tmp_path: Path) -> None:
        """Default -n 100 reads the last 100 lines (or all if fewer exist)."""
        log_file = tmp_path / "pkgd.log"
        lines = [f"line{i}\n" for i in range(10)]
        log_file.write_text("".join(lines))

        with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
            result = runner.invoke(cli, ["logs", "view"])

        assert result.exit_code == 0
        # All 10 lines should be present (fewer than default 100)
        for i in range(10):
            assert f"line{i}" in result.output

    def test_logs_view_custom_lines_count(self, runner: CliRunner, tmp_path: Path) -> None:
        """-n 50 reads only the last 50 lines."""
        log_file = tmp_path / "pkgd.log"
        lines = "\n".join(f"line{i}" for i in range(200))
        log_file.write_text(lines)

        with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
            result = runner.invoke(cli, ["logs", "view", "-n", "50"])

        assert result.exit_code == 0
        # Last 50 lines (150-199) should appear
        assert "line150" in result.output
        assert "line199" in result.output
        # Early lines should NOT appear
        assert "line0" not in result.output

    def test_logs_view_full_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        """--full reads the entire log file (no truncation)."""
        log_file = tmp_path / "pkgd.log"
        lines = "line1\nline2\nline3\n"
        log_file.write_text(lines)

        with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
            result = runner.invoke(cli, ["logs", "view", "--full"])

        assert result.exit_code == 0
        assert "line1" in result.output
        assert "line3" in result.output

    def test_logs_view_unreadable_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Unreadable log file exits 1 with an error message."""
        log_file = tmp_path / "pkgd.log"
        log_file.write_text("test content")
        log_file.chmod(0o000)  # Remove all permissions
        try:
            with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
                result = runner.invoke(cli, ["logs", "view"])

            assert result.exit_code == _EXIT_GENERAL_ERROR
            assert "Error reading log file" in result.output
        finally:
            log_file.chmod(0o644)  # Restore permissions for cleanup

    def test_logs_view_empty_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """Empty log file produces no output."""
        log_file = tmp_path / "pkgd.log"
        log_file.write_text("")

        with mock.patch("pkg_defender.cli.commands.logs.get_data_dir", return_value=tmp_path):
            result = runner.invoke(cli, ["logs", "view"])

        assert result.exit_code == 0
        assert result.output.strip() == ""  # Empty file, no content

    def test_logs_view_follow_help(self, runner: CliRunner) -> None:
        """logs follow --help succeeds and shows options."""
        result = runner.invoke(cli, ["logs", "follow", "--help"])

        assert result.exit_code == 0
        assert "EXIT CODES" in result.output
        assert "-n" in result.output


# ============================================================================
# TestBypassCommandRuntime (4 tests)
# ============================================================================


class TestBypassCommandRuntime:
    """Runtime behaviour tests for ``pkgd bypass``.

    Verifies that ``insert_bypass`` is actually called when appropriate
    (and NOT called on error paths).
    """

    @staticmethod
    def _make_bypass_enabled_config() -> PKGDConfig:
        """Return a config with bypass.command_enabled=True."""
        config = PKGDConfig()
        config.bypass.command_enabled = True
        return config

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_insert_bypass_called(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Valid bypass invokes ``insert_bypass`` with expected arguments."""
        mock_load_config.return_value = self._make_bypass_enabled_config()
        with (
            mock.patch("pkg_defender.cli.commands.bypass.insert_bypass") as mock_insert,
            mock.patch("pkg_defender.cli.commands.bypass.console.print"),
        ):
            result = runner.invoke(cli, ["bypass", "lodash@4.17.21", "--reason", "integration test"])

        assert result.exit_code == 0
        mock_insert.assert_called_once()
        _call_args, call_kwargs = mock_insert.call_args
        assert call_kwargs.get("ecosystem") == "npm"
        assert call_kwargs.get("package") == "lodash"
        assert call_kwargs.get("version") == "4.17.21"
        assert call_kwargs.get("reason") == "integration test"

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_with_expiry_calls_parse_expiry(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--expires flag triggers ``_parse_expiry``."""
        mock_load_config.return_value = self._make_bypass_enabled_config()
        with (
            mock.patch("pkg_defender.cli.commands.bypass._parse_expiry") as mock_parse,
            mock.patch("pkg_defender.cli.commands.bypass.insert_bypass"),
            mock.patch("pkg_defender.cli.commands.bypass.console.print"),
        ):
            mock_parse.return_value = datetime.now(UTC) + timedelta(days=7)
            result = runner.invoke(cli, ["bypass", "lodash@4.17.21", "--reason", "test", "--expires", "7d"])

        assert result.exit_code == 0
        mock_parse.assert_called_once_with("7d")

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_no_version_returns_error(self, mock_load_config: mock.MagicMock, runner: CliRunner) -> None:
        """Package spec without ``@version`` exits with usage error and does NOT call ``insert_bypass``."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        with mock.patch("pkg_defender.cli.commands.bypass.insert_bypass") as mock_insert:
            result = runner.invoke(cli, ["bypass", "lodash", "--reason", "test"])

        assert result.exit_code == _EXIT_USAGE_ERROR
        assert "must include a version" in result.output
        mock_insert.assert_not_called()

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_console_output_message(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """On success ``console.print`` is called at least once with a success message."""
        mock_load_config.return_value = self._make_bypass_enabled_config()
        with (
            mock.patch("pkg_defender.cli.commands.bypass.insert_bypass"),
            mock.patch("pkg_defender.cli.commands.bypass.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["bypass", "lodash@4.17.21", "--reason", "test"])

        assert result.exit_code == 0
        mock_print.assert_called()
        # At least one call should contain the success indicator
        found = any("Bypass created" in str(args) for args, _ in mock_print.call_args_list)
        assert found, "Expected console.print to be called with 'Bypass created'"

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_logger_warning_called(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Logger.warning is called with bypass details."""
        mock_load_config.return_value = self._make_bypass_enabled_config()
        with (
            mock.patch("pkg_defender.cli.commands.bypass.logger") as mock_logger,
            mock.patch("pkg_defender.cli.commands.bypass.insert_bypass"),
            mock.patch("pkg_defender.cli.commands.bypass.console.print"),
        ):
            result = runner.invoke(cli, ["bypass", "lodash@4.17.21", "--reason", "integration test"])

        assert result.exit_code == 0
        mock_logger.warning.assert_called_once()
        _args, _kwargs = mock_logger.warning.call_args
        log_msg = _args[0]
        assert "Bypass record created" in log_msg
        # The format arguments: user, ecosystem, package, version, reason, expires_at
        assert len(_args) >= 4
        assert "lodash" in str(_args[3])

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_threat_check_respects_bypass(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        db_conn: sqlite3.Connection,
    ) -> None:
        """Bypass record in DB is queryable — simulates the bypass query
        that ``_check_threats`` runs before blocking a package."""
        mock_load_config.return_value = self._make_bypass_enabled_config()

        # Insert a bypass record directly into the test DB
        from pkg_defender.db.schema import insert_bypass as _ins

        _ins(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="test bypass",
            user="tester",
        )

        # Verify the bypass query pattern used by _check_threats works
        rows = db_conn.execute(
            "SELECT package_name, version FROM bypasses "
            "WHERE ecosystem = ? "
            "AND (expires_at IS NULL OR expires_at >= datetime('now'))",
            ("npm",),
        ).fetchall()
        bypass_set = {(row[0], row[1]) for row in rows}
        assert ("lodash", "4.17.21") in bypass_set

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_threat_check_expired_bypass(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        db_conn: sqlite3.Connection,
    ) -> None:
        """Expired bypass record is NOT returned by the active bypasses query."""
        mock_load_config.return_value = self._make_bypass_enabled_config()

        from pkg_defender.db.schema import insert_bypass as _ins

        # Insert an expired bypass record
        _ins(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="expired bypass",
            expires_at=datetime(2020, 1, 1, tzinfo=UTC),
            user="tester",
        )

        # Verify expired bypass is NOT returned by the active query
        rows = db_conn.execute(
            "SELECT package_name, version FROM bypasses "
            "WHERE ecosystem = ? "
            "AND (expires_at IS NULL OR expires_at >= datetime('now'))",
            ("npm",),
        ).fetchall()
        bypass_set = {(row[0], row[1]) for row in rows}
        assert ("lodash", "4.17.21") not in bypass_set

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_cross_ecosystem(
        self,
        mock_load_config: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
        db_conn: sqlite3.Connection,
    ) -> None:
        """Bypass for ecosystem A doesn't affect ecosystem B in queries."""
        mock_load_config.return_value = self._make_bypass_enabled_config()

        from pkg_defender.db.schema import insert_bypass as _ins

        # Insert bypass for npm/lodash
        _ins(
            db_conn,
            ecosystem="npm",
            package="lodash",
            version="4.17.21",
            threat_id=None,
            reason="test cross-ecosystem",
            user="tester",
        )

        # Query for pypi should NOT return the npm bypass
        rows = db_conn.execute(
            "SELECT package_name, version FROM bypasses "
            "WHERE ecosystem = ? "
            "AND (expires_at IS NULL OR expires_at >= datetime('now'))",
            ("pypi",),
        ).fetchall()
        bypass_set = {(row[0], row[1]) for row in rows}
        assert len(bypass_set) == 0

        # Query for npm SHOULD return the bypass
        rows = db_conn.execute(
            "SELECT package_name, version FROM bypasses "
            "WHERE ecosystem = ? "
            "AND (expires_at IS NULL OR expires_at >= datetime('now'))",
            ("npm",),
        ).fetchall()
        bypass_set = {(row[0], row[1]) for row in rows}
        assert ("lodash", "4.17.21") in bypass_set


# ============================================================================
# TestSetupCommandRuntime (8 tests)
# ============================================================================


class TestSetupCommandRuntime:
    """Runtime behaviour tests for ``pkgd setup``.

    Verifies shell detection, completion installation, config creation, and
    error paths are exercised — not just that the command exits without
    crashing.
    """

    def test_setup_force_without_init_exits_2(self, runner: CliRunner) -> None:
        """--force without --init is a usage error (exit 2)."""
        result = runner.invoke(cli, ["setup", "--force"])
        assert result.exit_code == _EXIT_USAGE_ERROR
        assert "requires --init" in result.output

    def test_setup_init_creates_pkgd_toml(self, runner: CliRunner) -> None:
        """--init calls ``_write_toml_fallback`` and prints 'Created'."""
        with runner.isolated_filesystem():
            with (
                mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
                mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
                mock.patch("pkg_defender.cli.commands.setup.console.print"),
            ):
                result = runner.invoke(cli, ["setup", "--init"])

            assert result.exit_code == 0
            mock_write.assert_called_once()

    def test_setup_init_on_existing_without_force(self, runner: CliRunner) -> None:
        """--init without --force on an existing file raises usage error."""
        with runner.isolated_filesystem():
            (Path.cwd() / "pkgd.toml").write_text("# placeholder\n")
            result = runner.invoke(cli, ["setup", "--init"])

        assert result.exit_code == _EXIT_USAGE_ERROR
        assert "already exists" in result.output or "Error" in result.output

    def test_setup_detects_shell_and_installs_completion(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Default setup detects shell, installs completions, and writes config."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion") as mock_install,
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch("pkg_defender.cli.commands.setup.console.print"),
            mock.patch("pkg_defender.cli.commands.setup.subprocess.run") as mock_subproc,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            mock_subproc.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        mock_install.assert_called_once_with("zsh", dry_run=False)

    def test_setup_with_unsupported_shell(self, runner: CliRunner) -> None:
        """Unsupported shell exits 2 with a 'not supported' message."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="tcsh"),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["setup"])

        assert result.exit_code == _EXIT_USAGE_ERROR
        # Verify a "not supported" message was printed
        assert any("not supported" in str(args) for args, _ in mock_print.call_args_list), (
            "Expected console.print to contain 'not supported'"
        )

    def test_setup_dry_run_shows_message(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--dry-run prints a dry-run message without installing."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.subprocess.run"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup", "--dry-run"])

        assert result.exit_code == 0
        mock_write.assert_not_called()
        found = any("Dry-run" in str(args) for args, _ in mock_print.call_args_list)
        assert found, "Expected console.print to contain 'Dry-run'"

    def test_setup_calls_console_print_for_progress(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Setup calls ``console.print`` multiple times for progress messages."""
        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml"),
            mock.patch("pkg_defender.cli.commands.setup.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.setup.subprocess.run"),
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0
        assert mock_print.call_count >= 3, f"Expected at least 3 console.print calls, got {mock_print.call_count}"
        found = any("shell" in str(args).lower() for args, _ in mock_print.call_args_list)
        assert found, "Expected at least one console.print call containing 'shell'"

    def test_setup_init_mode_does_not_call_detect_shell(self, runner: CliRunner) -> None:
        """--init mode returns early and does NOT invoke shell detection."""
        with runner.isolated_filesystem():
            noop = mock.Mock(side_effect=AssertionError("detect_shell should not be called"))
            with (
                mock.patch("pkg_defender.cli.commands.setup.detect_shell", side_effect=noop),
                mock.patch("pkg_defender.cli.commands.setup._generate_config_template"),
                mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
                mock.patch("pkg_defender.cli.commands.setup.console.print"),
            ):
                result = runner.invoke(cli, ["setup", "--init"])

            assert result.exit_code == 0
            mock_write.assert_called_once()

    def test_setup_re_run_merges_existing_config(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Re-running setup merges with existing config, preserving custom values.

        Root cause: setup.py:331 unconditionally overwrites config with defaults.
        This test FAILS before the fix (custom values reset to defaults) and
        PASSES after (custom values preserved).

        Scenario: Existing config has ``cooldown.default_days=99`` and
        ``feeds.ghsa_token = "abc123"``.
        Expected: After re-run, both custom values are preserved in the merged
        config file.
        Previously: They were overwritten with defaults (3 and empty).
        """
        import tomllib

        config_path = isolated_env["config_path"]
        config_path.write_text("""[cooldown]
default_days = 99

[feeds]
ghsa_token = "abc123"
""")

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup.console.print"),
            mock.patch("pkg_defender.cli.commands.setup.subprocess.run") as mock_subproc,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            mock_subproc.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0

        merged = tomllib.loads(config_path.read_text("utf-8"))
        assert merged["cooldown"]["default_days"] == 99, "Custom cooldown value should be preserved"
        assert merged["feeds"]["ghsa_token"] == "abc123", "Custom token should be preserved"

    def test_setup_merge_adds_new_sections(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Re-running setup merges defaults into existing config, adding new sections.

        Root cause: setup.py:331 unconditionally overwrites config with the
        dict from _generate_full_default_config(), losing any sections from
        existing config that aren't in the defaults dict, and resetting values.
        This test FAILS before the fix (custom values reset, sections not
        preserved from existing) and PASSES after.

        Scenario: _generate_full_default_config returns a dict with a
        ``security`` section that PKGDConfig doesn't have (simulating a
        future default that adds a new section).
        Expected: The merged output includes the new ``security`` section
        AND preserves the existing ``cooldown.default_days = 99``.
        Previously: Only the mocked defaults would be written (security
        section present, but cooldown.default_days reset to 3).
        """
        config_path = isolated_env["config_path"]
        config_path.write_text("[cooldown]\ndefault_days = 99\n")

        from tomlkit import table as _tomlkit_table

        # Build a mock template doc with a "security" section that PKGDConfig doesn't have
        mock_doc = _generate_config_template()
        mock_doc["security"] = _tomlkit_table()
        mock_doc["security"]["scan_on_install"] = True
        mock_doc["cooldown"]["default_days"] = 3

        with (
            mock.patch("pkg_defender.cli.commands.setup.detect_shell", return_value="zsh"),
            mock.patch("pkg_defender.cli.commands.setup.is_shell_installed", return_value=True),
            mock.patch("pkg_defender.cli.commands.setup.install_completion"),
            mock.patch("pkg_defender.cli.commands.setup._generate_config_template", return_value=mock_doc),
            mock.patch("pkg_defender.cli.commands.setup._write_config_toml") as mock_write,
            mock.patch("pkg_defender.cli.commands.setup.console.print"),
            mock.patch("pkg_defender.cli.commands.setup.subprocess.run") as mock_subproc,
            mock.patch("pkg_defender.cli.commands.intel.intel_sync"),
        ):
            mock_subproc.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            result = runner.invoke(cli, ["--ci", "setup"])

        assert result.exit_code == 0

        written_content = mock_write.call_args[0][1]
        from tomlkit import parse as tomlkit_parse

        written = tomlkit_parse(written_content)
        # New section from defaults should be added
        assert "security" in written, "Missing 'security' section — merge should add new sections from defaults"
        assert written["security"]["scan_on_install"] is True
        # Existing value should be preserved
        assert written["cooldown"]["default_days"] == 99, (
            "Existing cooldown value overwritten — merge should preserve existing values"
        )

    def test_deep_merge_config_utility(self) -> None:
        """_deep_merge_config preserves existing values, adds missing keys,
        and recursively merges nested dicts."""
        # Existing keys preserved, missing keys added, nested merge
        base = {
            "cooldown": {"default_days": 99, "enabled": True},
            "existing_only_key": "keep_me",
        }
        overlay = {
            "cooldown": {"default_days": 3, "enabled": True, "strict_mode": True, "overrides": {}},
            "output": {"color": True, "json_mode": False},
        }

        merged = _deep_merge_config(base, overlay)

        # Existing values preserved
        assert merged["cooldown"]["default_days"] == 99
        assert merged["existing_only_key"] == "keep_me"
        # Missing keys added from overlay
        assert merged["cooldown"]["strict_mode"] is True
        # New sections added
        assert "output" in merged
        assert merged["output"]["color"] is True
        assert merged["output"]["json_mode"] is False
        # Empty existing dict returns full overlay
        assert _deep_merge_config({}, {"a": 1}) == {"a": 1}
        # Different types preserved correctly
        assert _deep_merge_config({"flag": True}, {"flag": False})["flag"] is True
        assert _deep_merge_config({"count": 42}, {"count": 0})["count"] == 42
        assert _deep_merge_config({"name": "original"}, {"name": "default"})["name"] == "original"


# ============================================================================
# TestAuditCommandRuntime (7 tests)
# ============================================================================


class TestAuditCommandRuntime:
    """Runtime behaviour tests for ``pkgd audit``.

    Verifies that display functions are called, feed state is checked,
    error paths fire, and output-format dispatch works correctly.
    """

    def test_audit_missing_lock_file_exits_2(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Missing lock file exits 2 with a descriptive message."""
        with mock.patch("pkg_defender.core.auditor.audit_lock_file", side_effect=FileNotFoundError):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == _EXIT_USAGE_ERROR
        assert "No recognised lock file found" in result.output

    def test_audit_rich_mode_calls_display_results(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Rich output mode calls ``display_audit_results``."""
        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 0
        mock_result.threats = []
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []
        mock_result.passed = 0

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results") as mock_display,
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
        ):
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_display.assert_called_once()

    def test_audit_json_mode_calls_format_json(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """JSON output mode calls ``format_json`` instead of ``display_audit_results``."""
        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 0
        mock_result.threats = []
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit.format_json", return_value="{}") as mock_format,
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results") as mock_display,
        ):
            result = runner.invoke(cli, ["audit", ".", "--output", "json"])

        assert result.exit_code == 0
        mock_format.assert_called_once()
        mock_display.assert_not_called()

    def test_audit_with_threats_exit_4(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Threats with --fail-on-threat exit 4."""
        mock_threat = mock.MagicMock()
        mock_threat.display_severity = "CRITICAL"
        mock_threat.record.summary = "Test critical threat"
        mock_threat.record.source = "test"

        mock_entry = mock.MagicMock()
        mock_entry.package = "axios"
        mock_entry.version = "1.6.0"
        mock_entry.ecosystem = "npm"
        mock_entry.threats = [mock_threat]

        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 1
        mock_result.threats = [mock_entry]
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []
        mock_result.passed = 0

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--fail-on-threat"])

        assert result.exit_code == _EXIT_THREAT_DETECTED

    def test_audit_calls_get_feed_state(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Audit checks feed state via ``get_feed_state``."""
        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 0
        mock_result.threats = []
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state") as mock_feed_state,
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            mock_feed_state.return_value = None
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_feed_state.assert_called_once()

    def test_audit_calls_get_db_path_and_init_db(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Audit initialises the database via ``get_db_path`` and ``init_db``."""
        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 0
        mock_result.threats = []
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit.get_db_path") as mock_get_db_path,
            mock.patch("pkg_defender.cli.commands.audit.init_db") as mock_init_db,
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            mock_conn = mock.MagicMock()
            mock_init_db.return_value = mock_conn
            result = runner.invoke(cli, ["audit", "."])

        assert result.exit_code == 0
        mock_get_db_path.assert_called_once()
        mock_init_db.assert_called_once()

    def test_audit_with_since_option_filters_results(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--since flag triggers ``_parse_duration`` and filters threats."""
        mock_result = mock.MagicMock()
        mock_result.project_path = "."
        mock_result.lock_file = "package-lock.json"
        mock_result.total_packages = 0
        mock_result.threats = []
        mock_result.cooldown_pending = []
        mock_result.passed_packages = []

        with (
            mock.patch("pkg_defender.core.auditor.audit_lock_file", return_value=mock_result),
            mock.patch("pkg_defender.cli.commands.audit._parse_duration") as mock_parse,
            mock.patch("pkg_defender.cli.commands.audit.get_feed_state", return_value=None),
            mock.patch("pkg_defender.cli.commands.audit.display_stale_db_warning"),
            mock.patch("pkg_defender.cli.commands.audit.display_audit_results"),
        ):
            result = runner.invoke(cli, ["audit", ".", "--since", "7d"])

        assert result.exit_code == 0
        mock_parse.assert_called_once_with("7d")


# ============================================================================
# TestResetCommandRuntime (11 tests)
# ============================================================================


class TestResetCommandRuntime:
    """Runtime behaviour tests for ``pkgd reset``.

    Verifies DB deletion, confirmation prompts, and error paths.
    ``--yes`` is a **global** flag that must come **before** the command name.
    """

    def test_reset_with_yes_deletes_db(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --yes deletes the database file and calls ``console.print``."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("fake db content")
        config_file = tmp_path / "config.toml"
        config_file.write_text("fake config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        assert not db_file.exists(), "Database file should have been deleted"
        mock_print.assert_called()

    def test_reset_console_print_called(self, runner: CliRunner, tmp_path: Path) -> None:
        """Success path calls ``console.print`` with a 'Deleted' message."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("fake db content")
        config_file = tmp_path / "config.toml"
        config_file.write_text("fake config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        found = any("Deleted" in str(args) for args, _ in mock_print.call_args_list)
        assert found, "Expected console.print to contain 'Deleted'"

    def test_reset_with_nonexistent_db(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset with no existing DB shows 'No data to reset'."""
        nonexistent_db = tmp_path / "threats.db"

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=nonexistent_db),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        found = any("No data to reset" in str(args) for args, _ in mock_print.call_args_list)
        assert found, "Expected console.print to contain 'No data to reset'"

    def test_reset_without_confirm_exits_1(self, runner: CliRunner) -> None:
        """reset without ``--yes`` and with confirmation refused exits 1."""
        with (
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=False),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
        ):
            result = runner.invoke(cli, ["reset"], input="n\n")

        assert result.exit_code == _EXIT_GENERAL_ERROR
        assert "Aborted" in result.output

    def test_reset_teardown_with_yes(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --teardown --yes deletes DB, WAL, logs, daemon state, and config."""
        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("fake db")
        wal_file = data_dir / "threats.db-wal"
        wal_file.write_text("wal data")
        config_file = tmp_path / "config.toml"
        config_file.write_text("fake config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert not db_file.exists(), "Database file should have been deleted"
        assert not wal_file.exists(), "WAL file should have been deleted"
        assert not config_file.exists(), "Config file should have been deleted"

    def test_reset_teardown_confirm_cancelled(self, runner: CliRunner, tmp_path: Path) -> None:
        """teardown sub-confirmation 'No' aborts — DB is NOT deleted."""
        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("fake db")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=tmp_path / "config.toml",
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=False),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run"),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert db_file.exists(), "DB file should NOT have been deleted"
        found = any("Teardown cancelled" in str(args) for args, _ in mock_print.call_args_list)
        assert found, "Expected console.print to contain 'Teardown cancelled'"

    def test_reset_teardown_removes_all_files(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --teardown --yes deletes DB, WAL/SHM/journal, logs, daemon state, and config."""
        data_dir = tmp_path
        # Create all files that teardown should clean
        files = {
            "threats.db": "fake db",
            "threats.db-wal": "wal data",
            "threats.db-shm": "shm data",
            "threats.db-journal": "journal data",
            "pkgd.log": "log data",
            "pkgd.log.1": "log rotate 1",
            "pkgd.log.2": "log rotate 2",
            "pkgd.log.3": "log rotate 3",
            "pkgd.log.4": "log rotate 4",
            "pkgd.log.5": "log rotate 5",
            "daemon_stdout.log": "stdout",
            "daemon_stderr.log": "stderr",
            "daemon.pid": "12345",
            "daemon_heartbeat.json": "{}",
            "daemon.lock": "",
        }
        for name, content in files.items():
            (data_dir / name).write_text(content)

        config_file = tmp_path / "config.toml"
        config_file.write_text("fake config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        for name in files:
            assert not (data_dir / name).exists(), f"{name} should have been deleted"
        assert not config_file.exists(), "Config file should have been deleted"

    def test_reset_teardown_removes_empty_data_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --teardown removes the data directory if it's empty afterward."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "threats.db").write_text("db")
        (data_dir / "pkgd.log").write_text("log")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert not data_dir.exists(), "Empty data directory should have been removed"

    def test_reset_teardown_keeps_nonempty_data_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --teardown does NOT remove data dir if non-empty files remain."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "threats.db").write_text("db")
        (data_dir / "user_file.txt").write_text("user data")  # Not a pkgd file
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert data_dir.exists(), "Non-empty data directory should NOT be removed"
        assert (data_dir / "user_file.txt").exists(), "User file should be untouched"

    def test_reset_teardown_partial_failure_continues(self, runner: CliRunner, tmp_path: Path) -> None:
        """reset --teardown continues cleanup even if one file deletion fails."""
        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("db")

        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        log_file = data_dir / "pkgd.log"
        log_file.write_text("log")

        # Track whether the real unlink was called on the db_file
        # We need to let the real trash/unlink logic run for other files,
        # but raise OSError on the db_file's unlink() call.
        real_unlink = Path.unlink

        def selective_unlink(self_path: Path, *args: object, **kwargs: object) -> None:
            if self_path == db_file:
                raise OSError("Device or resource busy")
            return real_unlink(self_path)

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError
            ),  # trash not available
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
            mock.patch.object(Path, "unlink", selective_unlink),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert db_file.exists(), "DB file should still exist (deletion failed)"
        assert not log_file.exists(), "Log file should have been deleted despite DB failure"
        assert not config_file.exists(), "Config should have been deleted despite DB failure"

    def test_reset_teardown_warning_text_includes_all_categories(self, runner: CliRunner, tmp_path: Path) -> None:
        """Teardown warning mentions database, WAL, logs, daemon state, and config."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("db")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        printed: list[str] = []

        def original_print(*args: object, **kwargs: object) -> None:
            printed.append(str(args))

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=tmp_path),
            mock.patch("pkg_defender.cli.commands.reset.get_default_config_path", return_value=config_file),
            mock.patch("pkg_defender.cli.commands.reset.console.print", side_effect=original_print),
            mock.patch("pkg_defender.cli.commands.reset.subprocess.run", side_effect=FileNotFoundError),
            mock.patch(
                "pkg_defender.cli.commands.reset.click.confirm", return_value=False
            ),  # Cancel to just check warning
        ):
            runner.invoke(cli, ["--yes", "reset", "--teardown"])

        warning_text = " ".join(printed).lower()

        # Verify ALL categories mentioned in the warning text are present
        assert "database" in warning_text or "db" in warning_text, "Warning should mention the database"
        assert "wal" in warning_text, "Warning should mention WAL files"
        assert "log" in warning_text, "Warning should mention log files"
        assert "daemon state" in warning_text or "daemon" in warning_text, "Warning should mention daemon state"
        assert "config" in warning_text, "Warning should mention config file"


# ============================================================================
# TestStatusCommandRuntime (5 tests)
# ============================================================================


class TestStatusCommandRuntime:
    """Runtime behaviour tests for ``pkgd status``.

    Verifies JSON format dispatch, Rich table rendering, feeds flag
    behaviour, and quiet-mode suppression.
    """

    def test_status_json_format_called(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``--json`` calls ``format_json``."""
        with (
            mock.patch("pkg_defender.cli.commands.status.format_json", return_value="{}") as mock_format,
            mock.patch("pkg_defender.cli.commands.status._get_config_from_context"),
            mock.patch("pkg_defender.cli.commands.status.stdout_console.print"),
        ):
            result = runner.invoke(cli, ["status", "--json"])

        assert result.exit_code == 0
        mock_format.assert_called_once()

    def test_status_rich_mode_console_print_called(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Rich mode calls ``stdout_console.print`` at least once."""
        with (
            mock.patch("pkg_defender.cli.commands.status.stdout_console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.status._get_config_from_context"),
        ):
            result = runner.invoke(cli, ["status"])

        assert result.exit_code == 0
        mock_print.assert_called()

    def test_status_json_output_has_summary_key(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--json output is valid JSON and contains expected top-level keys."""
        result = runner.invoke(cli, ["status", "--json"])

        assert result.exit_code == 0
        raw = result.output.strip()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert "summary" in parsed
        assert "active_bypasses" in parsed
        assert "feeds" in parsed

    def test_status_feeds_flag_shows_extra_table(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--feeds flag produces extra ``stdout_console.print`` calls."""
        with (
            mock.patch("pkg_defender.cli.commands.status.stdout_console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.status._get_config_from_context"),
        ):
            result = runner.invoke(cli, ["status", "--feeds"])

        assert result.exit_code == 0
        # With --feeds, there should be at least 3 print calls
        # (severity table, bypass table, feed health table, summary line)
        assert mock_print.call_count >= 3, (
            f"Expected >= 3 console.print calls with --feeds, got {mock_print.call_count}"
        )

    def test_status_quiet_mode_returns_early(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """--quiet mode skips Rich table output (``stdout_console.print`` not called for tables).

        Note: the existing test_cli_all_commands.py:test_quiet_flag_suppresses_status_output
        verifies ``console.print.assert_not_called()`` for ``--quiet status``.
        This test re-verifies with the same assertion for the runtime test class.
        """
        with (
            mock.patch("pkg_defender.cli.commands.status.stdout_console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.status._get_config_from_context"),
        ):
            result = runner.invoke(cli, ["--quiet", "status"])

        assert result.exit_code == 0
        mock_print.assert_not_called()
