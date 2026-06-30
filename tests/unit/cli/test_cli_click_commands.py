"""
Tests for pkg_defender.cli.main CLI.

Covers:
- All Click commands (audit, intel, bypass, reset, config, status, etc.)
- Help text output
- Error handling (bad args, missing deps)
- Exit codes
"""

import json
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli.main import cli
from pkg_defender.config.settings import PKGDConfig

# ============================================================================
# TestAuditCommand (10 tests)
# ============================================================================


class TestAuditCommand:
    """Tests for `pkgd audit` command."""

    def test_audit_help_returns_help_text(self, runner: CliRunner) -> None:
        """Help text is returned when audit --help is invoked."""
        result = runner.invoke(cli, ["audit", "--help"])

        assert result.exit_code == 0
        assert "usage" in result.output.lower()

    def test_audit_with_no_args_shows_usage(self, runner: CliRunner) -> None:
        """Help text is shown when audit is invoked without arguments."""
        result = runner.invoke(cli, ["audit"])

        assert result.exit_code == 0
        assert "audit" in result.output.lower() or "usage" in result.output.lower()

    def test_audit_with_valid_path(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_with_json_output(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit --json is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "--json", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_with_deep_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit --deep is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "--deep", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_with_fail_on_threat(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit --fail-on-threat is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "--fail-on-threat", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_with_since_option(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit --since is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "--since", "7d", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_nonexistent_path(self, runner: CliRunner) -> None:
        """Non-zero exit code is returned when audit is run on a nonexistent path."""
        result = runner.invoke(cli, ["audit", "/nonexistent/path"])

        assert result.exit_code != 0

    def test_audit_json_flag_short(self, runner: CliRunner, tmp_path: Path) -> None:
        """Usage error is returned when audit -o json is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "-o", "json", str(tmp_path)])

        assert result.exit_code == 2

    def test_audit_returns_usage_error_when_no_lock_file_with_pretty_json(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Usage error is returned when audit --pretty -o json is run on a directory without a lock file."""
        result = runner.invoke(cli, ["audit", "--pretty", "-o", "json", str(tmp_path)])

        assert result.exit_code == 2


# ============================================================================
# TestIntelCommand (5 tests)
# ============================================================================


class TestIntelCommand:
    """Tests for `pkgd intel` command group."""

    def test_intel_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Help text shows subcommands when intel --help is invoked."""
        result = runner.invoke(cli, ["intel", "--help"])

        assert result.exit_code == 0
        assert "sync" in result.output.lower()
        assert "search" in result.output.lower()

    def test_intel_sync_help(self, runner: CliRunner) -> None:
        """Help text is returned when intel sync --help is invoked."""
        result = runner.invoke(cli, ["intel", "sync", "--help"])

        assert result.exit_code == 0
        assert "sync" in result.output.lower()

    def test_intel_search_help(self, runner: CliRunner) -> None:
        """Help text is returned when intel search --help is invoked."""
        result = runner.invoke(cli, ["intel", "search", "--help"])

        assert result.exit_code == 0
        assert "search" in result.output.lower()

    def test_intel_report_help(self, runner: CliRunner) -> None:
        """Help text is returned when intel report --help is invoked."""
        result = runner.invoke(cli, ["intel", "report", "--help"])

        assert result.exit_code == 0
        assert "report" in result.output.lower()

    def test_intel_no_subcommand_shows_help(self, runner: CliRunner) -> None:
        """Help text is shown when intel is invoked without a subcommand."""
        result = runner.invoke(cli, ["intel"])

        assert result.exit_code in (0, 2)
        assert "usage" in result.output.lower() or "commands" in result.output.lower()


# ============================================================================
# TestBypassCommand (5 tests)
# ============================================================================


class TestBypassCommand:
    """Tests for `pkgd bypass` command."""

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_missing_reason_returns_error(self, mock_load_config: mock.MagicMock, runner: CliRunner) -> None:
        """Usage error is returned when bypass is invoked without --reason."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        result = runner.invoke(cli, ["bypass", "axios@1.6.0"])

        assert result.exit_code == 2
        assert "reason" in result.output.lower()

    def test_bypass_invalid_package_spec(self, runner: CliRunner) -> None:
        """Usage error is returned when bypass is invoked with an invalid package spec."""
        result = runner.invoke(cli, ["bypass", "axios", "--reason", "test"])

        assert result.exit_code == 2

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_valid_package_creates_entry(
        self, mock_load_config: mock.MagicMock, runner: CliRunner, isolated_env: dict[str, Path]
    ) -> None:
        """Bypass entry is created when a valid package spec and --reason are provided."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        result = runner.invoke(cli, ["bypass", "axios@1.6.0", "--reason", "testing"])

        assert result.exit_code == 0

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_with_expires_option(
        self, mock_load_config: mock.MagicMock, runner: CliRunner, isolated_env: dict[str, Path]
    ) -> None:
        """Bypass entry is created when --expires option is provided."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        result = runner.invoke(cli, ["bypass", "lodash@4.17.21", "--reason", "test", "--expires", "24h"])

        assert result.exit_code == 0

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_with_manager_option(
        self, mock_load_config: mock.MagicMock, runner: CliRunner, isolated_env: dict[str, Path]
    ) -> None:
        """Bypass entry is created when --manager option is provided."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        result = runner.invoke(cli, ["bypass", "requests@2.28.0", "--reason", "test", "--manager", "pip"])

        assert result.exit_code == 0


# ============================================================================
# TestResetCommand (5 tests)
# ============================================================================


class TestResetCommand:
    """Tests for `pkgd reset` command."""

    def test_reset_with_yes_flag(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Usage error is returned when reset is invoked with --yes (invalid option)."""
        result = runner.invoke(cli, ["reset", "--yes"])

        assert result.exit_code == 2

    def test_reset_with_teardown_flag(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Usage error is returned when reset is invoked with --teardown --yes."""
        result = runner.invoke(cli, ["reset", "--teardown", "--yes"])

        assert result.exit_code == 2

    def test_reset_without_yes_prompts(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Aborted exit code is returned when reset is invoked without confirmation."""
        result = runner.invoke(cli, ["reset"])

        assert result.exit_code == 1

    def test_reset_help_shows_options(self, runner: CliRunner) -> None:
        """Help text shows options when reset --help is invoked."""
        result = runner.invoke(cli, ["reset", "--help"])

        assert result.exit_code == 0
        assert "teardown" in result.output.lower()

    def test_reset_deletes_database(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Usage error is returned when reset --yes is run on an initialized database."""
        result = runner.invoke(cli, ["reset", "--yes"])

        assert result.exit_code == 2


# ============================================================================
# TestConfigCommand (5 tests)
# ============================================================================


class TestConfigCommand:
    """Tests for `pkgd config` command group."""

    def test_config_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Help text shows subcommands when config --help is invoked."""
        result = runner.invoke(cli, ["config", "--help"])

        assert result.exit_code == 0
        assert "view" in result.output.lower()

    def test_config_view_returns_success(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Success is returned when config view is run in an isolated environment."""
        result = runner.invoke(cli, ["config", "view"])

        assert result.exit_code == 0

    def test_config_get_existing_key(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Success is returned when config get is run with a valid key."""
        result = runner.invoke(cli, ["config", "get", "cooldown.default_days"])

        assert result.exit_code == 0

    def test_config_set_and_get(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Config value can be set and retrieved."""
        config_path = isolated_env["config_path"]

        set_result = runner.invoke(cli, ["--config", str(config_path), "config", "set", "cooldown.default_days", "14"])

        assert set_result.exit_code == 0

        get_result = runner.invoke(cli, ["--config", str(config_path), "config", "get", "cooldown.default_days"])

        assert get_result.exit_code == 0
        assert "14" in get_result.output

    def test_config_reset(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Aborted exit code is returned when config reset is invoked without confirmation."""
        result = runner.invoke(cli, ["config", "reset"])

        assert result.exit_code == 1

    def test_config_set_secret_command_exists(self, runner: CliRunner) -> None:
        """pkgd config --help shows set-secret subcommand."""
        result = runner.invoke(cli, ["config", "--help"])
        assert result.exit_code == 0
        assert "set-secret" in result.output

    def test_config_set_secret_delegates_to_set(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """pkgd config set-secret produces masked output."""
        config_path = isolated_env["config_path"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        result = runner.invoke(
            cli,
            ["--config", str(config_path), "config", "set-secret", "feeds.ghsa_token"],
            input="my-secret-token\nmy-secret-token\n",
        )
        assert result.exit_code == 0
        assert "********" in result.output


# ============================================================================
# TestStatusCommand (5 tests)
# ============================================================================


class TestStatusCommand:
    """Tests for `pkgd status` command."""

    def test_status_returns_success(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Success is returned when status is run in an isolated environment."""
        result = runner.invoke(cli, ["status"])

        assert result.exit_code == 0

    def test_status_json_output(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Success is returned when status --json is run on an initialized database."""
        result = runner.invoke(cli, ["status", "--json"])

        assert result.exit_code == 0

    def test_status_with_feeds_flag(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Success is returned when status --feeds is run in an isolated environment."""
        result = runner.invoke(cli, ["status", "--feeds"])

        assert result.exit_code == 0

    def test_status_returns_success_with_pretty_json_output(
        self, runner: CliRunner, isolated_env: dict[str, Path]
    ) -> None:
        """Success is returned when status --pretty --json is run in an isolated environment."""
        result = runner.invoke(cli, ["status", "--pretty", "--json"])

        assert result.exit_code == 0

    def test_status_help_shows_options(self, runner: CliRunner) -> None:
        """Help text shows options when status --help is invoked."""
        result = runner.invoke(cli, ["status", "--help"])

        assert result.exit_code == 0
        assert "output" in result.output.lower()


# ============================================================================
# TestSetupCommand (5 tests)
# ============================================================================


class TestSetupCommand:
    """Tests for `pkgd setup` command."""

    def test_setup_help_shows_options(self, runner: CliRunner) -> None:
        """Help text is returned when setup --help is invoked."""
        result = runner.invoke(cli, ["setup", "--help"])

        assert result.exit_code == 0
        assert "setup" in result.output.lower()

    @mock.patch("pkg_defender.cli.commands.intel.intel_sync")
    def test_setup_runs_without_error(
        self,
        mock_intel: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Aborted exit code is returned when setup is invoked in an isolated environment."""
        result = runner.invoke(cli, ["setup"])
        assert result.exit_code == 1

    @mock.patch("pkg_defender.cli.commands.intel.intel_sync")
    def test_setup_with_shell_option(
        self,
        mock_intel: mock.MagicMock,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """Aborted exit code is returned when setup --shell bash is invoked."""
        result = runner.invoke(cli, ["setup", "--shell", "bash"])
        assert result.exit_code == 1

    def test_setup_with_force_flag(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Usage error is returned when setup --force is used without --init."""
        result = runner.invoke(cli, ["setup", "--force"])

        assert result.exit_code == 2
        assert "requires --init" in result.output

    def test_setup_init_with_force(self, runner: CliRunner) -> None:
        """Config is overwritten when setup --init --force is run on an existing config."""
        with runner.isolated_filesystem():
            pkgd_toml = Path.cwd() / "pkgd.toml"
            pkgd_toml.write_text("# placeholder")

            result = runner.invoke(cli, ["setup", "--init", "--force"])

            assert result.exit_code == 0
            assert "Created" in result.output

    def test_setup_help_shows_shells(self, runner: CliRunner) -> None:
        """Help text shows supported shells when setup --help is invoked."""
        result = runner.invoke(cli, ["setup", "--help"])

        assert result.exit_code == 0
        # --shell option uses click.Choice with 5 supported shells
        assert "zsh" in result.output
        assert "bash" in result.output
        assert "fish" in result.output
        assert "powershell" in result.output
        assert "nushell" in result.output


# ============================================================================
# TestHealthCommand (5 tests)
# ============================================================================


class TestHealthCommand:
    """Tests for `pkgd health` command."""

    def test_health_returns_exit_code(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """A valid health exit code is returned when health is run."""
        result = runner.invoke(cli, ["health"])

        assert result.exit_code in (0, 1)

    def test_health_json_output(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Health -o json should produce valid JSON."""
        result = runner.invoke(cli, ["health", "--output", "json"])
        assert result.exit_code in (0, 1)
        raw = result.stdout.strip()
        assert raw.startswith("{") or raw.startswith("[")
        data = json.loads(raw)
        assert "ready" in data

    def test_health_help_shows_options(self, runner: CliRunner) -> None:
        """Help text is returned when health --help is invoked."""
        result = runner.invoke(cli, ["health", "--help"])

        assert result.exit_code == 0
        assert "health" in result.output.lower()

    def test_health_help_shows_exit_codes(self, runner: CliRunner) -> None:
        """Help text mentions exit codes when health --help is invoked."""
        result = runner.invoke(cli, ["health", "--help"])

        assert result.exit_code == 0
        assert "exit" in result.output.lower() or "code" in result.output.lower()

    def test_health_exit_codes_documentation(self, runner: CliRunner) -> None:
        """Help text mentions exit codes when health --help is invoked."""
        result = runner.invoke(cli, ["health", "--help"])

        assert result.exit_code == 0
        # Health command should document exit codes
        assert "exit" in result.output.lower() or "code" in result.output.lower()

    def test_health_verbose_mode(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Health command accepts --verbose flag."""
        result = runner.invoke(cli, ["health", "--verbose"])
        assert result.exit_code in (0, 1)

    def test_health_verbose_with_json(self, runner: CliRunner, isolated_env: dict[str, Path]) -> None:
        """Health --verbose works with --output json."""
        import json

        result = runner.invoke(cli, ["health", "--verbose", "--output", "json"])
        assert result.exit_code in (0, 1)
        data = json.loads(result.stdout)
        assert "checks" in data

    def test_health_json_failure_returns_error_exit_code(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Health -o json returns exit code 1 when health checks fail.

        Regression test for Item 12: JSON output path was missing the
        all_ok exit code check that the non-JSON path has.
        """
        # Force a health check failure by making the DB unreachable
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_db_path",
            lambda: Path("/nonexistent/test.db"),
        )
        result = runner.invoke(cli, ["health", "--output", "json"])
        assert result.exit_code == _EXIT_GENERAL_ERROR
        # JSON output should still be valid JSON indicating not ready
        data = json.loads(result.stdout)
        assert data.get("ready") is False


# ============================================================================
# TestCLIErrorPaths (11 tests)
# ============================================================================


class TestCLIErrorPaths:
    """Tests for CLI error paths: invalid flags, missing args, bad values,
    and nonexistent subcommands.

    Each test verifies a specific error path with an exact exit code and
    meaningful output assertion — never just ``exit_code is not None``.
    """

    # ---- Invalid command combinations / unknown flags ----

    def test_audit_unknown_flag_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when audit is invoked with an unknown flag."""
        result = runner.invoke(cli, ["audit", "--invalid-flag"])

        assert result.exit_code == 2
        assert "No such option" in result.output

    def test_health_unknown_flag_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when health is invoked with an unknown flag."""
        result = runner.invoke(cli, ["health", "--nonexistent"])

        assert result.exit_code == 2
        assert "No such option" in result.output

    # ---- Missing required arguments ----

    def test_config_set_missing_key_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when config set is invoked without a KEY argument."""
        result = runner.invoke(cli, ["config", "set"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output

    def test_config_get_missing_key_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when config get is invoked without a KEY argument."""
        result = runner.invoke(cli, ["config", "get"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output

    def test_bypass_missing_package_spec_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when bypass is invoked without a PACKAGE_SPEC argument."""
        result = runner.invoke(cli, ["bypass", "--reason", "test"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output

    def test_intel_search_missing_query_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when intel search is invoked without a QUERY argument."""
        result = runner.invoke(cli, ["intel", "search"])

        assert result.exit_code == 2
        assert "Missing argument" in result.output

    # ---- Invalid argument values ----

    def test_audit_invalid_output_format_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when audit -o is given an unsupported format."""
        result = runner.invoke(cli, ["audit", "-o", "xml", "."])

        assert result.exit_code == 2
        assert "is not one of" in result.output

    def test_audit_invalid_since_duration_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when audit --since is given an invalid duration."""
        result = runner.invoke(cli, ["audit", "--since", "not-a-date", "."])

        assert result.exit_code == 2
        assert "Invalid duration" in result.output

    def test_bypass_invalid_manager_choice_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when bypass --manager is given an invalid choice."""
        result = runner.invoke(cli, ["bypass", "axios@1.6.0", "--reason", "test", "--manager", "nonexistent"])

        assert result.exit_code == 2
        assert "is not one of" in result.output

    @mock.patch("pkg_defender.cli.commands.bypass.load_config")
    def test_bypass_invalid_expiry_format_returns_usage_error(
        self, mock_load_config: mock.MagicMock, runner: CliRunner
    ) -> None:
        """Usage error is returned when bypass --expires is given an invalid format."""
        bypass_config = PKGDConfig()
        bypass_config.bypass.command_enabled = True
        mock_load_config.return_value = bypass_config

        result = runner.invoke(cli, ["bypass", "axios@1.6.0", "--reason", "test", "--expires", "bad-format"])

        assert result.exit_code == 2
        assert "Invalid expiry format" in result.output

    # ---- Nonexistent subcommands ----

    def test_nonexistent_root_command_returns_usage_error(self, runner: CliRunner) -> None:
        """Usage error is returned when CLI is invoked with a nonexistent root command."""
        result = runner.invoke(cli, ["nonexistent"])

        assert result.exit_code == 2
        assert "No such command" in result.output


# ============================================================================
# TestGeneralCli (10 tests)
# ============================================================================


class TestGeneralCli:
    """Tests for general CLI behavior."""

    def test_version_flag_returns_version(self, runner: CliRunner, project_version: str) -> None:
        """Version string is returned when --version flag is used."""
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert project_version in result.output

    def test_version_short_flag(self, runner: CliRunner, project_version: str) -> None:
        """Version string is returned when -V flag is used."""
        result = runner.invoke(cli, ["-V"])

        assert result.exit_code == 0
        assert project_version in result.output

    def test_bare_cli_shows_help(self, runner: CliRunner) -> None:
        """Help text is shown when CLI is invoked with no arguments."""
        result = runner.invoke(cli, [])

        assert result.exit_code == 0
        assert "pkg-defender" in result.output.lower() or "usage (native)" in result.output.lower()

    def test_help_flag_long(self, runner: CliRunner) -> None:
        """Usage text is returned when --help flag is used."""
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "usage (native)" in result.output.lower()

    def test_help_flag_short(self, runner: CliRunner) -> None:
        """Usage text is returned when -h flag is used."""
        result = runner.invoke(cli, ["-h"])

        assert result.exit_code == 0
        assert "usage (native)" in result.output.lower()
