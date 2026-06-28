"""Tests for CLI exit code wiring."""

from __future__ import annotations


class TestExitCodeWiring:
    """Tests that each exit code is reachable from its trigger condition."""

    def test_general_error_exits_1(self) -> None:
        """A general error condition produces EXIT_GENERAL_ERROR (1)."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            # "health" in an isolated environment has no config and no DB,
            # producing EXIT_GENERAL_ERROR (1).
            result = runner.invoke(cli, ["health"])
            assert result.exit_code == 1

    def test_usage_error_exits_2(self) -> None:
        """Invalid arguments produce EXIT_USAGE_ERROR (2)."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["audit", "--unknown-flag"])
            assert result.exit_code == 2

    def test_config_error_exits_6(self) -> None:
        """An invalid config key produces EXIT_CONFIG_ERROR (6)."""
        from click.testing import CliRunner

        from pkg_defender.cli.main import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            # "config get invalid.key" triggers _validate_config_key which
            # raises SystemExit(EXIT_CONFIG_ERROR) for unknown sections.
            result = runner.invoke(cli, ["config", "get", "invalid.key"])
            assert result.exit_code == 6


class TestExitCodeConstants:
    """Tests for exit code constant definitions."""

    def test_exit_codes_are_distinct(self) -> None:
        """All 9 exit code constants have unique values."""
        from pkg_defender.cli._exit_codes import (
            EXIT_CONFIG_ERROR,
            EXIT_COOLDOWN,
            EXIT_DB_ERROR,
            EXIT_GENERAL_ERROR,
            EXIT_PARTIAL_FAILURE,
            EXIT_REGISTRY_UNREACHABLE,
            EXIT_SIGINT,
            EXIT_SUCCESS,
            EXIT_THREAT_DETECTED,
            EXIT_USAGE_ERROR,
        )

        codes = {
            EXIT_SUCCESS,
            EXIT_GENERAL_ERROR,
            EXIT_USAGE_ERROR,
            EXIT_COOLDOWN,
            EXIT_THREAT_DETECTED,
            EXIT_REGISTRY_UNREACHABLE,
            EXIT_CONFIG_ERROR,
            EXIT_DB_ERROR,
            EXIT_PARTIAL_FAILURE,
            EXIT_SIGINT,
        }
        assert len(codes) == 10

    def test_general_error_not_confused_with_usage(self) -> None:
        """EXIT_GENERAL_ERROR (1) and EXIT_USAGE_ERROR (2) are distinct."""
        from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR, EXIT_USAGE_ERROR

        assert EXIT_GENERAL_ERROR == 1
        assert EXIT_USAGE_ERROR == 2
        assert EXIT_GENERAL_ERROR != EXIT_USAGE_ERROR

    def test_exit_codes_have_messages(self) -> None:
        """All exit codes have messages in EXIT_CODE_DESCRIPTIONS."""
        from pkg_defender.cli._exit_codes import (
            EXIT_CODE_DESCRIPTIONS,
            EXIT_CONFIG_ERROR,
            EXIT_COOLDOWN,
            EXIT_DB_ERROR,
            EXIT_GENERAL_ERROR,
            EXIT_PARTIAL_FAILURE,
            EXIT_REGISTRY_UNREACHABLE,
            EXIT_SIGINT,
            EXIT_SUCCESS,
            EXIT_THREAT_DETECTED,
            EXIT_USAGE_ERROR,
        )

        all_codes = {
            EXIT_SUCCESS,
            EXIT_GENERAL_ERROR,
            EXIT_USAGE_ERROR,
            EXIT_COOLDOWN,
            EXIT_THREAT_DETECTED,
            EXIT_REGISTRY_UNREACHABLE,
            EXIT_CONFIG_ERROR,
            EXIT_DB_ERROR,
            EXIT_PARTIAL_FAILURE,
            EXIT_SIGINT,
        }
        for code in all_codes:
            assert code in EXIT_CODE_DESCRIPTIONS, f"Exit code {code} missing from EXIT_CODE_DESCRIPTIONS"


class TestNoRawExitCodeLiterals:
    """Ensure dispatcher.py uses named constants, not raw numeric literals."""

    def test_dispatcher_no_raw_exit_code_constants(self) -> None:
        """dispatcher.py does not contain raw SystemExit(1)."""
        from pathlib import Path

        dispatcher_path = Path(__file__).resolve().parents[3] / "src" / "pkg_defender" / "cli" / "dispatcher.py"
        content = dispatcher_path.read_text()

        # Should NOT contain raw SystemExit(1) — must use named constant
        assert "SystemExit(1)" not in content, "dispatcher.py contains raw SystemExit(1) — use EXIT_GENERAL_ERROR"

    def test_no_raw_exit_code_in_audit_events(self) -> None:
        """Audit events use named constants for exit_code parameter."""
        from pathlib import Path

        dispatcher_path = Path(__file__).resolve().parents[3] / "src" / "pkg_defender" / "cli" / "dispatcher.py"
        content = dispatcher_path.read_text()

        # Should NOT contain exit_code=1 or exit_code=2 in _log_audit_event calls
        assert "exit_code=1," not in content, "dispatcher.py audit event uses raw exit_code=1 — use named constant"
        assert "exit_code=2" not in content, "dispatcher.py audit event uses raw exit_code=2 — use named constant"


class TestDeadConstantsRemoved:
    """Dead exit constants removed from user_messages.py."""

    def test_user_messages_no_dead_exit_constants(self) -> None:
        """audit/user_messages.py does not define conflicting exit constants."""
        from pathlib import Path

        user_messages_path = Path(__file__).resolve().parents[3] / "src" / "pkg_defender" / "audit" / "user_messages.py"
        content = user_messages_path.read_text()

        assert "EXIT_FAIL_CLOSED" not in content, "Dead constant EXIT_FAIL_CLOSED found in user_messages.py"
        assert "EXIT_FAIL_CLOSED_CI" not in content, "Dead constant EXIT_FAIL_CLOSED_CI found in user_messages.py"
        assert "EXIT_BYPASS_WARNING" not in content, "Dead constant EXIT_BYPASS_WARNING found in user_messages.py"


class TestCommandGroupExitPattern:
    """Command group handlers use ctx.exit(0), not sys.exit(0)."""

    def test_no_sys_exit_in_group_handlers(self) -> None:
        """Group handler files do not use sys.exit(0)."""
        from pathlib import Path

        commands_dir = Path(__file__).resolve().parents[3] / "src" / "pkg_defender" / "cli" / "commands"
        for name in ("daemon.py", "config.py", "intel.py"):
            content = (commands_dir / name).read_text()
            assert "sys.exit(0)" not in content, f"{name} uses sys.exit(0) — use ctx.exit(0) for Click context teardown"
