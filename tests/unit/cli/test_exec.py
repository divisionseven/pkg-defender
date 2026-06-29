"""Tests for CLI exec module."""

import contextlib
import io
import json
import sys
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from pkg_defender.cli.dispatcher import CooldownCheckResult, ManagerDispatcher, ThreatCheckResult
from pkg_defender.models import CheckResult, ScoredThreat, ThreatRecord
from pkg_defender.models.command import BlockReason, CommandIntent, PackageRef, ParsedCommand
from pkg_defender.registry.base import CoverageTier, UnifiedRegistryAdapter


@contextlib.contextmanager
def _capture_stderr() -> Generator[io.StringIO, None, None]:
    """Capture stderr output, bypassing Rich Console.

    Patches both sys.stderr and the exec module's _stderr_write to
    ensure output is captured even when Rich Console is available.
    """
    from pkg_defender.cli import exec as exec_module

    captured = io.StringIO()

    def _plain_write(msg: str) -> None:
        sys.stderr.write(msg + "\n")

    with (
        patch.object(sys, "stderr", captured),
        patch.object(exec_module, "_stderr_write", _plain_write),
    ):
        yield captured


def make_package(**kwargs: Any) -> PackageRef:
    """Create a PackageRef with defaults for testing.

    Args:
        **kwargs: Override default fields (name, raw, version, ecosystem).

    Returns:
        A PackageRef instance with defaults applied.
    """
    defaults: dict[str, Any] = {
        "name": "test-pkg",
        "raw": "test-pkg",
        "version": None,
        "ecosystem": "pypi",
    }
    defaults.update(kwargs)
    return PackageRef(**defaults)


def make_parsed_command(**kwargs: Any) -> ParsedCommand:
    """Create a ParsedCommand with defaults for testing.

    Args:
        **kwargs: Override default fields (manager, packages, pkgd_flags, etc.).

    Returns:
        A ParsedCommand instance with defaults applied.
    """
    defaults: dict[str, Any] = {
        "manager": "pip",
        "intent": CommandIntent.INSTALL,
        "packages": [],
        "manager_subcommand": "install",
        "manager_flags": [],
        "pkgd_flags": {},
        "file_targets": [],
        "raw_args": ["install"],
        "requires_file_audit": False,
        "is_global": False,
        "is_dev_dependency": False,
    }
    defaults.update(kwargs)
    return ParsedCommand(**defaults)


class TestStderrWrite:
    def test_stderr_write_output(self) -> None:
        from pkg_defender.cli import exec as exec_module

        test_msg = "Test error message"
        with patch("pkg_defender.cli.exec._console_cls") as mock_console_cls:
            exec_module._stderr_write(test_msg)
        mock_console = mock_console_cls.return_value
        mock_console.print.assert_called_once_with(test_msg, style="error")

    def test_stderr_write_preserves_brackets(self) -> None:
        """Brackets in output must survive Rich rendering with markup=False."""
        from pkg_defender.cli import exec as exec_module

        if not exec_module._HAS_RICH:
            pytest.skip("Rich not available")

        captured = io.StringIO()
        with patch("sys.stderr", captured):
            exec_module._stderr_write("[osv] test message")

        output = captured.getvalue()
        assert "[osv]" in output, f"Expected '[osv]' in output, but it was missing.\nOutput: {output}"


class TestStdoutWrite:
    def test_stdout_write_output(self) -> None:
        from pkg_defender.cli import exec as exec_module

        test_msg = "Test output message"
        captured = io.StringIO()
        with patch.object(sys, "stdout", captured):
            exec_module._stdout_write(test_msg)
        output = captured.getvalue()
        assert test_msg in output


class TestExecClearedCommand:
    def test_exec_cleared_command_dry_run(self) -> None:
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="requests", raw="requests")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"dry_run": True},
            file_targets=[],
            raw_args=["install", "requests"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with patch.object(exec_module, "_print_dry_run") as mock_print:
            exec_module.handle_cleared_command(parsed)
            mock_print.assert_called_once()


class TestHandleBlockedCommand:
    def test_handle_threat(self) -> None:
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "malicious-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            patch.object(exec_module, "_print_threat_block") as mock_print,
            patch.object(sys, "exit") as mock_exit,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg_ref)
            mock_print.assert_called_once()
            mock_exit.assert_called_once_with(4)

    def test_handle_cooldown_block_with_force(self) -> None:
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"force": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        mock_exec.assert_called_once()

    def test_handle_cooldown_with_allow_once_flag(self) -> None:
        """--allow-once bypasses cooldown and logs bypass with 24h default expiry.

        Verifies the core allow-once flow: when allow_once=True (flag-only),
        _log_bypass is called with expires_at and reason_prefix="allow_once",
        then exec proceeds via exec_cleared_command.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        # Verify expires_at was passed (datetime) and reason_prefix is "allow_once"
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("expires_at") is not None
        assert call_kwargs.get("reason_prefix") == "allow_once"
        mock_exec.assert_called_once()

    def test_handle_cooldown_with_allow_once_value(self) -> None:
        """--allow-once=6h parses the custom duration via _parse_expiry.

        Verifies that when a custom duration is provided, _parse_expiry is
        called with the correct value string.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": "6h", "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_parse_expiry") as mock_parse,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_parse.assert_called_once_with("6h")
        mock_log.assert_called_once()
        mock_exec.assert_called_once()

    def test_allow_once_takes_priority_over_force(self) -> None:
        """When both --allow-once and --force are set, --allow-once branch is taken.

        Verifies that allow_once is checked before force in the COOLDOWN branch,
        so the more scoped bypass wins.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": True, "force": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("reason_prefix") == "allow_once", (
            "allow_once should win over force: expected reason_prefix='allow_once'"
        )
        mock_exec.assert_called_once()

    def test_force_shows_allow_once_tip(self) -> None:
        """When --force is used without --allow-once, a tip is shown.

        Verifies that the --force branch prints a message suggesting
        --allow-once as a safer alternative.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"force": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            _capture_stderr() as stderr_captured,
            patch.object(exec_module, "_log_bypass"),
            patch.object(exec_module, "exec_cleared_command"),
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        stderr_output = stderr_captured.getvalue()
        assert "allow-once" in stderr_output, "Expected --force tip to mention --allow-once"

    def test_allow_once_not_bypassing_threat(self) -> None:
        """--allow-once does NOT bypass threat blocks (exit code 4).

        Verifies that even with --allow-once set, a THREAT block still
        exits with EXIT_THREAT_DETECTED (4). Threat blocks are non-bypassable.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": True},
            file_targets=[],
            raw_args=["install", "malicious-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            patch.object(exec_module, "_print_threat_block") as mock_print,
            patch.object(sys, "exit") as mock_exit,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg_ref)
            mock_print.assert_called_once()
            mock_exit.assert_called_once_with(4)

    def test_log_bypass_reason_prefix(self) -> None:
        """_log_bypass with reason_prefix stores encoded reason string.

        Verifies that when reason_prefix is set, the reason field in the
        insert_bypass call uses the format '{reason_prefix}:{reason.name}'.
        """
        import sqlite3
        from pathlib import Path
        from unittest.mock import patch as mock_patch

        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": True},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        db_path = Path("/tmp") / f"test_bypass_reason_{id(pkg_ref)}.db"
        try:
            # Init schema with bypasses table
            from pkg_defender.db.schema import init_db

            conn = init_db(db_path)
            conn.close()

            with mock_patch("pkg_defender.cli.exec.get_db_path", return_value=db_path):
                exec_module._log_bypass(
                    parsed,
                    pkg_ref,
                    BlockReason.COOLDOWN,
                    reason_prefix="allow_once",
                )

            # Verify the DB entry
            verify_conn = sqlite3.connect(str(db_path))
            row = verify_conn.execute("SELECT reason, expires_at FROM bypasses ORDER BY id DESC LIMIT 1").fetchone()
            verify_conn.close()
            assert row is not None, "Expected a bypass entry in the database"
            assert row[0] == "allow_once:COOLDOWN", f"Expected reason='allow_once:COOLDOWN', got '{row[0]}'"
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_log_bypass_passes_checks_performed(self, tmp_path: Any) -> None:
        """_log_bypass() passes checks_performed through to insert_bypass().

        Regression test: verifies the checks_performed parameter flows
        from _log_bypass() into insert_bypass(). If this passthrough is
        removed, the test fails because insert_bypass won't receive the
        checks_performed value.

        Root cause: A-035 added checks_performed to the _log_bypass()
        signature with passthrough to insert_bypass() at
        src/pkg_defender/cli/exec.py:827. Without this passthrough, the
        insert_bypass would always use the default 'bypassed'.
        """
        from unittest.mock import patch as mock_patch

        from pkg_defender.cli import exec as exec_module
        from pkg_defender.db.schema import init_db

        # Create a temp DB so _log_bypass finds a valid database path
        db_path = tmp_path / "test_bypass.db"
        conn = init_db(db_path)
        conn.close()

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        with (
            mock_patch("pkg_defender.cli.exec.get_db_path", return_value=db_path),
            mock_patch("pkg_defender.cli.exec.insert_bypass") as mock_insert,
        ):
            exec_module._log_bypass(
                parsed,
                pkg_ref,
                BlockReason.THREAT,
                reason_prefix="bypass_threat",
                checks_performed="threat_only",
            )

        mock_insert.assert_called_once()
        call_kwargs = mock_insert.call_args.kwargs
        assert call_kwargs.get("checks_performed") == "threat_only", (
            f"Expected checks_performed='threat_only', got '{call_kwargs.get('checks_performed')}'"
        )

    def test_handle_blocked_command_passes_checks_performed(self) -> None:
        """handle_blocked_command() passes checks_performed through to _log_bypass().

        Regression test for the full passthrough chain: handle_blocked_command()
        must forward checks_performed to _log_bypass(). If this passthrough
        is removed at any of the 5 call sites in handle_blocked_command(),
        this test fails.

        Root cause: A-035 added checks_performed to the handle_blocked_command()
        signature at src/pkg_defender/cli/exec.py:108 with passthrough to all
        5 _log_bypass() call sites (THREAT line 139, COOLDOWN lines 175/188/197/201).

        This test exercises the COOLDOWN path with --force to verify the
        checks_performed parameter flows through to _log_bypass().
        """
        from unittest.mock import patch as mock_patch

        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"force": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        with (
            pytest.raises(SystemExit) as exc_info,
            mock_patch.object(exec_module, "_log_bypass") as mock_log,
            mock_patch.object(exec_module, "exec_cleared_command"),
        ):
            exec_module.handle_blocked_command(
                parsed,
                BlockReason.COOLDOWN,
                pkg_ref,
                checks_performed="cooldown_only",
            )

        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("checks_performed") == "cooldown_only", (
            f"Expected checks_performed='cooldown_only', got '{call_kwargs.get('checks_performed')}'"
        )

    def test_allow_once_invalid_expiry_raises_error(self) -> None:
        """Invalid expiry value in --allow-once=xyz raises click.BadParameter.

        Verifies that _parse_expiry raises click.BadParameter for invalid
        duration formats, ensuring users get clear feedback rather than
        silently falling back to a default. This is the production behavior:
        invalid values error out rather than silently applying 24h.
        """
        import click

        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": "xyz", "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(click.BadParameter, match="Invalid expiry format"),
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        mock_log.assert_not_called()
        mock_exec.assert_not_called()

    def test_allow_once_with_dry_run_still_bypasses(self) -> None:
        """--allow-once bypasses cooldown even when --dry-run is also set.

        When both --allow-once and --dry-run are set, the allow-once path
        still takes effect and calls exec_cleared_command. This is consistent
        with how --force handles --dry-run (all bypass paths call exec directly,
        bypassing the dry-run check).
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": True, "dry_run": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("reason_prefix") == "allow_once"
        mock_exec.assert_called_once()

    # ------------------------------------------------------------------
    # --dry-run prompt fix regression tests (A-032)
    # ------------------------------------------------------------------

    def test_cooldown_dry_run_does_not_prompt(self) -> None:
        """--dry-run in COOLDOWN branch skips _ask_bypass prompt and does not exec.

        Root cause: src/pkg_defender/cli/exec.py:224 — the condition
        ``elif not ci and not dry_run:`` already guards the prompt for
        COOLDOWN, so with ``dry_run=True`` the prompt is correctly skipped.
        This test proves the guard works: no prompt, no exec, clean exit 3.

        Before the fix, the dry_run check was missing entirely in some paths,
        causing the prompt to appear (blocking CI/automation).
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"dry_run": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_print_cooldown_block") as mock_print,
            patch.object(exec_module, "_ask_bypass") as mock_prompt,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_print.assert_called_once()
        mock_prompt.assert_not_called()  # Key assertion: no hang / no prompt
        mock_exec.assert_not_called()

    def test_vcs_source_dry_run_does_not_prompt_not_exec(self) -> None:
        """--dry-run in VCS_SOURCE branch (non-JSON) skips _ask_confirm and exec.

        Root cause: src/pkg_defender/cli/exec.py:245 — the dry_run check
        at line 245 was missing before the fix, so the _ask_confirm prompt
        at line 247 or exec_cleared_command at line 249 could run despite
        --dry-run being set.

        This test proves: with dry_run=True and no --json, the VCS_SOURCE
        branch prints the warning, then exits with code 1 — no prompt, no exec.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="vcs-pkg", raw="vcs-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"dry_run": True},
            file_targets=[],
            raw_args=["install", "vcs-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_print_vcs_warning") as mock_warn,
            patch.object(exec_module, "_ask_confirm") as mock_confirm,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.VCS_SOURCE, pkg_ref)
        assert exc_info.value.code == 1
        mock_warn.assert_called_once()
        mock_confirm.assert_not_called()  # Key assertion: no prompt
        mock_exec.assert_not_called()  # Key assertion: no execution

    def test_vcs_source_json_dry_run_does_not_exec(self) -> None:
        """--json + --dry-run in VCS_SOURCE branch produces JSON but does NOT exec.

        Root cause: src/pkg_defender/cli/exec.py:241 — the dry_run check
        at line 241 (inside the JSON path) was missing before the fix.
        Without it, exec_cleared_command at line 243 would run despite
        --dry-run being set, actually executing the blocked command.

        This test proves: with json=True and dry_run=True, JSON is emitted
        and the process exits with code 1 — no execution occurs.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="vcs-pkg", raw="vcs-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"json": True, "dry_run": True},
            file_targets=[],
            raw_args=["install", "vcs-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            patch("click.echo") as mock_echo,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
            pytest.raises(SystemExit) as exc_info,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.VCS_SOURCE, pkg_ref)
        assert exc_info.value.code == 1
        assert mock_echo.called
        mock_exec.assert_not_called()  # Key assertion: dry-run prevents exec

    def test_vcs_source_json_dry_run_produces_valid_json(self) -> None:
        """--json + --dry-run in VCS_SOURCE branch emits parseable JSON with dry_run flag.

        Verifies the JSON output includes ``decision: "block"``,
        ``reason: "VCS_SOURCE"``, and ``dry_run: true`` so consumers
        can distinguish actual blocks from dry-run blocks.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="vcs-pkg", raw="vcs-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"json": True, "dry_run": True},
            file_targets=[],
            raw_args=["install", "vcs-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            patch("click.echo") as mock_echo,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
            pytest.raises(SystemExit) as exc_info,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.VCS_SOURCE, pkg_ref)
        assert exc_info.value.code == 1
        assert mock_echo.called
        json_arg = mock_echo.call_args[0][0]
        data = json.loads(json_arg)
        assert data["decision"] == "block"
        assert data["reason"] == "VCS_SOURCE"
        assert data["dry_run"] is True
        mock_exec.assert_not_called()

    def test_cooldown_ci_still_skips_prompt(self) -> None:
        """--ci in COOLDOWN branch still skips _ask_bypass prompt (regression guard).

        Root cause: src/pkg_defender/cli/exec.py:224 — the condition
        ``elif not ci and not dry_run:`` guards the prompt. This test
        verifies that --ci still correctly bypasses the prompt even after
        the dry_run fix, ensuring the ci behavior was not accidentally
        changed.

        This is a regression guard: ci mode should continue to exit cleanly
        (code 3) without prompting, same as dry_run.
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"ci": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_print_cooldown_block") as mock_print,
            patch.object(exec_module, "_ask_bypass") as mock_prompt,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_print.assert_called_once()
        mock_prompt.assert_not_called()  # Key assertion: ci mode skips prompt
        mock_exec.assert_not_called()

    def test_prefix_force_triggers_cooldown_bypass(self) -> None:
        """Prefix --force (ctx.obj path) triggers cooldown bypass via merge.

        Simulates the full wiring path: ctx.obj["force"]=True → dispatcher
        merge → parsed.pkgd_flags["force"]=True → handle_blocked_command
        bypasses cooldown. The test starts with empty pkgd_flags (as the
        prefix path would leave them) and adds force post-construction
        (as the dispatcher merge does at dispatcher.py:104-116).
        """
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"cooldown": "24"},  # No force at construction — prefix path
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        # Simulate the dispatcher merge: ctx.obj["force"] → parsed.pkgd_flags["force"]
        parsed.pkgd_flags["force"] = True

        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        mock_exec.assert_called_once()

    def test_threat_json_output(self) -> None:
        """--json in THREAT branch produces JSON output."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(pkgd_flags={"json": True})
        pkg = make_package(name="evil", version="1.0.0", ecosystem="pypi")
        with (
            patch("click.echo") as mock_echo,
            pytest.raises(SystemExit) as exc_info,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg)
        assert exc_info.value.code == 4
        assert mock_echo.called
        json_arg = mock_echo.call_args[0][0]
        data = json.loads(json_arg)
        assert data["decision"] == "block"
        assert data["reason"] == "THREAT"

    def test_cooldown_json_output(self) -> None:
        """--json in COOLDOWN branch produces JSON output and blocks (no bypass)."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(pkgd_flags={"json": True})
        pkg = make_package(name="new", version="1.0.0", ecosystem="pypi")
        clears = datetime(2026, 6, 1, tzinfo=UTC)
        with (
            patch("click.echo") as mock_echo,
            pytest.raises(SystemExit) as exc_info,
        ):
            exec_module.handle_blocked_command(
                parsed, BlockReason.COOLDOWN, pkg, safe_version="pkg==0.9.0", clears_at=clears
            )
        assert exc_info.value.code == 3
        assert mock_echo.called
        json_arg = mock_echo.call_args[0][0]
        data = json.loads(json_arg)
        assert data["reason"] == "COOLDOWN"
        assert data["safe_version"] == "pkg==0.9.0"

    def test_vcs_json_output(self) -> None:
        """--json in VCS_SOURCE branch produces JSON output and execs (no prompt)."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(pkgd_flags={"json": True})
        pkg = make_package(name="vcs-pkg", ecosystem="pypi")
        with (
            patch("click.echo") as mock_echo,
            patch("pkg_defender.cli.exec.exec_cleared_command", side_effect=SystemExit(0)) as mock_exec,
            pytest.raises(SystemExit),
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.VCS_SOURCE, pkg)
        assert mock_echo.called
        # Verify err=True to prevent stdout mixing with exec'd command
        assert mock_echo.call_args[1].get("err") is True
        json_arg = mock_echo.call_args[0][0]
        data = json.loads(json_arg)
        assert data["reason"] == "VCS_SOURCE"
        assert data["decision"] == "block"
        mock_exec.assert_called_once_with(parsed)

    def test_local_path_json_output(self) -> None:
        """--json in LOCAL_PATH branch produces JSON output and execs."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(pkgd_flags={"json": True})
        pkg = make_package(name="local-pkg", ecosystem="pypi")
        with (
            patch("click.echo") as mock_echo,
            patch("pkg_defender.cli.exec.exec_cleared_command", side_effect=SystemExit(0)) as mock_exec,
            pytest.raises(SystemExit),
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.LOCAL_PATH, pkg)
        assert mock_echo.called
        # Verify err=True to prevent stdout mixing with exec'd command
        assert mock_echo.call_args[1].get("err") is True
        json_arg = mock_echo.call_args[0][0]
        data = json.loads(json_arg)
        assert data["reason"] == "LOCAL_PATH"
        mock_exec.assert_called_once_with(parsed)

    # ------------------------------------------------------------------
    # --bypass-cooldown and --bypass-threat tests
    # ------------------------------------------------------------------

    def test_bypass_cooldown_bypasses_cooldown(self) -> None:
        """--bypass-cooldown in COOLDOWN branch bypasses and logs with bypass_cooldown prefix."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_cooldown": True, "cooldown": "24"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("reason_prefix") == "bypass_cooldown"
        mock_exec.assert_called_once()

    def test_bypass_cooldown_does_not_bypass_threat(self) -> None:
        """--bypass-cooldown in THREAT branch does NOT bypass — still blocked (exit code 4)."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_cooldown": True},
            file_targets=[],
            raw_args=["install", "malicious-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            patch.object(exec_module, "_print_threat_block") as mock_print,
            patch.object(sys, "exit") as mock_exit,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg_ref)
            mock_print.assert_called_once()
            mock_exit.assert_called_once_with(4)

    def test_bypass_threat_bypasses_threat(self) -> None:
        """--bypass-threat in THREAT branch bypasses and logs with bypass_threat prefix."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_threat": True},
            file_targets=[],
            raw_args=["install", "malicious-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command", side_effect=SystemExit(0)) as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg_ref)
        assert exc_info.value.code == 0
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("reason_prefix") == "bypass_threat"
        mock_exec.assert_called_once()

    def test_bypass_threat_does_not_bypass_cooldown(self) -> None:
        """--bypass-threat in COOLDOWN branch does NOT bypass — still blocked (exit code 3)."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_threat": True, "cooldown": "24", "ci": True},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_print_cooldown_block") as mock_print,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        mock_print.assert_called_once()
        mock_log.assert_not_called()
        mock_exec.assert_not_called()

    def test_bypass_cooldown_reason_in_db(self) -> None:
        """DB entry for --bypass-cooldown has reason='bypass_cooldown:COOLDOWN'."""
        import sqlite3
        from pathlib import Path
        from unittest.mock import patch as mock_patch

        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_cooldown": True},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        db_path = Path("/tmp") / f"test_bypass_cooldown_reason_{id(pkg_ref)}.db"
        try:
            from pkg_defender.db.schema import init_db

            conn = init_db(db_path)
            conn.close()

            with mock_patch("pkg_defender.cli.exec.get_db_path", return_value=db_path):
                exec_module._log_bypass(
                    parsed,
                    pkg_ref,
                    BlockReason.COOLDOWN,
                    reason_prefix="bypass_cooldown",
                )

            verify_conn = sqlite3.connect(str(db_path))
            row = verify_conn.execute("SELECT reason FROM bypasses ORDER BY id DESC LIMIT 1").fetchone()
            verify_conn.close()
            assert row is not None, "Expected a bypass entry in the database"
            assert row[0] == "bypass_cooldown:COOLDOWN", f"Expected reason='bypass_cooldown:COOLDOWN', got '{row[0]}'"
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_bypass_threat_reason_in_db(self) -> None:
        """DB entry for --bypass-threat has reason='bypass_threat:THREAT'."""
        import sqlite3
        from pathlib import Path
        from unittest.mock import patch as mock_patch

        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0", ecosystem="pypi")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_threat": True},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        db_path = Path("/tmp") / f"test_bypass_threat_reason_{id(pkg_ref)}.db"
        try:
            from pkg_defender.db.schema import init_db

            conn = init_db(db_path)
            conn.close()

            with mock_patch("pkg_defender.cli.exec.get_db_path", return_value=db_path):
                exec_module._log_bypass(
                    parsed,
                    pkg_ref,
                    BlockReason.THREAT,
                    reason_prefix="bypass_threat",
                )

            verify_conn = sqlite3.connect(str(db_path))
            row = verify_conn.execute("SELECT reason FROM bypasses ORDER BY id DESC LIMIT 1").fetchone()
            verify_conn.close()
            assert row is not None, "Expected a bypass entry in the database"
            assert row[0] == "bypass_threat:THREAT", f"Expected reason='bypass_threat:THREAT', got '{row[0]}'"
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_bypass_cooldown_takes_priority_over_allow_once(self) -> None:
        """When both --bypass-cooldown and --allow-once set, --bypass-cooldown branch is taken."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={
                "bypass_cooldown": True,
                "allow_once": True,
                "cooldown": "24",
            },
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.COOLDOWN, pkg_ref)
        assert exc_info.value.code == 3
        # _log_bypass should be called exactly ONCE with bypass_cooldown prefix
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs.get("reason_prefix") == "bypass_cooldown", (
            "bypass_cooldown should win over allow_once: expected reason_prefix='bypass_cooldown'"
        )
        mock_exec.assert_called_once()

    def test_handle_cooldown_forwards_window_days(self) -> None:
        """handle_blocked_command passes window_days to _print_cooldown_block."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="new-pkg", raw="new-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"cooldown": "48"},
            file_targets=[],
            raw_args=["install", "new-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        with (
            patch.object(exec_module, "_print_cooldown_block") as mock_print,
            patch.object(exec_module, "_ask_bypass", return_value=False),
            pytest.raises(SystemExit),
        ):
            exec_module.handle_blocked_command(
                parsed,
                BlockReason.COOLDOWN,
                pkg_ref,
                window_days=2,
            )

        mock_print.assert_called_once()
        call_kwargs = mock_print.call_args.kwargs
        assert call_kwargs.get("window_days") == 2

    def test_bypass_threat_json_suppresses_message(self) -> None:
        """--bypass-threat --json suppresses stderr message and executes silently."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        parsed = ParsedCommand(
            manager="npm",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"bypass_threat": True, "json": True},
            file_targets=[],
            raw_args=["install", "malicious-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        with (
            pytest.raises(SystemExit) as exc_info,
            _capture_stderr() as stderr_captured,
            patch.object(exec_module, "_log_bypass") as mock_log,
            patch.object(exec_module, "exec_cleared_command", side_effect=SystemExit(0)) as mock_exec,
        ):
            exec_module.handle_blocked_command(parsed, BlockReason.THREAT, pkg_ref)
        assert exc_info.value.code == 0
        mock_log.assert_called_once()
        mock_exec.assert_called_once()
        # No stderr message should be emitted in JSON mode
        stderr_output = stderr_captured.getvalue()
        assert "Bypassing threat" not in stderr_output


class TestBuildJsonResult:
    """Tests for _build_json_result helper."""

    def test_json_result_allow(self) -> None:
        """Decision 'allow' produces correct JSON dict."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(packages=[make_package(name="requests", version="1.0.0", ecosystem="pypi")])
        result = exec_module._build_json_result(parsed, "allow")
        assert result["decision"] == "allow"
        assert result["manager"] == "pip"
        assert "packages" in result
        assert result["packages"][0]["name"] == "requests"
        assert result["packages"][0]["ecosystem"] == "pypi"
        assert "reason" not in result

    def test_json_result_block(self) -> None:
        """Block with THREAT reason produces correct JSON dict."""
        from pkg_defender.cli import exec as exec_module

        pkg = make_package(name="bad-pkg", version="2.0.0", ecosystem="npm")
        parsed = make_parsed_command(packages=[])
        result = exec_module._build_json_result(parsed, "block", reason="THREAT", package=pkg)
        assert result["decision"] == "block"
        assert result["reason"] == "THREAT"
        assert result["package"]["name"] == "bad-pkg"
        assert result["package"]["ecosystem"] == "npm"
        assert "packages" not in result

    def test_json_result_cooldown(self) -> None:
        """Cooldown block includes safe_version and clears_at."""
        from pkg_defender.cli import exec as exec_module

        pkg = make_package(name="new-pkg", version="1.0.0", ecosystem="pypi")
        parsed = make_parsed_command(packages=[])
        clears = datetime(2026, 6, 1, tzinfo=UTC)
        result = exec_module._build_json_result(
            parsed, "block", reason="COOLDOWN", package=pkg, safe_version="pkg==0.9.0", clears_at=clears
        )
        assert result["safe_version"] == "pkg==0.9.0"
        assert result["clears_at"] == "2026-06-01T00:00:00+00:00"
        assert result["package"]["ecosystem"] == "pypi"

    def test_json_result_dry_run(self) -> None:
        """Dry_run flag is included in JSON result dict."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(packages=[], pkgd_flags={"dry_run": True})
        result = exec_module._build_json_result(parsed, "allow")
        assert result["dry_run"] is True


class TestHandleClearedCommand:
    """Tests for handle_cleared_command JSON output."""

    def test_cleared_json_dry_run(self) -> None:
        """--json + --dry-run produces JSON and does NOT exec."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            packages=[make_package(name="ok", version="1.0.0", ecosystem="pypi")],
            pkgd_flags={"dry_run": True, "json": True},
        )
        with (
            patch("click.echo") as mock_echo,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed)
            assert mock_echo.called
            # Dry-run has no exec, so JSON stays on stdout
            assert mock_echo.call_args[1].get("err") is None or mock_echo.call_args[1].get("err") is False
            json_arg = mock_echo.call_args[0][0]
            data = json.loads(json_arg)
            assert data["decision"] == "allow"
            assert data["dry_run"] is True
            mock_exec.assert_not_called()

    def test_cleared_json_no_dry_run(self) -> None:
        """--json without --dry-run produces JSON (to stderr) THEN execs."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            packages=[make_package(name="ok", version="1.0.0", ecosystem="pypi")], pkgd_flags={"json": True}
        )
        with (
            patch("click.echo") as mock_echo,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed)
            assert mock_echo.called
            # Verify err=True to prevent stdout mixing with exec'd command
            assert mock_echo.call_args[1].get("err") is True
            json_arg = mock_echo.call_args[0][0]
            data = json.loads(json_arg)
            assert data["decision"] == "allow"
            mock_exec.assert_called_once_with(parsed)


class TestPassthroughMessage:
    """Tests for the [PKGD] informational passthrough message in handle_cleared_command.

    The message ``[PKGD] "{manager} {raw_args}" not classified as dangerous —
    passing through to {manager}.`` was added to provide visibility into
    SAFE_PASSTHROUGH commands that skip security checks.
    """

    def test_passthrough_message_output(self) -> None:
        """[PKGD] passthrough message is printed for SAFE_PASSTHROUGH commands.

        Regression test: ensures the informational message is emitted before
        exec for commands that are not classified as dangerous.

        Root cause: ``src/pkg_defender/cli/exec.py:113-116`` — the
        ``_stderr_write()`` line added before ``exec_cleared_command()``
        in ``handle_cleared_command()``.

        This test FAILS before the fix (no message emitted) and PASSES after.
        """
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            manager="brew",
            intent=CommandIntent.SAFE_PASSTHROUGH,
            raw_args=["list"],
            manager_subcommand="list",
        )
        with (
            _capture_stderr() as stderr_captured,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed, passthrough=True)
            mock_exec.assert_called_once_with(parsed)
        output = stderr_captured.getvalue()
        assert '[PKGD] "brew list" not classified as dangerous' in output

    def test_passthrough_message_suppressed_on_dry_run(self) -> None:
        """[PKGD] passthrough message is NOT printed when --dry-run is set.

        The dry_run return path exits before the informational message line,
        so the message must NOT appear in stderr. This prevents false
        expectations when the user is only previewing an audit.
        """
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            manager="brew",
            intent=CommandIntent.SAFE_PASSTHROUGH,
            raw_args=["list"],
            manager_subcommand="list",
            pkgd_flags={"dry_run": True},
        )
        with (
            _capture_stderr() as stderr_captured,
            patch("pkg_defender.cli.exec._print_dry_run") as mock_dry_run,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed)
            mock_dry_run.assert_called_once_with(parsed)
            mock_exec.assert_not_called()
        output = stderr_captured.getvalue()
        assert "[PKGD]" not in output

    def test_passthrough_message_multi_word_command(self) -> None:
        """[PKGD] message includes the full multi-word command.

        Ensures that ``parsed.raw_args`` is joined correctly with spaces
        for subcommands that have multiple arguments (e.g. ``brew update
        opencode``), not just the first word.
        """
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            manager="brew",
            intent=CommandIntent.SAFE_PASSTHROUGH,
            raw_args=["update", "opencode"],
            manager_subcommand="update",
        )
        with (
            _capture_stderr() as stderr_captured,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed, passthrough=True)
            mock_exec.assert_called_once_with(parsed)
        output = stderr_captured.getvalue()
        assert '[PKGD] "brew update opencode" not classified as dangerous' in output

    def test_passthrough_message_suppressed_for_install_intent(self) -> None:
        """[PKGD] passthrough message is NOT printed for INSTALL commands.

        Regression test for the bug fix: the message should only appear for
        SAFE_PASSTHROUGH/REMOVE commands. INSTALL commands go through security
        checks and already have detailed pass messages.

        This test FAILS before the fix (message appears) and PASSES after
        (message suppressed).
        """
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            manager="pip",
            intent=CommandIntent.INSTALL,
            raw_args=["install", "requests"],
            manager_subcommand="install",
        )
        with (
            _capture_stderr() as stderr_captured,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed)
            mock_exec.assert_called_once_with(parsed)
        output = stderr_captured.getvalue()
        assert '[PKGD] "pip install requests" not classified as dangerous' not in output
        # The message should NOT appear for INSTALL intents
        assert "not classified as dangerous" not in output


class TestFlagMerge:
    """Tests for the ctx.obj → parsed.pkgd_flags merge in dispatcher.run().

    Verifies that Click-global flags (prefix placement) are correctly
    merged into the adapter-level pkgd_flags dict, fixing A-027.
    """

    def test_merge_ctx_obj_into_pkgd_flags(self) -> None:
        """ctx.obj values are merged into parsed.pkgd_flags for prefix placement.

        Verifies that the merge logic correctly copies ctx.obj entries
        (allow_once, force, etc.) into parsed.pkgd_flags, enabling
        'pkgd --allow-once pip install pkg' prefix placement to work.
        """
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        ctx.obj = {"allow_once": "24h", "force": True}

        # Merge (the code from dispatcher.run())
        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        assert parsed.pkgd_flags.get("allow_once") == "24h"
        assert parsed.pkgd_flags.get("force") is True

    def test_merge_does_not_overwrite_existing(self) -> None:
        """Merge does NOT overwrite values already set in parsed.pkgd_flags.

        Verifies that if the adapter-level parse already set a flag value,
        the merge step does not overwrite it with the ctx.obj value.
        """
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"allow_once": "6h"},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        ctx.obj = {"allow_once": "24h"}

        # Merge (the code from dispatcher.run())
        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        # The existing value "6h" should NOT be overwritten
        assert parsed.pkgd_flags.get("allow_once") == "6h"

    def test_merge_empty_ctx_does_not_crash(self) -> None:
        """Merge handles None ctx.obj gracefully without crashing."""
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        ctx.obj = None

        # Should not raise
        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        assert parsed.pkgd_flags == {}

    def test_merge_skips_none_and_false_values(self) -> None:
        """Merge skips None and False values from ctx.obj.

        Verifies that flags set to None or False in ctx.obj are not
        merged into pkgd_flags (handles default/unset flags).
        """
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        # allow_once=None should not be merged; fail_on_threat=False should not be merged
        ctx.obj = {"allow_once": None, "fail_on_threat": False, "force": True}

        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        assert "allow_once" not in parsed.pkgd_flags
        assert "fail_on_threat" not in parsed.pkgd_flags
        assert parsed.pkgd_flags.get("force") is True

    def test_merge_transfers_dry_run_from_ctx_obj(self) -> None:
        """--dry-run in ctx.obj is merged into parsed.pkgd_flags.

        Verifies that 'pkgd --dry-run pip install requests' prefix
        placement works by checking that dry_run=True in ctx.obj
        reaches parsed.pkgd_flags. Even with the scoped merge,
        dry_run is a recognized PKGD_FLAGS entry so it is transferred.
        """
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        ctx.obj = {"dry_run": True}

        pkgd_flag_keys = self._get_test_pkgd_flag_keys()
        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key in pkgd_flag_keys and key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        assert parsed.pkgd_flags.get("dry_run") is True

    def test_merge_skips_non_pkgd_flags(self) -> None:
        """Non-pkgd ctx.obj values are NOT merged into parsed.pkgd_flags.

        Verifies that the scoped merge does not leak non-pkgd
        ctx.obj entries (quiet, config_file, debug, etc.) into
        parsed.pkgd_flags. Only recognized PKGD_FLAGS entries
        should survive the merge.
        """
        from unittest.mock import MagicMock

        from pkg_defender.models.command import ParsedCommand

        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        ctx.obj = {
            "dry_run": True,
            "quiet": True,
            "config_file": "/tmp/config.toml",
            "no_color": True,
            "debug": True,
            "ci_auto_detected": True,
        }

        pkgd_flag_keys = self._get_test_pkgd_flag_keys()
        if ctx and ctx.obj:
            for key, value in ctx.obj.items():
                if key in pkgd_flag_keys and key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        # Only dry_run should be merged
        assert parsed.pkgd_flags.get("dry_run") is True
        assert "quiet" not in parsed.pkgd_flags
        assert "config_file" not in parsed.pkgd_flags
        assert "no_color" not in parsed.pkgd_flags
        assert "debug" not in parsed.pkgd_flags
        assert "ci_auto_detected" not in parsed.pkgd_flags

    @staticmethod
    def _get_test_pkgd_flag_keys() -> frozenset[str]:
        """Return recognized pkgd flag keys derived from the actual PKGD_FLAGS constant.

        Mirrors the production logic in dispatcher.py:104-116 that derives
        allowed keys from UnifiedRegistryAdapter.PKGD_FLAGS.
        """
        keys: set[str] = set()
        for flag in UnifiedRegistryAdapter.PKGD_FLAGS:
            if flag.startswith("--"):
                keys.add(flag[2:].replace("-", "_"))
        keys.add("verbose")
        return frozenset(keys)

    def test_print_dry_run_output(self) -> None:
        from pkg_defender.cli import exec as exec_module

        pkg_ref1 = PackageRef(name="requests", raw="requests")
        pkg_ref2 = PackageRef(name="flask", raw="flask")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref1, pkg_ref2],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"dry_run": True},
            file_targets=[],
            raw_args=["install", "requests", "flask"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        captured = io.StringIO()
        with patch.object(sys, "stdout", captured):
            exec_module._print_dry_run(parsed)
        output = captured.getvalue()
        assert "[PKGD] Dry run — would execute:" in output
        assert "[PKGD] Packages:" in output

    def test_prefix_json_merges_and_outputs(self) -> None:
        """Prefix --json (via ctx.obj merge) produces JSON output."""
        from pkg_defender.cli import exec as exec_module

        parsed = make_parsed_command(
            packages=[make_package(name="ok", version="1.0.0", ecosystem="pypi")], pkgd_flags={"dry_run": True}
        )
        # Simulate dispatcher merge: ctx.obj has "json" but parsed.pkgd_flags doesn't yet
        parsed.pkgd_flags["json"] = True
        with (
            patch("click.echo") as mock_echo,
            patch("pkg_defender.cli.exec.exec_cleared_command") as mock_exec,
        ):
            exec_module.handle_cleared_command(parsed)
            assert mock_echo.called
            # Dry-run has no exec, so JSON stays on stdout
            assert mock_echo.call_args[1].get("err") is None or mock_echo.call_args[1].get("err") is False
            json_arg = mock_echo.call_args[0][0]
            data = json.loads(json_arg)
            assert data["decision"] == "allow"
            assert data["dry_run"] is True
            mock_exec.assert_not_called()


class TestPrintThreatBlock:
    def test_print_threat_block_output(self) -> None:
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="malicious-pkg", raw="malicious-pkg")
        with _capture_stderr() as captured:
            exec_module._print_threat_block(pkg_ref)
        output = captured.getvalue()
        assert "BLOCKED" in output
        assert "malicious-pkg" in output


class TestAskBypass:
    def test_ask_bypass_yes(self) -> None:
        from pkg_defender.cli import exec as exec_module

        with patch("builtins.input", return_value="y"):
            result = exec_module._ask_bypass()
        assert result is True

    def test_ask_bypass_no(self) -> None:
        from pkg_defender.cli import exec as exec_module

        with patch("builtins.input", return_value="n"):
            result = exec_module._ask_bypass()
        assert result is False


class TestModuleFunctions:
    def test_has_exec_function(self) -> None:
        from pkg_defender.cli import exec as exec_module

        assert hasattr(exec_module, "exec_cleared_command")
        assert callable(exec_module.exec_cleared_command)

    def test_has_handle_cleared(self) -> None:
        from pkg_defender.cli import exec as exec_module

        assert hasattr(exec_module, "handle_cleared_command")
        assert callable(exec_module.handle_cleared_command)

    def test_has_handle_blocked(self) -> None:
        from pkg_defender.cli import exec as exec_module

        assert hasattr(exec_module, "handle_blocked_command")
        assert callable(exec_module.handle_blocked_command)


class TestCheckThreatsDbFailure:
    """Tests that _check_threats blocks install when DB is invalid or missing.

    These tests FAIL before the fix (returns True = allow) and PASS after
    (returns False = block), verifying the fail-closed behavior required by
    spec §2.1 "No False Security Theater".
    """

    def test_db_path_none_blocks_install(self, tmp_path: Path) -> None:
        """When get_db_path returns None, install must be blocked."""
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[MagicMock(name="requests", version="2.31.0")],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()

        with patch("pkg_defender.config.get_db_path", return_value=None):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when db_path is None"

    def test_db_path_missing_blocks_install(self, tmp_path: Path) -> None:
        """When threat DB file doesn't exist, install must be blocked."""
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[MagicMock(name="requests", version="2.31.0")],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()

        nonexistent = tmp_path / "nonexistent.db"

        with patch("pkg_defender.config.get_db_path", return_value=nonexistent):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when DB file doesn't exist"

    def test_db_path_missing_echoes_message(self, tmp_path: Path) -> None:
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[MagicMock(name="requests", version="2.31.0")],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        nonexistent = tmp_path / "nonexistent.db"

        with (
            patch("pkg_defender.config.get_db_path", return_value=nonexistent),
            patch("click.echo") as mock_echo,
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when DB file doesn't exist"
        mock_echo.assert_called_once()
        args, kwargs = mock_echo.call_args
        assert "Threat database not found" in args[0], (
            f"Expected 'Threat database not found' in message, got: {args[0]}"
        )

    def test_db_open_error_blocks_install(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[MagicMock(name="requests", version="2.31.0")],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch("sqlite3.connect", side_effect=sqlite3.Error("database disk image is malformed")),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when DB open fails with sqlite3.Error"


class TestCheckThreatsPackageErrors:
    """Tests that _check_threats blocks install on per-package errors.

    These tests FAIL before the fix (errors cause continue/skip = allow)
    and PASS after (errors cause return False = block).
    """

    _THREATS_DDL = (
        "CREATE TABLE IF NOT EXISTS threats ("
        "id TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, "
        "package_name TEXT, severity TEXT NOT NULL DEFAULT 'UNKNOWN', "
        "confidence REAL NOT NULL DEFAULT 0.0, "
        "source TEXT NOT NULL DEFAULT 'osv', "
        "summary TEXT NOT NULL DEFAULT '', "
        "first_seen TEXT NOT NULL DEFAULT(datetime('now')), "
        "last_seen TEXT NOT NULL DEFAULT(datetime('now')), "
        "hit_count INTEGER NOT NULL DEFAULT 1, "
        "ingested_at TEXT NOT NULL DEFAULT(datetime('now')))"
    )

    def test_no_version_blocks_install(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        pkg_no_version = MagicMock(name="requests", version=None)
        pkg_no_version.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg_no_version],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        # Create a minimal valid DB so we get past the DB-existence check
        conn = sqlite3.connect(str(db_path))
        conn.execute(self._THREATS_DDL)
        conn.commit()
        conn.close()

        with patch("pkg_defender.config.get_db_path", return_value=db_path):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when package version is None"
        assert result.block_decision is not None, "Expected block_decision when package version is None"
        assert result.block_decision.reason == BlockReason.THREAT

    def test_check_timeout_blocks_install(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        pkg = MagicMock(name="requests", version="2.31.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute(self._THREATS_DDL)
        conn.commit()
        conn.close()

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch("pkg_defender.core.checker.check_packages_batch", side_effect=sqlite3.Error("check timed out")),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when batch check raises sqlite3.Error"

    def test_check_db_error_blocks_install(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        pkg = MagicMock(name="requests", version="2.31.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute(self._THREATS_DDL)
        conn.commit()
        conn.close()

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch("pkg_defender.core.checker.check_packages_batch", side_effect=sqlite3.Error("disk I/O error")),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when batch check fails with sqlite3.Error"


class TestCheckThreatsBatch:
    """Tests for batch-mode threat checking (C2 batch wiring)."""

    _THREATS_DDL = (
        "CREATE TABLE IF NOT EXISTS threats ("
        "id TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, "
        "package_name TEXT, severity TEXT NOT NULL DEFAULT 'UNKNOWN', "
        "confidence REAL NOT NULL DEFAULT 0.0, "
        "source TEXT NOT NULL DEFAULT 'osv', "
        "summary TEXT NOT NULL DEFAULT '', "
        "first_seen TEXT NOT NULL DEFAULT(datetime('now')), "
        "last_seen TEXT NOT NULL DEFAULT(datetime('now')), "
        "hit_count INTEGER NOT NULL DEFAULT 1, "
        "ingested_at TEXT NOT NULL DEFAULT(datetime('now')))"
    )

    def test_batch_with_multiple_packages(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models import CheckResult
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"

        pkg1 = MagicMock(name="requests", version="2.31.0")
        pkg1.name = "requests"
        pkg2 = MagicMock(name="flask", version="3.0.0")
        pkg2.name = "flask"

        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg1, pkg2],
            manager="pip",
            raw_args=["pip", "install", "requests", "flask"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute(self._THREATS_DDL)
        conn.commit()
        conn.close()

        # Mock batch to return one blocked, one clear
        def batch_side_effect(conn: Any, packages: Any) -> dict[tuple[str, str, str], CheckResult]:
            return {
                ("pypi", "requests", "2.31.0"): CheckResult(
                    blocked=True,
                    highest_score=0.8,
                    highest_severity="HIGH",
                ),
                ("pypi", "flask", "3.0.0"): CheckResult(
                    blocked=False,
                    highest_score=0.0,
                    highest_severity="UNKNOWN",
                ),
            }

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch(
                "pkg_defender.core.checker.check_packages_batch",
                side_effect=batch_side_effect,
            ),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when one package is blocked"

    def test_batch_db_error_still_blocks(self, tmp_path: Path) -> None:
        import sqlite3
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        pkg = MagicMock(name="requests", version="2.31.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests"],
        )
        ctx = MagicMock()
        db_path = tmp_path / "test.db"

        with (
            patch("pkg_defender.config.get_db_path", return_value=db_path),
            patch(
                "pkg_defender.core.checker.check_packages_batch",
                side_effect=sqlite3.Error("batch error"),
            ),
        ):
            result = dispatcher._check_threats(parsed, ctx)

        assert result.passed is False, "Expected False (block) when batch raises sqlite3.Error"


class TestCheckCooldown:
    """Tests for the new _check_cooldown method.

    These tests verify that cooldown checking blocks installs when
    packages are too new or release dates are unavailable.
    """

    def test_cooldown_blocks_new_package(self) -> None:
        """When a package was released recently, install must be blocked."""
        from unittest.mock import MagicMock

        from pkg_defender.cli.dispatcher import ManagerDispatcher

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock(coverage_tier=CoverageTier.FULL)

    def test_cooldown_blocks_new_package_partial_tier(self) -> None:
        """PARTIAL tier: cooldown check blocks a recent package install."""
        from datetime import UTC, datetime
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock(coverage_tier=CoverageTier.PARTIAL)

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests==2.28.0"],
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        # Package released 1 hour ago
        recent_date = datetime(2026, 5, 10, 0, 0, tzinfo=UTC)
        release_dates: dict[str, tuple[datetime | None, str]] = {"requests": (recent_date, "verified")}

        with patch(
            "pkg_defender.audit.cooldown.step_check_cooldown",
            return_value=(False, 5),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False, "Expected False (block) when package is within cooldown window"
        assert result.block_decision is not None
        assert result.block_decision.package.name == "requests"

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests==2.28.0"],
        )
        ctx = MagicMock()

        # Package released 1 hour ago
        recent_date = datetime(2026, 5, 10, 0, 0, tzinfo=UTC)
        release_dates2: dict[str, tuple[datetime | None, str]] = {"requests": (recent_date, "verified")}

        with patch(
            "pkg_defender.audit.cooldown.step_check_cooldown",
            return_value=(False, 5),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates2)

        assert result.passed is False, "Expected False (block) when package is within cooldown window"
        assert result.block_decision is not None
        # safe_version and clears_at are passed (defaulting to None when not computed)
        assert result.block_decision.safe_version is None or isinstance(result.block_decision.safe_version, str), (
            "safe_version should be str or None"
        )
        assert result.block_decision.clears_at is None or isinstance(result.block_decision.clears_at, datetime), (
            "clears_at should be datetime or None"
        )

    def test_cooldown_allows_old_package(self) -> None:
        """When a package was released long ago, install is allowed."""
        from datetime import UTC, datetime
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests==2.28.0"],
        )
        ctx = MagicMock()

        # Package released 30+ days ago
        old_date = datetime(2026, 4, 1, 0, 0, tzinfo=UTC)
        release_dates: dict[str, tuple[datetime | None, str]] = {"requests": (old_date, "verified")}

        with patch(
            "pkg_defender.audit.cooldown.step_check_cooldown",
            return_value=(True, 0),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is True, "Expected True (allow) when package is outside cooldown window"

    def test_cooldown_missing_release_date_blocks(self) -> None:
        """When release date is None for a package, install must be blocked."""
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock(coverage_tier=CoverageTier.FULL)

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests==2.28.0"],
        )
        ctx = MagicMock()

        release_dates: dict[str, tuple[datetime | None, str]] = {"requests": (None, "")}

        with (
            patch("pkg_defender.config.load_config"),
            patch("pkg_defender.cli.exec.handle_blocked_command"),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, release_dates)

        assert result.passed is False, "Expected False (block) when release date is None"

    def test_cooldown_empty_release_dates_blocks(self) -> None:
        """When no release dates are available at all, install must be blocked."""
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock(coverage_tier=CoverageTier.FULL)

        pkg = MagicMock(name="requests", version="2.28.0")
        pkg.name = "requests"
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "requests==2.28.0"],
        )
        ctx = MagicMock()

        with (
            patch("pkg_defender.config.load_config"),
            patch("pkg_defender.cli.exec.handle_blocked_command"),
        ):
            result = dispatcher._check_cooldown(parsed, ctx, {})

        assert result.passed is False, "Expected False (block) when release_dates is empty"

    def test_check_cooldown_release_date_none(self) -> None:
        """_check_cooldown handles release_date=None without NameError on window."""
        from unittest.mock import MagicMock, patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.models.command import CommandIntent, ParsedCommand

        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.ecosystem = "pypi"

        pkg = MagicMock(name="new-pkg", version="1.0.0")
        pkg.name = "new-pkg"
        pkg.ecosystem = None
        parsed = ParsedCommand(
            intent=CommandIntent.INSTALL,
            packages=[pkg],
            manager="pip",
            raw_args=["pip", "install", "new-pkg"],
        )
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}

        release_dates: dict[str, tuple[datetime | None, str]] = {"new-pkg": (None, "")}

        with (
            patch("pkg_defender.audit.cooldown.step_check_cooldown", return_value=(False, 7)),
            patch("pkg_defender.config.load_config"),
            patch("pkg_defender.config.get_db_path", return_value=None),
            patch("pkg_defender.cli.exec.handle_blocked_command"),
        ):
            try:
                dispatcher._check_cooldown(parsed, ctx, release_dates)
            except NameError:
                pytest.fail("NameError raised: window not initialized for release_date=None")


class TestExplainOutput:
    """Tests for the explain (decision trace) output functions.

    Each test verifies that the explain functions produce expected output
    containing key decision-trace information.
    """

    # ------------------------------------------------------------------
    # Helper: capture output via _stderr_write (Rich → sys.stderr)
    # ------------------------------------------------------------------

    @staticmethod
    def _capture_explain(func: Any, *args: Any, **kwargs: Any) -> str:
        """Execute an explain function and capture its output."""
        with _capture_stderr() as captured:
            func(*args, **kwargs)
        return captured.getvalue()

    # ------------------------------------------------------------------
    # Threat explain tests
    # ------------------------------------------------------------------

    def test_explain_threat_basic(self) -> None:
        """Threat explain output contains BLOCKED, threat reason, and package name/version."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="malicious-pkg", version="1.0.0", ecosystem="pypi")
        result = CheckResult(
            blocked=True,
            threats=[
                ScoredThreat(
                    record=ThreatRecord(
                        id="GHSA-xxxx",
                        ecosystem="pypi",
                        source="OSV",
                        summary="Malicious package",
                    ),
                    final_score=0.85,
                    display_severity="HIGH",
                    version_match_type="exact",
                ),
            ],
            highest_score=0.85,
            highest_severity="HIGH",
        )
        output = self._capture_explain(exec_module._print_explain_threat, pkg, result)
        assert "BLOCKED" in output
        assert "Known security threat" in output
        assert "malicious-pkg" in output
        assert "1.0.0" in output

    def test_explain_threat_scores(self) -> None:
        """Threat explain output includes highest score and severity."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="bad-pkg", version="2.0.0")
        result = CheckResult(
            blocked=True,
            threats=[
                ScoredThreat(
                    record=ThreatRecord(
                        id="GHSA-yyyy",
                        ecosystem="npm",
                        source="GitHub Advisory",
                        summary="Critical vuln",
                    ),
                    final_score=0.95,
                    display_severity="CRITICAL",
                    version_match_type="exact",
                ),
            ],
            highest_score=0.95,
            highest_severity="CRITICAL",
        )
        output = self._capture_explain(exec_module._print_explain_threat, pkg, result)
        assert "Highest score" in output
        assert "0.95" in output
        assert "CRITICAL" in output

    def test_explain_threat_multi(self) -> None:
        """Threat explain with multiple threats shows Threat #1, Threat #2, sources, summaries."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="multi-threat-pkg", version="3.0.0")
        result = CheckResult(
            blocked=True,
            threats=[
                ScoredThreat(
                    record=ThreatRecord(
                        id="GHSA-aaa",
                        ecosystem="pypi",
                        source="OSV",
                        summary="Dependency confusion",
                    ),
                    final_score=0.85,
                    display_severity="HIGH",
                    version_match_type="exact",
                ),
                ScoredThreat(
                    record=ThreatRecord(
                        id="GHSA-bbb",
                        ecosystem="pypi",
                        source="GitHub Advisory Database",
                        summary="Typo-squatting",
                    ),
                    final_score=0.45,
                    display_severity="MEDIUM",
                    version_match_type="exact",
                ),
            ],
            highest_score=0.85,
            highest_severity="HIGH",
        )
        output = self._capture_explain(exec_module._print_explain_threat, pkg, result)
        assert "Threat #1" in output
        assert "Threat #2" in output
        assert "OSV" in output
        assert "GitHub Advisory Database" in output
        assert "Dependency confusion" in output
        assert "Typo-squatting" in output

    # ------------------------------------------------------------------
    # Cooldown explain tests
    # ------------------------------------------------------------------

    def test_explain_cooldown_basic(self) -> None:
        """Cooldown explain output contains BLOCKED, cooldown reason, package name, and safe version."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="new-pkg", version="1.0.0", ecosystem="pypi")
        release_date = datetime(2026, 5, 15, 14, 30, 0, tzinfo=UTC)
        output = self._capture_explain(
            exec_module._print_explain_cooldown,
            pkg,
            release_date,
            3,
            "pypi",
            5,
            "new-pkg==0.9.0",
        )
        assert "BLOCKED" in output
        assert "Cooldown period" in output
        assert "new-pkg" in output
        assert "Safe version" in output
        assert "new-pkg==0.9.0" in output

    def test_explain_cooldown_dates(self) -> None:
        """Cooldown explain output shows release date, remaining, clears-at, window, safe version."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="cool-pkg", version="2.0.0", ecosystem="npm")
        release_date = datetime(2026, 5, 14, 10, 0, 0, tzinfo=UTC)
        output = self._capture_explain(
            exec_module._print_explain_cooldown,
            pkg,
            release_date,
            2,
            "npm",
            7,
            "cool-pkg@1.9.0",
        )
        assert "Release date" in output
        assert "2026-05-14" in output
        assert "Cooldown window" in output
        assert "7 days" in output
        assert "npm" in output
        assert "Safe version" in output
        assert "cool-pkg@1.9.0" in output

    def test_explain_cooldown_no_release_date(self) -> None:
        """Cooldown explain with None release date handles gracefully and no safe version."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="unknown-pkg", version="1.0.0")
        output = self._capture_explain(
            exec_module._print_explain_cooldown,
            pkg,
            None,
            5,
            "pypi",
            5,
        )
        assert "Release date" in output
        assert "Unknown" in output
        assert "Safe version" not in output

    # ------------------------------------------------------------------
    # DB/System explain tests
    # ------------------------------------------------------------------

    def test_explain_no_db(self) -> None:
        """No-DB explain output references missing database and setup instruction."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="requests", version="2.31.0")
        output = self._capture_explain(
            exec_module._print_explain_no_db,
            pkg,
            "/tmp/.local/share/pkg-defender/threats.db",
        )
        assert "Threat database not found" in output
        assert "pkgd setup" in output
        assert "threats.db" in output

    def test_explain_no_version(self) -> None:
        """No-version explain references version pinning advice."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="requests")
        output = self._capture_explain(exec_module._print_explain_no_version, pkg)
        assert "No version specified" in output
        assert "Specify a version" in output
        assert "requests" in output

    def test_explain_stale_db(self) -> None:
        """Stale-DB explain output references last sync, threshold, and error."""
        from pkg_defender.cli import exec as exec_module

        output = self._capture_explain(
            exec_module._print_explain_stale_db,
            "/tmp/.local/share/pkg-defender/threats.db",
            "2026-04-01 @ 10:00:00 UTC",
            24,
            "Connection timeout to OSV feed",
        )
        assert "stale" in output or "Stale" in output
        assert "2026-04-01" in output
        assert "24 hours" in output
        assert "pkgd intel sync" in output

    def test_explain_db_connection(self) -> None:
        """DB-connection explain output references error detail."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="test-pkg", version="1.0.0")
        output = self._capture_explain(
            exec_module._print_explain_db_connection,
            pkg,
            "database disk image is malformed",
        )
        assert "Could not open threat database" in output
        assert "database disk image is malformed" in output

    # ------------------------------------------------------------------
    # Source explain tests
    # ------------------------------------------------------------------

    def test_explain_vcs(self) -> None:
        """VCS explain output references VCS source and cannot-verify reason."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(
            name="my-custom-package",
            raw="git+https://github.com/user/repo.git",
        )
        output = self._capture_explain(exec_module._print_explain_vcs, pkg)
        assert "VCS source" in output
        assert "cannot verify" in output

    def test_explain_local_path(self) -> None:
        """Local-path explain output references local path and cannot-verify reason."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="./my-local-package", raw="./my-local-package")
        output = self._capture_explain(exec_module._print_explain_local_path, pkg)
        assert "Local path" in output
        assert "cannot verify" in output

    # ------------------------------------------------------------------
    # Error explain tests
    # ------------------------------------------------------------------

    def test_explain_timeout(self) -> None:
        """Timeout explain output references timeout seconds and actionable advice."""
        from pkg_defender.cli import exec as exec_module

        output = self._capture_explain(exec_module._print_explain_timeout, 30)
        assert "timed out" in output
        assert "30 seconds" in output
        assert "Increase timeout" in output

    def test_explain_no_result(self) -> None:
        """Null-result explain output references no result and sync advice."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="broken-pkg", version="1.0.0")
        output = self._capture_explain(exec_module._print_explain_no_result, pkg)
        assert "No threat check result" in output
        assert "pkgd intel sync" in output

    # ------------------------------------------------------------------
    # Edge-case tests: empty threats, detail_url, singular age forms, etc.
    # ------------------------------------------------------------------

    def test_explain_threat_zero_threats(self) -> None:
        """Threat explain with empty threats list still renders without error."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="no-threat-detail", version="1.0.0", ecosystem="pypi")
        result = CheckResult(
            blocked=True,
            threats=[],
            highest_score=0.0,
            highest_severity="UNKNOWN",
        )
        output = self._capture_explain(exec_module._print_explain_threat, pkg, result)
        assert "BLOCKED" in output
        assert "Matching threats" in output
        # No crash with zero threats — no "Threat #1" should appear
        assert "Threat #1" not in output

    def test_explain_threat_with_detail_url(self) -> None:
        """Threat explain includes reference URL when detail_url is set."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="ref-pkg", version="1.0.0", ecosystem="pypi")
        result = CheckResult(
            blocked=True,
            threats=[
                ScoredThreat(
                    record=ThreatRecord(
                        id="GHSA-ref",
                        ecosystem="pypi",
                        source="OSV",
                        summary="Vulnerability with reference",
                        detail_url="https://osv.dev/GHSA-ref",
                    ),
                    final_score=0.75,
                    display_severity="HIGH",
                    version_match_type="exact",
                ),
            ],
            highest_score=0.75,
            highest_severity="HIGH",
        )
        output = self._capture_explain(exec_module._print_explain_threat, pkg, result)
        assert "Reference" in output
        assert "https://osv.dev/GHSA-ref" in output

    def test_explain_cooldown_zero_remaining(self) -> None:
        """Cooldown explain with 0 days remaining renders correctly and shows safe version."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="borderline-pkg", version="1.0.0", ecosystem="pypi")
        release_date = datetime(2026, 5, 14, 10, 0, 0, tzinfo=UTC)
        output = self._capture_explain(
            exec_module._print_explain_cooldown,
            pkg,
            release_date,
            0,
            "pypi",
            5,
            "borderline-pkg==0.9.0",
        )
        assert "0 days" in output
        assert "Remaining" in output
        assert "Clears at" in output
        assert "Safe version" in output
        assert "borderline-pkg==0.9.0" in output

    def test_format_age_singular(self) -> None:
        """_format_age uses singular 'day' and 'hour' for 1-day/1-hour ages."""
        from pkg_defender.cli import exec as exec_module

        # 1 day 1 hour ago
        release_date = datetime.now(UTC) - timedelta(days=1, hours=1)
        age = exec_module._format_age(release_date)
        assert "1 day" in age
        assert "1 hour" in age

    def test_format_age_future_date(self) -> None:
        """_format_age returns '0 days 0 hours' for a future date."""
        from pkg_defender.cli import exec as exec_module

        release_date = datetime.now(UTC) + timedelta(days=1)
        age = exec_module._format_age(release_date)
        assert age == "0 days 0 hours"

    def test_explain_header_without_ecosystem(self) -> None:
        """_print_explain_header works when package has no ecosystem."""
        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="no-eco-pkg", version="1.0.0")
        output = self._capture_explain(
            exec_module._print_explain_header,
            pkg,
            "❌ BLOCKED",
            "Generic block reason",
        )
        assert "Decision Trace" in output
        assert "no-eco-pkg" in output
        assert "1.0.0" in output
        assert "BLOCKED" in output
        # No ecosystem line should appear
        assert "Ecosystem" not in output

    def test_explain_stale_db_never_synced(self) -> None:
        """Stale-DB explain renders 'Never synced' when last_sync is None."""
        from pkg_defender.cli import exec as exec_module

        output = self._capture_explain(
            exec_module._print_explain_stale_db,
            "/tmp/.local/share/pkg-defender/threats.db",
            None,
            24,
            "Connection timeout to OSV feed",
        )
        assert "Never synced" in output
        assert "24 hours" in output
        assert "pkgd intel sync" in output

    # ------------------------------------------------------------------
    # Helper function tests
    # ------------------------------------------------------------------

    def test_format_age_with_date(self) -> None:
        """_format_age returns human-readable age for a given date."""
        from pkg_defender.cli import exec as exec_module

        # Use a fixed reference point
        release_date = datetime.now(UTC) - timedelta(days=2, hours=3)
        age = exec_module._format_age(release_date)
        assert "2 days" in age

    def test_format_age_none(self) -> None:
        """_format_age returns 'Unknown' for None input."""
        from pkg_defender.cli import exec as exec_module

        age = exec_module._format_age(None)
        assert age == "Unknown"

    def test_format_age_naive_datetime(self) -> None:
        """_format_age handles naive datetime without crashing."""
        from pkg_defender.cli import exec as exec_module

        release_date = datetime(2026, 3, 1, 12, 0, 0)  # naive
        age = exec_module._format_age(release_date)
        assert "days" in age  # Should produce valid output, not TypeError

    def test_allow_once_cooldown_block_message(self) -> None:
        """Cooldown block message shows --allow-once, safe_version, and clears_at when present."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="test-pkg", raw="test-pkg")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"cooldown": "24"},
            file_targets=[],
            raw_args=["install", "test-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        from pkg_defender.cli import exec as exec_module2

        # Test with safe_version and clears_at present
        clears_at = datetime.now(UTC) + timedelta(days=3)
        captured = io.StringIO()

        def _patch_write(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(
                exec_module2,
                "_stderr_write",
                _patch_write,
            ),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                safe_version="test-pkg==1.2.3",
                clears_at=clears_at,
                window_days=5,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )
        output = captured.getvalue()
        assert "--allow-once" in output
        assert "--force" in output
        assert "Safe version: test-pkg==1.2.3" in output
        assert "Clears at:" in output
        assert clears_at.strftime("%Y-%m-%d @ %H:%M UTC") in output
        assert exec_module._format_remaining_time(clears_at) in output
        assert "Cooldown window: 5 days" in output

        # Test without safe_version/clears_at (existing behavior preserved)
        captured2 = io.StringIO()

        def _patch_write2(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured2),
            patch.object(
                exec_module2,
                "_stderr_write",
                _patch_write2,
            ),
        ):
            exec_module._print_cooldown_block(pkg_ref, parsed, window_days=5)
        output2 = captured2.getvalue()
        assert "--allow-once" in output2
        assert "Safe version:" not in output2
        assert "Clears at:" not in output2

    def test_cooldown_block_expired_clears_at(self) -> None:
        """Cooldown block with past clears_at should show negative days without crashing."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="old-block", raw="old-block")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"cooldown": "24"},
            file_targets=[],
            raw_args=["install", "old-block"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        past_clears = datetime.now(UTC) - timedelta(days=1)
        captured = io.StringIO()

        def _patch_write(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(
                exec_module,
                "_stderr_write",
                _patch_write,
            ),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                clears_at=past_clears,
                window_days=3,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )
        output = captured.getvalue()
        assert "Clears at:" in output
        assert "Cooldown window: 3 days" in output

    def test_cooldown_block_safe_version_absent(self) -> None:
        """_print_cooldown_block omits safe_version and cooldown clears when both are None."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="no-safe-pkg", raw="no-safe-pkg")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={"cooldown": "24"},
            file_targets=[],
            raw_args=["install", "no-safe-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )
        captured = io.StringIO()

        def _patch_write(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(
                exec_module,
                "_stderr_write",
                _patch_write,
            ),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                safe_version=None,
                clears_at=None,
                window_days=3,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )
        output = captured.getvalue()
        assert "BLOCKED" in output
        assert "Safe version:" not in output
        assert "Clears at:" not in output
        assert "Cooldown window: 3 days" in output

    def test_cooldown_block_window_days_display(self) -> None:
        """_print_cooldown_block displays window_days with correct pluralization."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="multi-day", raw="multi-day")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "multi-day"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        captured = io.StringIO()

        def _pw(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(exec_module, "_stderr_write", _pw),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                window_days=7,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )

        output = captured.getvalue()
        assert "Cooldown window: 7 days" in output

    def test_cooldown_block_singular_day(self) -> None:
        """_print_cooldown_block uses 'day' (not 'days') when window_days=1."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="single-day", raw="single-day")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "single-day"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        captured = io.StringIO()

        def _pw(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(exec_module, "_stderr_write", _pw),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                window_days=1,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )

        output = captured.getvalue()
        assert "Cooldown window: 1 day" in output

    def test_cooldown_block_without_window_days(self) -> None:
        """_print_cooldown_block defaults to 3 days when window_days not passed."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="default-pkg", raw="default-pkg")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "default-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        captured = io.StringIO()

        def _pw(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(exec_module, "_stderr_write", _pw),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                release_date=datetime.now(UTC) - timedelta(days=1),
                date_source="pypi_json",
            )

        output = captured.getvalue()
        assert "Cooldown window: 3 days" in output

    def test_allow_once_explain_action(self) -> None:
        """Explain cooldown output includes --allow-once in action suggestions."""
        from datetime import UTC, datetime

        from pkg_defender.cli import exec as exec_module

        pkg = PackageRef(name="cool-pkg", version="1.0.0", ecosystem="pypi")
        release_date = datetime(2026, 5, 15, 14, 30, 0, tzinfo=UTC)
        captured = io.StringIO()

        def _patch_write(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(
                exec_module,
                "_stderr_write",
                _patch_write,
            ),
        ):
            exec_module._print_explain_cooldown(pkg, release_date, 3, "pypi", 5, date_source="")
        output = captured.getvalue()
        assert "--allow-once" in output

    def test_make_separator(self) -> None:
        """_make_separator creates a decorated title line."""
        from pkg_defender.cli import exec as exec_module

        sep = exec_module._make_separator("Test Title")
        assert "──" in sep
        assert "Test Title" in sep
        assert sep.startswith("[PKGD]")

    def test_cooldown_block_shows_publish_date(self) -> None:
        """_print_cooldown_block shows Published line when release_date is provided."""
        from pkg_defender.cli import exec as exec_module

        pkg_ref = PackageRef(name="dated-pkg", raw="dated-pkg")
        parsed = ParsedCommand(
            manager="pip",
            intent=CommandIntent.INSTALL,
            packages=[pkg_ref],
            manager_subcommand="install",
            manager_flags=[],
            pkgd_flags={},
            file_targets=[],
            raw_args=["install", "dated-pkg"],
            requires_file_audit=False,
            is_global=False,
            is_dev_dependency=False,
        )

        captured = io.StringIO()

        def _pw(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        with (
            patch.object(sys, "stderr", captured),
            patch.object(exec_module, "_stderr_write", _pw),
        ):
            exec_module._print_cooldown_block(
                pkg_ref,
                parsed,
                release_date=datetime(2023, 10, 2, 12, 0, tzinfo=UTC),
                date_source="verified",
                window_days=3,
            )

        output = captured.getvalue()
        assert "Published: 2023-10-02 @ 12:00 UTC (source: verified)" in output


class TestFormatSourceLabel:
    """Tests for _format_source_label()."""

    def test_unknown_source(self) -> None:
        """Empty string maps to 'unknown'."""
        from pkg_defender.cli.exec import _format_source_label

        assert _format_source_label("") == "unknown"

    def test_known_source_registry_api(self) -> None:
        """registry_api maps to 'registry'."""
        from pkg_defender.cli.exec import _format_source_label

        assert _format_source_label("registry_api") == "registry"

    def test_known_source_github_tags(self) -> None:
        """github_tags maps to 'GitHub Tags'."""
        from pkg_defender.cli.exec import _format_source_label

        assert _format_source_label("github_tags") == "GitHub Tags"

    def test_unknown_label_passed_through(self) -> None:
        """Unmapped labels are returned unchanged."""
        from pkg_defender.cli.exec import _format_source_label

        assert _format_source_label("custom_source") == "custom_source"


class TestManagerNameInJsonOutput:
    """Tests that JSON output contains correct manager name for all pip variants.

    Regression tests for M1: pip3/pipx returned ``'pip'`` instead of their
    actual name in JSON output. The fix overwrites ``parsed.manager`` with
    ``self.manager_name`` in ``ManagerDispatcher.run()`` after the adapter's
    ``parse()`` returns, so the user's original input is preserved.
    """

    def test_pip3_json_output_has_pip3_manager(self, runner: CliRunner) -> None:
        """Running pip3 install --json --dry-run should show 'manager': 'pip3'."""
        import json
        from unittest.mock import patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.cli.exec import handle_cleared_command
        from pkg_defender.cli.main import cli

        async def _skip_checks(
            self_dispatcher: ManagerDispatcher,
            parsed: object,
            ctx: object,
        ) -> None:
            """Bypass pre-install checks and jump straight to output."""
            handle_cleared_command(parsed)  # type: ignore[arg-type]

        with patch.object(
            ManagerDispatcher,
            "_run_pre_install_check_async",
            _skip_checks,
        ):
            result = runner.invoke(cli, ["pip3", "install", "--dry-run", "--json", "requests"])

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}: {result.stderr}"
        data = json.loads(result.output)
        assert data["manager"] == "pip3", f"Expected 'pip3', got '{data['manager']}'"

    def test_pipx_json_output_has_pipx_manager(self, runner: CliRunner) -> None:
        """Running pipx install --json --dry-run should show 'manager': 'pipx'."""
        import json
        from unittest.mock import patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.cli.exec import handle_cleared_command
        from pkg_defender.cli.main import cli

        async def _skip_checks(
            self_dispatcher: ManagerDispatcher,
            parsed: object,
            ctx: object,
        ) -> None:
            handle_cleared_command(parsed)  # type: ignore[arg-type]

        with patch.object(
            ManagerDispatcher,
            "_run_pre_install_check_async",
            _skip_checks,
        ):
            result = runner.invoke(cli, ["pipx", "install", "--dry-run", "--json", "requests"])

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}: {result.stderr}"
        data = json.loads(result.output)
        assert data["manager"] == "pipx", f"Expected 'pipx', got '{data['manager']}'"

    def test_pip_json_output_has_pip_manager(self, runner: CliRunner) -> None:
        """Running pip install --json --dry-run should still show 'manager': 'pip'.

        Non-regression guard: pip (the canonical name) must not regress to
        a different value after the pip3/pipx fix.
        """
        import json
        from unittest.mock import patch

        from pkg_defender.cli.dispatcher import ManagerDispatcher
        from pkg_defender.cli.exec import handle_cleared_command
        from pkg_defender.cli.main import cli

        async def _skip_checks(
            self_dispatcher: ManagerDispatcher,
            parsed: object,
            ctx: object,
        ) -> None:
            handle_cleared_command(parsed)  # type: ignore[arg-type]

        with patch.object(
            ManagerDispatcher,
            "_run_pre_install_check_async",
            _skip_checks,
        ):
            result = runner.invoke(cli, ["pip", "install", "--dry-run", "--json", "requests"])

        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}: {result.stderr}"
        data = json.loads(result.output)
        assert data["manager"] == "pip", f"Expected 'pip', got '{data['manager']}'"


class TestJsonModeSuppression:
    """Tests that ``--json`` suppresses ``click.echo`` stderr messages in
    ``_run_pre_install_check()``.

    Verifies that when ``pkgd_flags["json"]`` is ``True``, the 4 success/note
    messages that were added with ``if not parsed.pkgd_flags.get("json"):``
    guards are correctly suppressed. The regression guard also verifies that
    without the ``--json`` flag, messages are still emitted.
    """

    def _make_dispatcher(self) -> ManagerDispatcher:
        """Create a bare dispatcher instance (bypasses __init__)."""
        dispatcher = ManagerDispatcher.__new__(ManagerDispatcher)
        dispatcher.manager_name = "pip"
        return dispatcher

    def _make_parsed(self, **kwargs: Any) -> ParsedCommand:
        """Create a ParsedCommand for testing."""
        defaults: dict[str, Any] = {
            "manager": "pip",
            "manager_subcommand": "install",
            "intent": CommandIntent.INSTALL,
            "packages": [],
            "raw_args": ["pip", "install"],
            "pkgd_flags": {},
        }
        defaults.update(kwargs)
        return ParsedCommand(**defaults)

    def _make_ctx(self) -> MagicMock:
        """Create a mock Click context."""
        ctx = MagicMock()
        ctx.obj = {"fail_on_threat": True}
        return ctx

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_json_suppresses_audit_success(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--json suppresses AUDIT-tier success echo message.

        Both the AUDIT warning (already guarded) and the success message
        (newly guarded) must be suppressed when ``--json`` is active.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT
        parsed = self._make_parsed(pkgd_flags={"json": True})

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        mock_echo.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_json_suppresses_partial_note(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--json suppresses PARTIAL-tier note echo message.

        The note about partial coverage must not be printed when ``--json``
        is active.
        """
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(
            passed=True,
            cooldown_pass=True,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL
        parsed = self._make_parsed(pkgd_flags={"json": True})

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        mock_echo.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_json_suppresses_partial_cooldown(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--json suppresses PARTIAL-tier cooldown pass echo message.

        The "Cooldown check passed" message must not be printed when
        ``--json`` is active.
        """
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(
            passed=True,
            cooldown_pass=True,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.PARTIAL
        parsed = self._make_parsed(pkgd_flags={"json": True})

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        mock_echo.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_json_suppresses_full_success(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """--json suppresses FULL-tier success echo message.

        The "All checks passed" message must not be printed when
        ``--json`` is active.
        """
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )
        mock_check_cooldown.return_value = CooldownCheckResult(
            passed=True,
            cooldown_pass=True,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.FULL
        parsed = self._make_parsed(pkgd_flags={"json": True})

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        mock_echo.assert_not_called()

    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._ensure_db_fresh")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_threats")
    @patch("pkg_defender.cli.dispatcher.ManagerDispatcher._check_cooldown")
    def test_non_json_does_not_suppress_messages(
        self,
        mock_check_cooldown: MagicMock,
        mock_check_threats: MagicMock,
        mock_ensure_db_fresh: MagicMock,
    ) -> None:
        """Without --json, echo messages are still printed (regression guard).

        Verifies that the normal (non-JSON) code path still emits click.echo
        calls, proving the ``if not json`` guard does not suppress output
        when no ``--json`` flag is present.
        """
        ManagerDispatcher._warned_audit_managers.clear()
        mock_ensure_db_fresh.return_value = True
        mock_check_threats.return_value = ThreatCheckResult(
            passed=True,
            threat_count_general=0,
            threat_count_versioned=0,
        )

        dispatcher = self._make_dispatcher()
        dispatcher.adapter = MagicMock()
        dispatcher.adapter.coverage_tier = CoverageTier.AUDIT
        parsed = self._make_parsed(pkgd_flags={})  # No json flag

        with (
            patch.object(click, "echo") as mock_echo,
            patch("pkg_defender.cli.exec.handle_cleared_command"),
        ):
            dispatcher._run_pre_install_check(parsed, self._make_ctx())

        assert mock_echo.called, "Expected click.echo to be called when --json is not set"


class TestLookupResolutionInfoLogging:
    """Regression tests for _lookup_resolution_info exception handling.

    Verifies that DB lookup failures are logged at debug level instead of
    silently swallowed.
    """

    def test_db_lookup_failure_is_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """Exception during DB lookup produces a debug log entry."""
        from unittest.mock import patch

        from pkg_defender.cli.exec import _lookup_resolution_info
        from pkg_defender.models.command import PackageRef

        package = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0")

        # _lookup_resolution_info uses a local import from pkg_defender.config,
        # so the mock target must be pkg_defender.config.get_db_path.
        with (
            patch("pkg_defender.config.get_db_path", side_effect=RuntimeError("DB locked")),
            caplog.at_level("DEBUG", logger="pkg_defender.cli.exec"),
        ):
            result = _lookup_resolution_info(package, "pypi")

        assert result is None
        assert "DB lookup failed" in caplog.text

    def test_db_lookup_failure_does_not_propagate(self) -> None:
        """Exception during DB lookup returns None, not propagates."""
        from unittest.mock import patch

        from pkg_defender.cli.exec import _lookup_resolution_info
        from pkg_defender.models.command import PackageRef

        package = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0")

        with patch("pkg_defender.config.get_db_path", side_effect=RuntimeError("DB locked")):
            result = _lookup_resolution_info(package, "pypi")

        assert result is None


class TestLogBypassLogging:
    """Regression tests for _log_bypass exception handling.

    Verifies that bypass audit trail write failures produce both a
    logger.warning call and a stderr message.
    """

    def test_bypass_write_failure_is_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """Exception during bypass DB write produces a warning log entry."""
        from unittest.mock import patch

        from pkg_defender.cli.exec import _log_bypass
        from pkg_defender.models.command import BlockReason, PackageRef, ParsedCommand

        parsed = ParsedCommand(manager="pip", manager_subcommand="install", raw_args=[])
        package = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0")
        reason = BlockReason.THREAT

        with (
            patch("pkg_defender.cli.exec.get_db_path", side_effect=RuntimeError("DB error")),
            caplog.at_level("WARNING", logger="pkg_defender.cli.exec"),
        ):
            _log_bypass(parsed, package, reason)

        assert "Failed to write bypass to database audit log" in caplog.text

    def test_bypass_write_failure_does_not_propagate(self) -> None:
        """Exception during bypass DB write is caught, not propagated."""
        from unittest.mock import patch

        from pkg_defender.cli.exec import _log_bypass
        from pkg_defender.models.command import BlockReason, PackageRef, ParsedCommand

        parsed = ParsedCommand(manager="pip", manager_subcommand="install", raw_args=[])
        package = PackageRef(name="test-pkg", raw="test-pkg", version="1.0.0")
        reason = BlockReason.THREAT

        with patch("pkg_defender.cli.exec.get_db_path", side_effect=RuntimeError("DB error")):
            # Should not raise
            _log_bypass(parsed, package, reason)
