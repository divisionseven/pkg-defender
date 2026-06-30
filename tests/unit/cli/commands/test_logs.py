"""Tests for pkg_defender.cli.commands.logs module.

Covers ``pkgd logs view`` and ``pkgd logs follow`` commands.
Targets 90%+ line and branch coverage.

Strategy
--------
- ``get_data_dir()`` is patched ONLY at the ``logs`` module where the
  function is resolved at call time (``pkg_defender.cli.commands.logs.get_data_dir``).
  Do NOT also patch ``config.settings.get_data_dir`` — that causes the
  CLI group to initialize differently and breaks command dispatch.
  (The ``logs`` module imports ``get_data_dir`` at module load time from
  ``cli.common``, so the attribute exists on the already-loaded module.)
- Test log files are created in the temp directory with known content.

Tailing-loop edge cases
-----------------------
The ``logs follow`` tailing loop uses ``os.fstat`` to detect file
changes. We test the branches by capturing the **original** ``fstat``
function before patching, then calling it selectively:

.. code::

    _ORIG_FSTAT = os.fstat       # captured before any monkeypatch
    monkeypatch.setattr(…os.fstat, lambda fd: … _ORIG_FSTAT(fd) …)

This avoids infinite recursion when the patched function delegates
to the real implementation.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR
from pkg_defender.cli.commands.logs import logs_follow
from pkg_defender.cli.main import cli

# Capture the original fstat once to avoid recursion when patching
_ORIG_FSTAT = os.fstat

# logs_follow must be a synchronous function. If someone re-adds
# "async def logs_follow", Click won't await it and the command
# will print a coroutine repr instead of executing.
assert not inspect.iscoroutinefunction(logs_follow), (
    "logs_follow must be a synchronous function. Click 8.x does not await async command callbacks."
)


def _setup_log_file(tmp_path: Path, lines: int = 20) -> Path:
    """Create a temp log file with *lines* numbered lines."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    log_file = data_dir / "pkgd.log"
    content = "\n".join(f"Log line {i}" for i in range(lines))
    log_file.write_text(content + "\n", encoding="utf-8")
    return log_file


def _patch_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect ``get_data_dir`` to a temp directory.

    IMPORTANT: Only patch ``pkg_defender.cli.commands.logs.get_data_dir``.
    Do NOT also patch ``config.settings.get_data_dir`` or
    ``cli.common.get_data_dir`` — those interfere with CLI group
    initialization and break command dispatch.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    def _get_data_dir() -> Path:
        return data_dir

    monkeypatch.setattr("pkg_defender.cli.commands.logs.get_data_dir", _get_data_dir)
    return data_dir


# ============================================================================
# TestLogsGroup
# ============================================================================


class TestLogsGroup:
    """Basic group-level behaviour."""

    def test_logs_help(self, runner: CliRunner) -> None:
        """``pkgd logs --help`` shows subcommands."""
        result = runner.invoke(cli, ["logs", "--help"])
        assert result.exit_code == 0
        assert "view" in result.output
        assert "follow" in result.output


# ============================================================================
# TestLogsView
# ============================================================================


class TestLogsView:
    """Tests for ``pkgd logs view``."""

    def test_view_no_log_file(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no log file exists, prints error and exits 1.

        Root cause: ``logs.py`` lines 62-68 — if ``log_file.exists()``
        is False, error message is printed and ``SystemExit(1)`` raised.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        result = runner.invoke(cli, ["logs", "view"])
        assert result.exit_code == 1
        assert "Error" in result.output

    def test_view_default_lines(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without ``--full``, shows the last 100 lines by default.

        Root cause: ``logs.py`` lines 70-79 — the function reads all
        lines and joins the last ``lines`` (default 100).
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=50)
        result = runner.invoke(cli, ["logs", "view"])
        assert result.exit_code == 0
        # Should show all 50 lines (less than default 100)
        assert "Log line 0" in result.output
        assert "Log line 49" in result.output

    def test_view_custom_lines(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``-n`` controls how many lines are shown."""
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=50)
        result = runner.invoke(cli, ["logs", "view", "-n", "5"])
        assert result.exit_code == 0
        assert "Log line 49" in result.output
        assert "Log line 45" in result.output
        assert "Log line 44" not in result.output  # 6th from end

    def test_view_full_flag(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``--full`` shows entire log file.

        Root cause: ``logs.py`` line 72 — ``if full:`` branch reads the
        entire file at once instead of slicing by line count.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=200)
        result = runner.invoke(cli, ["logs", "view", "--full"])
        assert result.exit_code == 0
        assert "Log line 0" in result.output
        assert "Log line 199" in result.output

    def test_view_full_with_n_ignored(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``--full`` with ``-n`` still shows all lines (``--full`` wins).

        This verifies that when ``full`` is True, ``lines`` is ignored.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=30)
        result = runner.invoke(cli, ["logs", "view", "--full", "-n", "3"])
        assert result.exit_code == 0
        assert "Log line 0" in result.output
        assert "Log line 29" in result.output

    def test_view_oserror(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unreadable log file prints error and exits 1.

        Root cause: ``logs.py`` lines 80-85 — ``OSError`` during
        file open/read is caught and ``SystemExit(1)`` raised.

        Note: Uses ``log_file.mkdir()`` instead of ``chmod(0o000)``
        because ``os.chmod`` does not deny read access to the file
        owner on Windows. ``open()`` on a directory raises ``OSError``
        on ALL platforms.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        log_file = data_dir / "pkgd.log"
        log_file.mkdir()  # Directory → open() raises OSError on all platforms
        result = runner.invoke(cli, ["logs", "view"])
        assert result.exit_code == 1
        assert "Error reading log file" in result.output


# ============================================================================
# TestLogsFollow
# ============================================================================


class TestLogsFollow:
    """Tests for ``pkgd logs follow`` (tail -f style log tailing)."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_follow(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, lines: int = 10) -> str:
        """Execute ``pkgd logs follow`` and return captured stdout.

        Sets up the test environment and returns result output via CliRunner.
        Tests that need to exit the tailing loop should patch ``time.sleep``
        to raise ``KeyboardInterrupt`` before calling this helper.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        result = runner.invoke(cli, ["logs", "follow", "-n", str(lines)])
        return result.output

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_follow_no_log_file(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no log file exists, prints error and exits 1.

        Root cause: ``logs.py`` lines 120-126 — same check as ``view``
        but in the ``follow`` command handler.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        result = runner.invoke(cli, ["logs", "follow", "-n", "10"])
        assert result.exit_code == EXIT_GENERAL_ERROR
        assert "Error" in result.output

    def test_follow_shows_initial_lines(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``logs follow`` shows initial lines of the log file.

        Root cause: ``logs.py`` lines 128-163 — initial lines are read
        and displayed, then the tailing loop begins. We patch
        ``time.sleep`` to raise ``KeyboardInterrupt`` so the loop exits
        immediately.

        This test verifies the initial-display path (lines 129-134).
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=15)

        def _exit_on_sleep(_delay: float) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", _exit_on_sleep)

        result = runner.invoke(cli, ["logs", "follow", "-n", "5"])

        assert "Log line 14" in result.output
        assert "Log line 10" in result.output
        assert "Log line 9" not in result.output

    def test_follow_oserror(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unreadable log file prints error and exits 1.

        Root cause: ``logs.py`` lines 135-140 — ``OSError`` during
        initial file read is caught and ``SystemExit(1)`` raised.

        Note: Uses ``log_file.mkdir()`` instead of ``chmod(0o000)``
        because ``os.chmod`` does not deny read access to the file
        owner on Windows. ``open()`` on a directory raises ``OSError``
        on ALL platforms.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        log_file = data_dir / "pkgd.log"
        log_file.mkdir()  # Directory → open() raises OSError on all platforms

        result = runner.invoke(cli, ["logs", "follow", "-n", "10"])
        assert result.exit_code == EXIT_GENERAL_ERROR
        assert "Error reading log file" in result.output

    def test_follow_empty_log_file(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty log file — ``if initial:`` is falsy (line 132→134).

        Root cause: ``logs.py`` lines 131-134 — when the file is empty
        (0 bytes), ``initial`` evaluates to ``""``, so the ``click.echo``
        is skipped but ``file_position = f.tell()`` still runs.

        This test verifies the ``if initial:`` falsy branch.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        log_file = data_dir / "pkgd.log"
        log_file.write_text("", encoding="utf-8")  # truly empty file (0 bytes)

        def _exit_on_sleep(_delay: float) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", _exit_on_sleep)

        # Should not raise — KeyboardInterrupt is caught
        result = runner.invoke(cli, ["logs", "follow", "-n", "10"])
        assert result.exit_code == 0

    def test_follow_tailing_loop_fstat_oserror(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError during fstat in the tailing loop breaks out (lines 148-149).

        Root cause: ``logs.py`` lines 145-149 — the ``try/except OSError``
        inside the ``while True`` loop catches ``os.fstat`` failures and
        breaks out.

        We patch ``os.fstat`` to raise ``OSError`` on the first call made
        inside the tailing loop.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=5)

        # os.fstat is only called in the while loop, so raising on every
        # call exercises the ``except OSError: break`` path (lines 148-149).
        monkeypatch.setattr(
            "pkg_defender.cli.commands.logs.os.fstat",
            lambda fd: (_ for _ in ()).throw(OSError("fstat failed")),
        )

        # Should exit cleanly — OSError inside the loop triggers break
        result = runner.invoke(cli, ["logs", "follow", "-n", "5"])
        assert result.exit_code == 0

    def test_follow_tailing_new_content(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """New content appended while tailing (lines 152-155).

        Root cause: ``logs.py`` lines 151-155 — when ``current_size >
        file_position``, the code seeks to the old position and reads
        new lines.

        We patch ``os.fstat`` to write extra content to the file before
        returning a fake larger size. This ensures the subsequent
        ``for line in f:`` loop reads actual content.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        log_file = data_dir / "pkgd.log"
        log_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

        appended = False

        def _growing_fstat(fd: int) -> object:
            nonlocal appended
            if not appended:
                appended = True
                # Append real content so the for-loop has data to read
                with open(log_file, "a", encoding="utf-8") as af:
                    af.write("new line!\n")
            return type("FakeStat", (), {"st_size": 9999})()

        monkeypatch.setattr(
            "pkg_defender.cli.commands.logs.os.fstat",
            _growing_fstat,
        )

        def _exit_on_sleep(_delay: float) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", _exit_on_sleep)

        result = runner.invoke(cli, ["logs", "follow", "-n", "3"])

        assert "new line!" in result.output

    def test_follow_tailing_file_truncated(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """File truncated while tailing (lines 157-158).

        Root cause: ``logs.py`` lines 156-158 — when ``current_size <
        file_position`` (file was truncated), ``file_position`` resets
        to 0 and seeks to the beginning.

        We patch ``os.fstat`` to report a smaller file size on the
        tailing loop's call.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=10)

        # Always report a smaller-than-real file size to trigger
        # the ``current_size < file_position`` branch
        monkeypatch.setattr(
            "pkg_defender.cli.commands.logs.os.fstat",
            lambda fd: type("FakeStat", (), {"st_size": 5})(),
        )

        def _exit_on_sleep(_delay: float) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", _exit_on_sleep)

        # Should not raise — truncation branch resets position, then KeyboardInterrupt exits
        result = runner.invoke(cli, ["logs", "follow", "-n", "10"])
        assert result.exit_code == 0

    def test_follow_keyboard_interrupt(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """KeyboardInterrupt in the tailing loop is caught (line 161-162).

        Root cause: ``logs.py`` lines 161-162 — ``except KeyboardInterrupt``
        catches Ctrl+C and silently exits.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _setup_log_file(tmp_path, lines=5)

        def _exit_on_sleep(_delay: float) -> None:
            raise KeyboardInterrupt()

        monkeypatch.setattr("time.sleep", _exit_on_sleep)

        # Should not raise — KeyboardInterrupt is caught by the handler
        result = runner.invoke(cli, ["logs", "follow", "-n", "5"])
        assert result.exit_code == 0
