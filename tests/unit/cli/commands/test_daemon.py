"""Tests for pkg_defender.cli.commands.daemon module.

Covers all ``pkgd daemon`` subcommands: run, start, stop, status,
install, uninstall. Targets 90%+ line and branch coverage.

Mocking strategy
----------------
- ``is_quiet_mode()`` is patched to ``True`` to suppress Rich console
  output (avoids ANSI/rich rendering in test assertions).
- ``get_data_dir()`` **must** be patched at ``config.settings.get_data_dir``
  (not at the ``daemon`` module) because ``daemon.py`` uses **local imports**
  inside function bodies::

      from pkg_defender.config.settings import get_data_dir

  These resolve at call time from the source module, so the source
  module is the correct patch target.
- ``subprocess.Popen`` is patched for ``daemon start``.
- ``is_daemon_running``, ``read_heartbeat``, ``release_lock`` are
  patched at their definition module (``pkg_defender.daemon.runner``).
- ``install_service``, ``uninstall_service`` are patched at
  ``pkg_defender.daemon.service``.
"""

from __future__ import annotations

import errno
import signal
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli


def _patch_quiet_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Suppress Rich console output for daemon tests."""
    monkeypatch.setattr(
        "pkg_defender.cli.commands.daemon.is_quiet_mode",
        lambda: True,
    )


def _patch_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect data directory to a temp path.

    Patches at ``config.settings.get_data_dir`` because daemon commands
    use local imports (``from pkg_defender.config.settings import get_data_dir``)
    inside function bodies.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "pkg_defender.config.settings.get_data_dir",
        lambda: data_dir,
    )
    return data_dir


# ============================================================================
# TestDaemonGroup
# ============================================================================


class TestDaemonGroup:
    """Basic group-level behaviour."""

    def test_daemon_help(self, runner: CliRunner) -> None:
        """``pkgd daemon --help`` shows subcommands."""
        result = runner.invoke(cli, ["daemon", "--help"])
        assert result.exit_code == 0
        assert "run" in result.output
        assert "start" in result.output
        assert "stop" in result.output
        assert "status" in result.output
        assert "install" in result.output
        assert "uninstall" in result.output

    # Note: Lines 20-24 in daemon.py handle the ``invoked_subcommand is None``
    # case but are unreachable because the group does not set
    # ``invoke_without_command=True``. Those lines are effectively dead code.


# ============================================================================
# TestDaemonRun
# ============================================================================


class TestDaemonRun:
    """Tests for ``pkgd daemon run`` (foreground daemon)."""

    def test_run_delegates_to_runner(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``daemon run`` calls ``run_daemon()``.

        Root cause: ``daemon.py`` line 45 — the function delegates to
        ``pkg_defender.daemon.runner.run_daemon``.
        """
        mock_run = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.run_daemon",
            mock_run,
        )
        result = runner.invoke(cli, ["daemon", "run"])
        assert result.exit_code == 0
        mock_run.assert_called_once()


# ============================================================================
# TestDaemonStart
# ============================================================================


class TestDaemonStart:
    """Tests for ``pkgd daemon start``."""

    def test_start_when_already_running(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """When daemon is already running, prints message and returns.

        Root cause: ``daemon.py`` lines 73-77 — ``is_daemon_running``
        returns True, so the function returns early without starting.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at line 76 is exercised.
        """
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: True,
        )
        result = runner.invoke(cli, ["daemon", "start"])
        assert result.exit_code == 0
        assert "already running" in result.output

    def test_start_when_already_running_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Quiet mode suppresses "already running" message.

        Root cause: ``daemon.py`` line 74 — ``if not is_quiet_mode()``
        guard.
        """
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: True,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "start"])
        assert result.exit_code == 0

    def test_start_spawns_process(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """When daemon is not running, ``Popen`` is called and survives settle window.

        Root cause: ``daemon.py`` lines 80-93 — ``subprocess.Popen`` is
        called with ``[sys.executable, "-c", "from pkg_defender.cli.main
        import run_cli; run_cli(['daemon', 'run'])"]``, then a 2-second
        settle window confirms the process didn't crash immediately before
        writing the PID file.
        """
        mock_popen = MagicMock()
        mock_popen.return_value.poll.return_value = None  # process still running
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.subprocess.Popen",
            mock_popen,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        result = runner.invoke(cli, ["daemon", "start"])
        assert result.exit_code == 0
        assert "started" in result.output
        mock_popen.assert_called_once()

    def test_start_spawns_process_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Quiet mode suppresses "started" message.

        Root cause: ``daemon.py`` line 91 — ``if not is_quiet_mode()``
        guard.
        """
        mock_popen = MagicMock()
        mock_popen.return_value.poll.return_value = None  # process still running
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.subprocess.Popen",
            mock_popen,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "start"])
        assert result.exit_code == 0
        mock_popen.assert_called_once()

    def test_start_reports_failure_when_process_exits(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """When daemon process exits during settle window, reports failure.

        Root cause: ``daemon.py`` lines 97-99 — if ``proc.poll()`` returns
        a non-None value during the settle window, the daemon crashed on
        startup and an error message with exit code is displayed.
        """
        mock_popen = MagicMock()
        mock_popen.return_value.poll.return_value = 1  # process exited with code 1
        mock_popen.return_value.returncode = 1
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.subprocess.Popen",
            mock_popen,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        result = runner.invoke(cli, ["daemon", "start"])
        assert result.exit_code == 1
        assert "failed to start" in result.output.lower()

    def test_start_invokes_via_c_flag_direct_import(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``daemon start`` uses ``-c`` with direct import, not ``-m``.

        The subprocess must use
        ``-c "from pkg_defender.cli.main import run_cli; run_cli(...)"``
        to avoid double-execution via the ``-m`` module runner.
        """
        mock_popen = MagicMock()
        mock_popen.return_value.poll.return_value = None  # process still running
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.is_daemon_running",
            lambda data_dir: False,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.subprocess.Popen",
            mock_popen,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        runner.invoke(cli, ["daemon", "start"])

        call_args = mock_popen.call_args[0][0]  # first positional arg = command list
        assert call_args[0] == sys.executable
        assert call_args[1] == "-c"
        assert "from pkg_defender.cli.main import run_cli" in call_args[2]
        assert "-m" not in call_args


# ============================================================================
# TestDaemonStop
# ============================================================================


class TestDaemonStop:
    """Tests for ``pkgd daemon stop``."""

    def test_stop_not_running(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When no heartbeat exists, prints message and returns.

        Root cause: ``daemon.py`` lines 116-120 — ``heartbeat_path.exists()``
        is False, so early return with message.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at line 119 is exercised.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "not appear to be running" in result.output

    def test_stop_not_running_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Quiet mode suppresses "not running" message.

        Root cause: ``daemon.py`` line 117 — ``is_quiet_mode`` check.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0

    def test_stop_removes_heartbeat(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """No PID file but heartbeat exists → legacy fallback: remove heartbeat.

        Root cause: ``daemon.py`` lines 192-196 — the
        ``elif heartbeat_path.exists()`` branch handles daemons that were
        started without a PID file (legacy path). The heartbeat is removed
        and ``release_lock`` is called. The daemon stops at end of cycle.

        This test runs with ``is_quiet_mode() == False`` so the
        ``click.echo`` at lines 195-196 and 199-200 are exercised.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        heartbeat = data_dir / "daemon_heartbeat.json"
        heartbeat.write_text('{"status": "ok"}')

        mock_release = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            mock_release,
        )
        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert not heartbeat.exists()
        assert "Heartbeat removed" in result.output
        assert "Daemon stopped." in result.output
        mock_release.assert_called_once()

    def test_stop_removes_heartbeat_quiet(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Quiet mode suppresses all output in the legacy heartbeat-only path.

        Root cause: ``daemon.py`` lines 192-196 — the ``elif heartbeat_path.exists()``
        legacy branch. The ``is_quiet_mode()`` guard at line 195 suppresses
        "Heartbeat removed"; the guard at line 199 suppresses "Daemon stopped."
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        heartbeat = data_dir / "daemon_heartbeat.json"
        heartbeat.write_text('{"status": "ok"}')

        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            MagicMock(),
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0


# ============================================================================
# TestDaemonStopSigterm
# ============================================================================


class TestDaemonStopSigterm:
    """Tests for SIGTERM-based daemon stop (PID-file path).

    Covers all branches of the ``daemon_stop()`` PID-file logic
    (``daemon.py`` lines 141-200):
    - Valid PID + graceful shutdown
    - Stale PID file (ESRCH)
    - Corrupt PID file
    - SIGTERM timeout -> SIGKILL fallback
    - PID file without heartbeat
    - Heartbeat-only legacy path
    - Not running at all
    """

    def test_stop_with_valid_pid_sends_sigterm(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Valid PID, process exists -> SIGTERM sent -> process dies -> cleanup.

        Root cause: ``daemon.py`` lines 168-180 -- ``os.kill(pid, signal.SIGTERM)``
        is sent, and the wait loop detects ESRCH and breaks early.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        pid = 12345
        pid_file = data_dir / "daemon.pid"
        pid_file.write_text(str(pid))

        mock_kill = MagicMock()
        # Call 1: os.kill(pid, 0) -- check if process exists -> succeeds
        # Call 2: os.kill(pid, SIGTERM) -- send SIGTERM -> succeeds
        # Call 3: os.kill(pid, 0) -- check if died -> ESRCH (process gone)
        mock_kill.side_effect = [
            None,
            None,
            OSError(errno.ESRCH, "No such process"),
        ]
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.os.kill",
            mock_kill,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            MagicMock(),
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "SIGTERM" in result.output
        assert "Daemon stopped." in result.output
        assert not pid_file.exists()
        mock_kill.assert_any_call(pid, signal.SIGTERM)

    def test_stop_with_stale_pid_esrch(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PID file exists, process gone -> ESRCH -> clean up and report stale.

        Root cause: ``daemon.py`` lines 157-165 -- ``os.kill(pid, 0)`` raises
        ``OSError`` with ``errno.ESRCH``, leading to early return with cleanup.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        pid = 12345
        pid_file = data_dir / "daemon.pid"
        pid_file.write_text(str(pid))

        mock_kill = MagicMock()
        mock_kill.side_effect = [
            OSError(errno.ESRCH, "No such process"),
        ]
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.os.kill",
            mock_kill,
        )
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            MagicMock(),
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "stale PID" in result.output or "already stopped" in result.output
        assert not pid_file.exists()

    def test_stop_with_corrupt_pid_file(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PID file content is not a valid int -> ValueError -> cleanup.

        Root cause: ``daemon.py`` line 144 -- ``int(pid_path.read_text().strip())``
        raises ``ValueError``, caught at line 145. Never calls ``os.kill``.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        pid_file = data_dir / "daemon.pid"
        pid_file.write_text("not-a-number")

        mock_release = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            mock_release,
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "corrupt PID" in result.output
        assert not pid_file.exists()
        mock_release.assert_called_once()

    @pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL is POSIX-only")
    def test_stop_sigterm_then_sigkill(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """SIGTERM sent, process still alive after 5s -> SIGKILL fallback.

        Root cause: ``daemon.py`` lines 181-186 -- the ``for`` loop's ``else``
        clause fires when no ESRCH was detected during the 5-second wait,
        causing ``os.kill(pid, signal.SIGKILL)``.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        pid = 12345
        pid_file = data_dir / "daemon.pid"
        pid_file.write_text(str(pid))

        mock_kill = MagicMock()
        # Call 1: os.kill(pid, 0) -- check if exists
        # Call 2: os.kill(pid, SIGTERM)
        # Calls 3-7: os.kill(pid, 0) -- loop: 5 iterations, all succeed
        # Call 8: os.kill(pid, SIGKILL) -- force kill
        mock_kill.side_effect = [
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.os.kill",
            mock_kill,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            MagicMock(),
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "SIGTERM" in result.output
        assert "SIGKILL" in result.output
        assert not pid_file.exists()
        mock_kill.assert_any_call(pid, signal.SIGKILL)

    def test_stop_pid_no_heartbeat_cleanup(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PID file exists, no heartbeat file -- still works (cleanup PID file).

        Root cause: ``daemon.py`` lines 141, 189 -- the ``pid_path.exists()``
        branch is entered regardless of whether the heartbeat file exists.
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        pid = 12345
        pid_file = data_dir / "daemon.pid"
        pid_file.write_text(str(pid))
        # Intentionally no heartbeat file

        mock_kill = MagicMock()
        mock_kill.side_effect = [
            None,
            None,
            OSError(errno.ESRCH, "No such process"),
        ]
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.os.kill",
            mock_kill,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.time.sleep",
            lambda s: None,
        )
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            MagicMock(),
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert not pid_file.exists()

    def test_stop_heartbeat_without_pid_fallback(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No PID file, heartbeat exists -- legacy fallback.

        Root cause: ``daemon.py`` lines 192-196 -- the
        ``elif heartbeat_path.exists()`` branch handles daemons started
        without a PID file (legacy foreground-run path).
        """
        data_dir = _patch_data_dir(monkeypatch, tmp_path)
        heartbeat = data_dir / "daemon_heartbeat.json"
        heartbeat.write_text('{"status": "ok"}')

        mock_release = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.release_lock",
            mock_release,
        )

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert not heartbeat.exists()
        assert "Heartbeat removed" in result.output
        assert "Daemon stopped." in result.output
        mock_release.assert_called_once()

    def test_stop_not_running_no_files(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No PID file, no heartbeat -- "not running" early return.

        Root cause: ``daemon.py`` lines 136-139 -- the
        ``not pid_path.exists() and not heartbeat_path.exists()`` guard
        triggers early return with message.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        # Intentionally no PID file and no heartbeat file

        result = runner.invoke(cli, ["daemon", "stop"])
        assert result.exit_code == 0
        assert "not appear to be running" in result.output


# ============================================================================
# TestDaemonStatus
# ============================================================================


class TestDaemonStatus:
    """Tests for ``pkgd daemon status``."""

    def test_status_not_running(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When no heartbeat, exits 1 with error message.

        Root cause: ``daemon.py`` lines 157-162 — ``read_heartbeat``
        returns ``None``, so ``SystemExit(1)`` is raised.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at lines 160-161 are exercised.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: None,
        )
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 1
        assert "not running" in result.output

    def test_status_not_running_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Quiet mode suppresses "not running" message."""
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: None,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 1

    def test_status_running_ok(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """When heartbeat is present and status is 'ok', display OK.

        Root cause: ``daemon.py`` lines 164-183 — the heartbeat data is
        read, status color is green, feeds table is displayed.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at lines 171-172 and 178-183 are exercised.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: {
                "status": "ok",
                "last_sync": "2026-05-29T10:00:00",
                "error": None,
                "feeds": {"osv": 150},
            },
        )
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 0
        assert "Status:" in result.output

    def test_status_with_error(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Heartbeat with error displays error line.

        Root cause: ``daemon.py`` lines 174-175 — ``if error:`` branch
        prints the error to stderr.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: {
                "status": "error",
                "last_sync": "2026-05-29T10:00:00",
                "error": "Sync failed",
                "feeds": {},
            },
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 0
        assert "Error" in result.output

    def test_status_no_feeds(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Heartbeat with empty feeds does not display feed table.

        Root cause: ``daemon.py`` line 177 — ``if feeds and not is_quiet_mode()``
        guards feed table display.
        """
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: {
                "status": "ok",
                "last_sync": "2026-05-29T10:00:00",
                "error": None,
                "feeds": {},
            },
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 0

    def test_status_quiet_mode_no_output(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Quiet mode suppresses all status output.

        Root cause: multiple ``if not is_quiet_mode():`` guards in the
        status handler (lines 158, 169, 177).
        """
        _patch_data_dir(monkeypatch, tmp_path)
        monkeypatch.setattr(
            "pkg_defender.daemon.runner.read_heartbeat",
            lambda data_dir, **kw: {
                "status": "ok",
                "last_sync": "2026-05-29T10:00:00",
                "error": "something",
                "feeds": {"osv": 1},
            },
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "status"])
        assert result.exit_code == 0


# ============================================================================
# TestDaemonInstall
# ============================================================================


class TestDaemonInstall:
    """Tests for ``pkgd daemon install``."""

    def test_install_success(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``daemon install`` calls ``install_service`` with no platform.

        Root cause: ``daemon.py`` lines 216-226 — ``install_service`` is
        called with ``platform_name=None``, and the result path is displayed.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at line 220 is exercised.
        """
        mock_install = MagicMock(return_value=Path("/tmp/service.plist"))
        monkeypatch.setattr(
            "pkg_defender.daemon.service.install_service",
            mock_install,
        )
        result = runner.invoke(cli, ["daemon", "install"])
        assert result.exit_code == 0
        assert "Service installed" in result.output
        mock_install.assert_called_once_with(platform_name=None)

    def test_install_success_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Quiet mode suppresses "Service installed" message."""
        mock_install = MagicMock(return_value=Path("/tmp/service.plist"))
        monkeypatch.setattr(
            "pkg_defender.daemon.service.install_service",
            mock_install,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "install"])
        assert result.exit_code == 0
        mock_install.assert_called_once_with(platform_name=None)

    def test_install_with_platform(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``--platform linux`` is passed through to ``install_service``.

        Root cause: ``daemon.py`` line 217 — ``platform`` option value
        (or ``None``) is forwarded to ``install_service``.
        """
        mock_install = MagicMock(return_value=Path("/tmp/pkgd.service"))
        monkeypatch.setattr(
            "pkg_defender.daemon.service.install_service",
            mock_install,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "install", "--platform", "linux"])
        assert result.exit_code == 0
        mock_install.assert_called_once_with(platform_name="linux")

    def test_install_value_error(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``install_service`` raises ``ValueError`` → error message.

        Root cause: ``daemon.py`` lines 221-226 — ``ValueError`` is
        caught, error message printed, ``SystemExit(1)`` raised.
        """
        monkeypatch.setattr(
            "pkg_defender.daemon.service.install_service",
            MagicMock(side_effect=ValueError("Unknown platform")),
        )
        result = runner.invoke(cli, ["daemon", "install"])
        assert result.exit_code == 1
        assert "Error" in result.output

    def test_install_file_not_found(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``install_service`` raises ``FileNotFoundError`` → error message.

        Root cause: ``daemon.py`` line 221 — ``FileNotFoundError`` is
        also caught.
        """
        monkeypatch.setattr(
            "pkg_defender.daemon.service.install_service",
            MagicMock(side_effect=FileNotFoundError("pkgd binary not found")),
        )
        result = runner.invoke(cli, ["daemon", "install"])
        assert result.exit_code == 1
        assert "Error" in result.output


# ============================================================================
# TestDaemonUninstall
# ============================================================================


class TestDaemonUninstall:
    """Tests for ``pkgd daemon uninstall``."""

    def test_uninstall_success(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``daemon uninstall`` calls ``uninstall_service()``.

        Root cause: ``daemon.py`` lines 251-255 — ``uninstall_service()``
        is called and success message printed.

        This test runs with ``is_quiet_mode() == False`` so the
        ``console.print`` at line 255 is exercised.
        """
        mock_uninstall = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.service.uninstall_service",
            mock_uninstall,
        )
        result = runner.invoke(cli, ["daemon", "uninstall"])
        assert result.exit_code == 0
        assert "Service uninstalled" in result.output
        mock_uninstall.assert_called_once()

    def test_uninstall_success_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Quiet mode suppresses "Service uninstalled" message."""
        mock_uninstall = MagicMock()
        monkeypatch.setattr(
            "pkg_defender.daemon.service.uninstall_service",
            mock_uninstall,
        )
        _patch_quiet_mode(monkeypatch)
        result = runner.invoke(cli, ["daemon", "uninstall"])
        assert result.exit_code == 0
        mock_uninstall.assert_called_once()

    def test_uninstall_value_error(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """``uninstall_service`` raises ``ValueError`` → error message.

        Root cause: ``daemon.py`` lines 256-258 — ``ValueError`` is
        caught, error printed, ``SystemExit(1)`` raised.
        """
        monkeypatch.setattr(
            "pkg_defender.daemon.service.uninstall_service",
            MagicMock(side_effect=ValueError("Unknown platform")),
        )
        result = runner.invoke(cli, ["daemon", "uninstall"])
        assert result.exit_code == 1
        assert "Error" in result.output


# ============================================================================
# TestDaemonRestart
# ============================================================================


class TestDaemonRestart:
    """Tests for the daemon restart command."""

    def test_restart_when_running(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Restart calls stop then start when daemon is running."""
        stop_called: list[bool] = []
        start_called: list[bool] = []

        def _mock_stop(**kwargs: Any) -> None:
            stop_called.append(True)

        def _mock_start() -> None:
            start_called.append(True)

        monkeypatch.setattr("pkg_defender.cli.commands.daemon._stop_daemon", _mock_stop)
        monkeypatch.setattr("pkg_defender.cli.commands.daemon._start_daemon", _mock_start)
        # Ensure not quiet so we get the success message
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.is_quiet_mode",
            lambda: False,
        )

        result = runner.invoke(cli, ["daemon", "restart"])
        assert result.exit_code == 0
        assert stop_called, "_stop_daemon was not called"
        assert start_called, "_start_daemon was not called"
        assert "Daemon restarted" in result.output

    def test_restart_when_not_running(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Restart still calls start even when daemon was not running."""
        start_called: list[bool] = []

        def _mock_stop(**kwargs: Any) -> None:
            pass  # _stop_daemon handles "not running" gracefully

        def _mock_start() -> None:
            start_called.append(True)

        monkeypatch.setattr("pkg_defender.cli.commands.daemon._stop_daemon", _mock_stop)
        monkeypatch.setattr("pkg_defender.cli.commands.daemon._start_daemon", _mock_start)
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.is_quiet_mode",
            lambda: False,
        )

        result = runner.invoke(cli, ["daemon", "restart"])
        assert result.exit_code == 0
        assert start_called, "_start_daemon was not called"

    def test_restart_quiet(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        """Quiet restart suppresses success message."""
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon._stop_daemon",
            lambda **kwargs: None,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon._start_daemon",
            lambda: None,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon.is_quiet_mode",
            lambda: True,
        )

        result = runner.invoke(cli, ["daemon", "restart"])
        assert result.exit_code == 0
        assert "Daemon restarted" not in result.output

    def test_restart_calls_stop_then_start(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Restart calls ``_stop_daemon`` then ``_start_daemon``.

        Uses mocks on the private helpers to verify the call sequence
        WITHOUT invoking real process management. If this test passes,
        the TypeError crash from calling a Click command programmatically
        is fixed.
        """
        call_sequence: list[str] = []
        _patch_data_dir(monkeypatch, tmp_path)

        def _mock_stop(*args: Any, **kwargs: Any) -> None:
            call_sequence.append("stop")

        def _mock_start() -> None:
            call_sequence.append("start")

        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon._stop_daemon",
            _mock_stop,
        )
        monkeypatch.setattr(
            "pkg_defender.cli.commands.daemon._start_daemon",
            _mock_start,
        )

        result = runner.invoke(cli, ["daemon", "restart"])
        assert result.exit_code == 0
        assert call_sequence == ["stop", "start"], f"Expected stop then start, got {call_sequence}"

    def test_restart_help(self, runner: CliRunner) -> None:
        """Help text mentions restart."""
        result = runner.invoke(cli, ["daemon", "--help"])
        assert result.exit_code == 0
        assert "restart" in result.output
