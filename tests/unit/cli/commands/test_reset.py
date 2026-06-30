"""Tests for the reset command (``pkgd reset``).

Covers both the non-teardown path (DB-only deletion) and the teardown path
(full cleanup including daemon uninstall, WAL/SHM/journal, logs, daemon state,
and config file).
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli.main import cli

pytestmark = pytest.mark.unit


class TestReset:
    """Tests for ``pkgd reset`` (non-teardown path, lines 215–235)."""

    def test_aborts_without_confirmation(self, runner: CliRunner) -> None:
        """When confirmation is declined, reset aborts with exit code 1."""
        with mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=False):
            result = runner.invoke(cli, ["reset"])

        assert result.exit_code == _EXIT_GENERAL_ERROR
        assert "Aborted." in result.output

    def test_no_data_shows_message(self, runner: CliRunner, tmp_path: Path) -> None:
        """When the database file does not exist, reset prints 'No data to reset'."""
        nonexistent_db = tmp_path / "threats.db"
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=nonexistent_db),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        assert any("No data to reset" in str(args) for args, _ in mock_print.call_args_list)

    def test_deletes_db_file(self, runner: CliRunner, tmp_path: Path) -> None:
        """When the database file exists, reset deletes it and shows the deleted path."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("fake db content")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        assert not db_file.exists(), "Database file should have been deleted"
        assert any("Deleted" in str(args) for args, _ in mock_print.call_args_list)

    def test_os_error_on_db_delete_shows_warning(self, runner: CliRunner, tmp_path: Path) -> None:
        """When the database file cannot be deleted, the error is caught and displayed."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("fake db content")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch.object(
                Path,
                "unlink",
                side_effect=OSError("Permission denied"),
            ),
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        assert db_file.exists(), "DB file should still exist (deletion failed)"
        assert "Warning: Could not delete" in result.output

    def test_trash_falls_back_to_unlink(self, runner: CliRunner, tmp_path: Path) -> None:
        """When ``trash`` command is unavailable, reset falls back to ``Path.unlink()``."""
        db_file = tmp_path / "threats.db"
        db_file.write_text("fake db content")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ) as mock_subproc,
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
        ):
            result = runner.invoke(cli, ["--yes", "reset"])

        assert result.exit_code == 0
        assert not db_file.exists(), "Database file should have been deleted via unlink fallback"
        # subprocess.run was called for the trash attempt
        mock_subproc.assert_called()


class TestResetTeardown:
    """Tests for ``pkgd reset --teardown`` (lines 80–213).

    Verifies the full teardown path: daemon uninstall, WAL/SHM/journal deletion,
    log file deletion, daemon state deletion, config deletion, and empty data
    directory removal.
    """

    def test_teardown_cancelled_returns_gracefully(self, runner: CliRunner, tmp_path: Path) -> None:
        """When teardown confirmation is declined, no files are deleted."""
        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("fake db")
        config_file = tmp_path / "config.toml"
        config_file.write_text("fake config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=False),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert db_file.exists(), "DB file should NOT have been deleted"
        assert any("Teardown cancelled" in str(args) for args, _ in mock_print.call_args_list)

    def test_teardown_deletes_all_files(self, runner: CliRunner, tmp_path: Path) -> None:
        """``--teardown`` deletes DB, WAL/SHM/journal, logs, daemon state, and config."""
        data_dir = tmp_path
        files = {
            "threats.db": "db",
            "threats.db-wal": "wal",
            "threats.db-shm": "shm",
            "threats.db-journal": "journal",
            "pkgd.log": "log",
            "pkgd.log.1": "log1",
            "pkgd.log.2": "log2",
            "pkgd.log.3": "log3",
            "pkgd.log.4": "log4",
            "pkgd.log.5": "log5",
            "daemon_stdout.log": "stdout",
            "daemon_stderr.log": "stderr",
            "daemon.pid": "12345",
            "daemon_heartbeat.json": "{}",
            "daemon.lock": "",
        }
        for name, content in files.items():
            (data_dir / name).write_text(content)

        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        for name in files:
            assert not (data_dir / name).exists(), f"{name} should have been deleted"
        assert not config_file.exists(), "Config file should have been deleted"

    def test_teardown_daemon_uninstall_failure_continues(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Daemon uninstall failure does not prevent file deletion."""
        from pkg_defender.daemon.service import LAUNCHD_LABEL

        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("db")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        # Create the plist file so is_installed=True (macOS path)
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text("plist content")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch("platform.system", return_value="Darwin"),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
            mock.patch(
                "pkg_defender.daemon.service.uninstall_service",
                side_effect=RuntimeError("service manager not found"),
            ),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert not db_file.exists(), "DB should have been deleted despite daemon error"
        assert not config_file.exists(), "Config should have been deleted despite daemon error"
        assert any("Warning: Could not uninstall daemon" in str(args) for args, _ in mock_print.call_args_list)

    def test_teardown_os_error_on_wal_file_continues(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """OSError on WAL file deletion logs a warning and continues with other files."""
        data_dir = tmp_path
        db_file = data_dir / "threats.db"
        db_file.write_text("db")
        wal_file = data_dir / "threats.db-wal"
        wal_file.write_text("wal")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        # Selective unlink: raise OSError only for the WAL file
        real_unlink = Path.unlink

        def selective_unlink(self_path: Path, *args: object, **kwargs: object) -> None:
            if "threats.db-wal" in str(self_path):
                raise OSError("File in use")
            return real_unlink(self_path)

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=db_file),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
            mock.patch.object(Path, "unlink", selective_unlink),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert not db_file.exists(), "DB file should have been deleted"
        assert wal_file.exists(), "WAL file should still exist (deletion failed)"
        assert not config_file.exists(), "Config file should have been deleted"
        # WAL warning uses click.echo (not console.print), so check result.output
        assert "Warning: Could not delete" in result.output

    def test_teardown_removes_empty_data_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        """After deleting all files, an empty data directory is removed."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "threats.db").write_text("db")
        (data_dir / "pkgd.log").write_text("log")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print"),
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        assert not data_dir.exists(), "Empty data directory should have been removed"

    def test_teardown_os_error_on_empty_dir_does_not_crash(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """OSError from ``rmdir()`` on empty dir does not crash the teardown."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "threats.db").write_text("db")
        config_file = tmp_path / "config.toml"
        config_file.write_text("config")

        with (
            mock.patch("pkg_defender.cli.commands.reset.get_db_path", return_value=data_dir / "threats.db"),
            mock.patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
            mock.patch(
                "pkg_defender.cli.commands.reset.get_default_config_path",
                return_value=config_file,
            ),
            mock.patch("pkg_defender.cli.commands.reset.console.print") as mock_print,
            mock.patch(
                "pkg_defender.cli.commands.reset.subprocess.run",
                side_effect=FileNotFoundError,
            ),
            mock.patch("pkg_defender.cli.commands.reset.click.confirm", return_value=True),
            mock.patch.object(Path, "rmdir", side_effect=OSError("Directory not empty")),
        ):
            result = runner.invoke(cli, ["--yes", "reset", "--teardown"])

        assert result.exit_code == 0
        # Other files should still be deleted
        assert not (data_dir / "threats.db").exists()
        assert not config_file.exists()
        # The teardown output should still show deleted files
        assert any("Teardown Complete" in str(args) for args, _ in mock_print.call_args_list)
