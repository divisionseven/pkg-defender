"""Tests for the background daemon — heartbeat, service generators, CLI commands."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from pkg_defender.daemon.runner import (
    HEARTBEAT_FILENAME,
    acquire_single_instance_lock,
    is_daemon_running,
    read_heartbeat,
    release_lock,
    write_heartbeat,
)
from pkg_defender.daemon.service import (
    LAUNCHD_LABEL,
    SYSTEMD_SERVICE_NAME,
    generate_launchd_plist,
    generate_scheduled_task_xml,
    generate_systemd_unit,
    install_service,
    uninstall_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    """Provide an isolated data directory for heartbeat tests."""
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture(autouse=True)
def close_unawaited_coroutines() -> Generator[None, None, None]:
    """Close any unawaited coroutines after each test to prevent RuntimeWarning.

    This fixture ensures that any coroutine created during a test but not awaited
    is properly closed before garbage collection. Without this, Python's GC can
    trigger RuntimeWarning about unawaited coroutines during test teardown.
    """
    import gc
    import warnings

    yield

    # Suppress RuntimeWarning during cleanup and force garbage collection
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning)
        gc.collect()


# ---------------------------------------------------------------------------
# write_heartbeat tests
# ---------------------------------------------------------------------------


class TestWriteHeartbeat:
    """Tests for write_heartbeat()."""

    def test_creates_correct_json(self, data_dir: Path) -> None:
        """Heartbeat file must contain the exact status dict as JSON."""
        status = {
            "last_sync": "2026-04-01T12:00:00+00:00",
            "status": "ok",
            "error": None,
            "feeds": {"osv": 42, "ghsa": 7},
        }

        write_heartbeat(data_dir, status)

        hb_path = data_dir / HEARTBEAT_FILENAME
        assert hb_path.exists()

        with open(hb_path, encoding="utf-8") as fh:
            loaded = json.load(fh)

        assert loaded["last_sync"] == "2026-04-01T12:00:00+00:00"
        assert loaded["status"] == "ok"
        assert loaded["error"] is None
        assert loaded["feeds"] == {"osv": 42, "ghsa": 7}

    def test_creates_data_dir_if_missing(self, tmp_path: Path) -> None:
        """write_heartbeat should create the data directory if it doesn't exist."""
        missing_dir = tmp_path / "nonexistent" / "deep"
        status: dict[str, Any] = {
            "last_sync": "2026-04-01T00:00:00+00:00",
            "status": "ok",
            "error": None,
            "feeds": {},
        }

        write_heartbeat(missing_dir, status)

        assert (missing_dir / HEARTBEAT_FILENAME).exists()

    def test_overwrites_existing_heartbeat(self, data_dir: Path) -> None:
        """Second write should overwrite the first."""
        write_heartbeat(data_dir, {"last_sync": "t1", "status": "ok", "error": None, "feeds": {}})
        write_heartbeat(data_dir, {"last_sync": "t2", "status": "error", "error": "oops", "feeds": {"osv": 0}})

        with open(data_dir / HEARTBEAT_FILENAME, encoding="utf-8") as fh:
            loaded = json.load(fh)

        assert loaded["status"] == "error"
        assert loaded["last_sync"] == "t2"

    def test_error_status_records_message(self, data_dir: Path) -> None:
        """Error status must include the error string."""
        write_heartbeat(
            data_dir,
            {
                "last_sync": datetime.now(UTC).isoformat(),
                "status": "error",
                "error": "Connection refused",
                "feeds": {},
            },
        )

        loaded = read_heartbeat(data_dir)
        assert loaded is not None
        assert loaded["status"] == "error"
        assert loaded["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# read_heartbeat tests
# ---------------------------------------------------------------------------


class TestReadHeartbeat:
    """Tests for read_heartbeat()."""

    def test_returns_data_for_fresh_heartbeat(self, data_dir: Path) -> None:
        """A just-written heartbeat should be returned."""
        status = {
            "last_sync": datetime.now(UTC).isoformat(),
            "status": "ok",
            "error": None,
            "feeds": {"osv": 10},
        }
        write_heartbeat(data_dir, status)

        result = read_heartbeat(data_dir)
        assert result is not None
        assert result["status"] == "ok"
        assert result["feeds"]["osv"] == 10

    def test_returns_none_for_missing_file(self, data_dir: Path) -> None:
        """No heartbeat file → None."""
        assert read_heartbeat(data_dir) is None

    def test_returns_none_for_stale_heartbeat(self, data_dir: Path) -> None:
        """Heartbeat older than staleness threshold → None."""
        stale_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        write_heartbeat(
            data_dir,
            {
                "last_sync": stale_time,
                "status": "ok",
                "error": None,
                "feeds": {},
            },
        )

        assert read_heartbeat(data_dir) is None

    def test_returns_none_for_corrupt_json(self, data_dir: Path) -> None:
        """Corrupt JSON file → None (no exception)."""
        hb_path = data_dir / HEARTBEAT_FILENAME
        hb_path.write_text("not valid json {{{", encoding="utf-8")

        assert read_heartbeat(data_dir) is None

    def test_returns_none_when_no_last_sync_key(self, data_dir: Path) -> None:
        """Missing last_sync field → None (can't check staleness)."""
        hb_path = data_dir / HEARTBEAT_FILENAME
        hb_path.write_text('{"status": "ok"}', encoding="utf-8")

        # Without last_sync, staleness can't be determined — return None
        assert read_heartbeat(data_dir) is None

    def test_boundary_freshness(self, data_dir: Path) -> None:
        """Heartbeat just under the explicit 24-hour override is still fresh.

        Passes staleness_threshold_hours=24 explicitly because the config
        default changed from 24 to 8 (P2-B fix). This test validates the
        staleness comparison logic, not the specific default value.
        """
        almost_stale = (datetime.now(UTC) - timedelta(hours=23, minutes=59)).isoformat()
        write_heartbeat(
            data_dir,
            {
                "last_sync": almost_stale,
                "status": "ok",
                "error": None,
                "feeds": {},
            },
        )

        result = read_heartbeat(data_dir, staleness_threshold_hours=24)
        assert result is not None


# ---------------------------------------------------------------------------
# is_daemon_running tests
# ---------------------------------------------------------------------------


class TestIsDaemonRunning:
    """Tests for is_daemon_running()."""

    def test_true_with_fresh_heartbeat(self, data_dir: Path) -> None:
        """Fresh heartbeat → daemon is running."""
        write_heartbeat(
            data_dir,
            {
                "last_sync": datetime.now(UTC).isoformat(),
                "status": "ok",
                "error": None,
                "feeds": {},
            },
        )
        assert is_daemon_running(data_dir) is True

    def test_false_with_stale_heartbeat(self, data_dir: Path) -> None:
        """Stale heartbeat → daemon is not running."""
        stale_time = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        write_heartbeat(
            data_dir,
            {
                "last_sync": stale_time,
                "status": "ok",
                "error": None,
                "feeds": {},
            },
        )
        assert is_daemon_running(data_dir) is False

    def test_false_with_missing_heartbeat(self, data_dir: Path) -> None:
        """No heartbeat file → daemon is not running."""
        assert is_daemon_running(data_dir) is False


# ---------------------------------------------------------------------------
# generate_launchd_plist tests
# ---------------------------------------------------------------------------


class TestGenerateLaunchdPlist:
    """Tests for generate_launchd_plist()."""

    def test_produces_valid_xml(self, pq_binary: Path, tmp_path: Path) -> None:
        """Generated plist must be valid XML containing required keys."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"

        xml_str = generate_launchd_plist(pq_binary, config_path, data_dir)

        # Basic XML structure checks
        assert xml_str.strip().startswith("<?xml")
        assert "<plist" in xml_str
        assert "</plist>" in xml_str

        # Required keys
        assert f"<string>{LAUNCHD_LABEL}</string>" in xml_str
        assert f"<string>{pq_binary}</string>" in xml_str
        assert "<string>daemon</string>" in xml_str
        assert "<string>run</string>" in xml_str
        assert "<key>KeepAlive</key>" in xml_str
        assert "<true/>" in xml_str

    def test_includes_log_paths(self, pq_binary: Path, tmp_path: Path) -> None:
        """Stdout/stderr paths must be under data_dir."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"

        xml_str = generate_launchd_plist(pq_binary, config_path, data_dir)

        assert "daemon_stdout.log" in xml_str
        assert "daemon_stderr.log" in xml_str
        assert str(data_dir) in xml_str

    def test_includes_config_env_var(self, pq_binary: Path, tmp_path: Path) -> None:
        """Config path must be set as environment variable."""
        config_path = tmp_path / "my-config.toml"
        data_dir = tmp_path / "data"

        xml_str = generate_launchd_plist(pq_binary, config_path, data_dir)

        assert "PKGD_CONFIG_PATH" in xml_str
        assert str(config_path) in xml_str

    def test_includes_path_env_var(self) -> None:
        """launchd plist includes PATH in EnvironmentVariables."""
        xml_str = generate_launchd_plist(
            pq_binary=Path("/opt/homebrew/bin/pkgd"),
            config_path=Path("/Users/test/.config/pkg-defender/pkgd.toml"),
            data_dir=Path("/Users/test/Library/Application Support/pkg-defender"),
        )
        assert "<key>PATH</key>" in xml_str
        assert "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" in xml_str


# ---------------------------------------------------------------------------
# generate_systemd_unit tests
# ---------------------------------------------------------------------------


class TestGenerateSystemdUnit:
    """Tests for generate_systemd_unit()."""

    def test_produces_valid_unit(self, pq_binary: Path, tmp_path: Path) -> None:
        """Generated unit must contain required systemd sections."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"

        unit_str = generate_systemd_unit(pq_binary, config_path, data_dir)

        assert "[Unit]" in unit_str
        assert "[Service]" in unit_str
        assert "[Install]" in unit_str
        assert "Type=simple" in unit_str
        assert "Restart=on-failure" in unit_str
        assert "RestartSec=60" in unit_str

    def test_returns_exec_start_with_daemon_run_command(self, pq_binary: Path, tmp_path: Path) -> None:
        """ExecStart must invoke 'pkgd daemon run'."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"

        unit_str = generate_systemd_unit(pq_binary, config_path, data_dir)

        assert f"ExecStart={pq_binary} daemon run" in unit_str

    def test_wanted_by_default_target(self, pq_binary: Path, tmp_path: Path) -> None:
        """Install section must target default.target."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"

        unit_str = generate_systemd_unit(pq_binary, config_path, data_dir)

        assert "WantedBy=default.target" in unit_str

    def test_includes_path_env_var(self) -> None:
        """systemd unit includes PATH in Environment directive."""
        home = "/home/testuser"
        unit_str = generate_systemd_unit(
            pq_binary=Path("/usr/local/bin/pkgd"),
            config_path=Path("/home/testuser/.config/pkg-defender/pkgd.toml"),
            data_dir=Path("/home/testuser/.local/share/pkg-defender"),
            home=home,
        )
        assert "Environment=PATH=" in unit_str
        assert f"{home}/.local/bin" in unit_str


# ---------------------------------------------------------------------------
# generate_scheduled_task_xml tests
# ---------------------------------------------------------------------------


class TestGenerateScheduledTaskXml:
    """Tests for generate_scheduled_task_xml()."""

    def test_produces_valid_xml(self, pq_binary: Path, tmp_path: Path) -> None:
        """Generated Task Scheduler XML must be parseable."""
        config_path = tmp_path / "config.toml"
        data_dir = tmp_path / "data"
        xml_str = generate_scheduled_task_xml(pq_binary, config_path, data_dir)

        assert xml_str.strip().startswith("<?xml")
        assert "<Task" in xml_str
        assert "</Task>" in xml_str
        assert "PT4H" in xml_str  # 4-hour interval

    def test_includes_pkgd_binary(self) -> None:
        """Scheduled task XML wraps binary in cmd.exe with config_path."""
        xml_str = generate_scheduled_task_xml(
            pq_binary=Path("C:\\tools\\pkgd.exe"),
            config_path=Path("C:\\Users\\test\\.config\\pkg-defender\\pkgd.toml"),
            data_dir=Path("C:\\Users\\test\\AppData\\Local\\pkg-defender"),
        )
        assert "<Command>cmd</Command>" in xml_str

        xml_str = generate_scheduled_task_xml(
            pq_binary=Path("C:\\tools\\pkgd.exe"),
            config_path=Path("C:\\Users\\test\\.config\\pkg-defender\\pkgd.toml"),
            data_dir=Path("C:\\Users\\test\\AppData\\Local\\pkg-defender"),
        )
        # Should NOT contain the old hardcoded date
        assert "2026-01-01" not in xml_str
        # Should contain today's date in ISO format
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        assert today in xml_str

    def test_includes_config_path(self) -> None:
        """Scheduled task XML sets PKGD_CONFIG_PATH."""
        xml_str = generate_scheduled_task_xml(
            pq_binary=Path("C:\\tools\\pkgd.exe"),
            config_path=Path("C:\\Users\\test\\.config\\pkg-defender\\pkgd.toml"),
            data_dir=Path("C:\\Users\\test\\AppData\\Local\\pkg-defender"),
        )
        assert "PKGD_CONFIG_PATH" in xml_str


# ---------------------------------------------------------------------------
# install_service tests
# ---------------------------------------------------------------------------


class TestInstallService:
    """Tests for install_service()."""

    def test_macos_creates_plist(self, tmp_path: Path, pq_binary: Path) -> None:
        """macOS install should create a .plist in a LaunchAgents-like dir."""
        launch_agents = tmp_path / "Library" / "LaunchAgents"
        launch_agents.mkdir(parents=True)

        with (
            patch(
                "pkg_defender.daemon.service.Path.home",
                return_value=tmp_path,
            ),
            patch(
                "pkg_defender.config.settings.get_config_dir",
                return_value=tmp_path / "config",
            ),
            patch(
                "pkg_defender.config.settings.get_data_dir",
                return_value=tmp_path / "data",
            ),
        ):
            result = install_service(platform_name="macos", pq_binary=pq_binary)

        assert result.name == f"{LAUNCHD_LABEL}.plist"
        assert result.exists()
        content = result.read_text()
        assert LAUNCHD_LABEL in content

    def test_linux_creates_service(self, tmp_path: Path, pq_binary: Path) -> None:
        """Linux install should create a .service in systemd user dir."""
        with (
            patch(
                "pkg_defender.daemon.service.Path.home",
                return_value=tmp_path,
            ),
            patch(
                "pkg_defender.config.settings.get_config_dir",
                return_value=tmp_path / "config",
            ),
            patch(
                "pkg_defender.config.settings.get_data_dir",
                return_value=tmp_path / "data",
            ),
        ):
            result = install_service(platform_name="linux", pq_binary=pq_binary)

        assert result.name == f"{SYSTEMD_SERVICE_NAME}.service"
        assert result.exists()
        content = result.read_text()
        assert "[Service]" in content

    def test_windows_creates_xml(self, tmp_path: Path, pq_binary: Path) -> None:
        """Windows install should create a Task Scheduler XML."""
        with (
            patch(
                "pkg_defender.config.settings.get_config_dir",
                return_value=tmp_path / "config",
            ),
            patch(
                "pkg_defender.config.settings.get_data_dir",
                return_value=tmp_path / "data",
            ),
        ):
            result = install_service(platform_name="windows", pq_binary=pq_binary)

        assert result.name.endswith("-task.xml")
        assert result.exists()
        content = result.read_text()
        assert "<Task" in content

    def test_invalid_platform_raises(self, pq_binary: Path) -> None:
        """Unknown platform must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown platform"):
            install_service(platform_name="solaris", pq_binary=pq_binary)


# ---------------------------------------------------------------------------
# uninstall_service tests
# ---------------------------------------------------------------------------


class TestUninstallService:
    """Tests for uninstall_service()."""

    def test_macos_removes_plist(self, tmp_path: Path) -> None:
        """macOS uninstall should remove the plist file."""
        launch_agents = tmp_path / "Library" / "LaunchAgents"
        launch_agents.mkdir(parents=True)
        plist = launch_agents / f"{LAUNCHD_LABEL}.plist"
        plist.write_text("<plist/>")

        with patch(
            "pkg_defender.daemon.service.Path.home",
            return_value=tmp_path,
        ):
            uninstall_service(platform_name="macos")

        assert not plist.exists()

    def test_linux_removes_service(self, tmp_path: Path) -> None:
        """Linux uninstall should remove the systemd unit."""
        unit_dir = tmp_path / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        unit = unit_dir / f"{SYSTEMD_SERVICE_NAME}.service"
        unit.write_text("[Service]\nType=simple\n")

        with patch(
            "pkg_defender.daemon.service.Path.home",
            return_value=tmp_path,
        ):
            uninstall_service(platform_name="linux")

        assert not unit.exists()

    def test_uninstall_nonexistent_is_noop(self, tmp_path: Path) -> None:
        """Uninstalling when no service exists should not raise."""
        with patch(
            "pkg_defender.daemon.service.Path.home",
            return_value=tmp_path,
        ):
            # Should not raise
            uninstall_service(platform_name="macos")
            uninstall_service(platform_name="linux")


# ---------------------------------------------------------------------------
# CLI — daemon status command
# ---------------------------------------------------------------------------


class TestDaemonStatusCli:
    """Tests for the 'pkgd daemon status' CLI command."""

    def test_status_no_heartbeat_exits_1(self, tmp_path: Path) -> None:
        """pkgd daemon status with no heartbeat → exit 1."""
        from pkg_defender.cli.main import cli

        with patch(
            "pkg_defender.config.settings.get_data_dir",
            return_value=tmp_path,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, ["daemon", "status"])

        assert result.exit_code == 1
        assert "not running" in result.output.lower()

    def test_status_fresh_heartbeat_shows_ok(self, tmp_path: Path) -> None:
        """pkgd daemon status with fresh heartbeat → shows ok status."""
        from pkg_defender.cli.main import cli

        # Write a fresh heartbeat
        write_heartbeat(
            tmp_path,
            {
                "last_sync": datetime.now(UTC).isoformat(),
                "status": "ok",
                "error": None,
                "feeds": {"osv": 5, "ghsa": 3},
            },
        )

        with patch(
            "pkg_defender.config.settings.get_data_dir",
            return_value=tmp_path,
        ):
            runner = CliRunner()
            result = runner.invoke(cli, ["daemon", "status"])

        assert result.exit_code == 0
        assert "ok" in result.output.lower()


# ---------------------------------------------------------------------------
# write_heartbeat — error path coverage
# ---------------------------------------------------------------------------


class TestWriteHeartbeatErrorPath:
    """Tests for write_heartbeat error cleanup (lines 59-61)."""

    def test_cleanup_on_write_error(self, data_dir: Path) -> None:
        """If write fails, temp file is cleaned up (no orphan .tmp files)."""
        import tempfile as tf

        original_mkstemp = tf.mkstemp

        captured_tmp: list[str] = []

        def capturing_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
            fd, path = original_mkstemp(*args, **kwargs)
            captured_tmp.append(path)
            return fd, path

        with (
            patch("pkg_defender.daemon.runner.tempfile.mkstemp", side_effect=capturing_mkstemp),
            patch("pkg_defender.daemon.runner.json.dump", side_effect=OSError("disk full")),
            pytest.raises(OSError, match="disk full"),
        ):
            write_heartbeat(
                data_dir,
                {"last_sync": "t", "status": "ok", "error": None, "feeds": {}},
            )

        # Temp files should be cleaned up
        for tmp_path in captured_tmp:
            assert not Path(tmp_path).exists(), f"Orphan temp file: {tmp_path}"


# ---------------------------------------------------------------------------
# read_heartbeat — edge case coverage (lines 94, 99-100)
# ---------------------------------------------------------------------------


class TestReadHeartbeatEdgeCases:
    """Tests for read_heartbeat edge cases."""

    def test_naive_datetime_in_heartbeat_treated_as_utc(self, data_dir: Path) -> None:
        """Naive datetime string (no tz) in heartbeat is treated as UTC (line 94)."""
        import json as json_mod

        hb_path = data_dir / HEARTBEAT_FILENAME
        # Write a naive datetime — no timezone info
        naive_time = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        hb_path.write_text(
            json_mod.dumps({"last_sync": naive_time, "status": "ok", "error": None, "feeds": {}}),
            encoding="utf-8",
        )

        result = read_heartbeat(data_dir)
        # Should succeed because the naive datetime gets UTC attached
        assert result is not None
        assert result["status"] == "ok"

    def test_invalid_datetime_format_returns_none(self, data_dir: Path) -> None:
        """Invalid datetime format in last_sync → None (lines 99-100)."""
        import json as json_mod

        hb_path = data_dir / HEARTBEAT_FILENAME
        hb_path.write_text(
            json_mod.dumps(
                {
                    "last_sync": "definitely-not-a-date-####",
                    "status": "ok",
                    "error": None,
                    "feeds": {},
                }
            ),
            encoding="utf-8",
        )

        # Should return None instead of raising
        assert read_heartbeat(data_dir) is None


# ---------------------------------------------------------------------------
# _detect_platform and _find_pkgd_binary tests (service.py coverage)
# ---------------------------------------------------------------------------


class TestDetectPlatform:
    """Tests for _detect_platform (lines 192-197)."""

    def test_darwin_returns_macos(self) -> None:
        """platform.system() == 'Darwin' → 'macos'."""
        from pkg_defender.daemon.service import _detect_platform

        with patch("pkg_defender.daemon.service.platform.system", return_value="Darwin"):
            assert _detect_platform() == "macos"

    def test_windows_returns_windows(self) -> None:
        """platform.system() == 'Windows' → 'windows'."""
        from pkg_defender.daemon.service import _detect_platform

        with patch("pkg_defender.daemon.service.platform.system", return_value="Windows"):
            assert _detect_platform() == "windows"

    def test_linux_returns_linux(self) -> None:
        """platform.system() == 'Linux' → 'linux'."""
        from pkg_defender.daemon.service import _detect_platform

        with patch("pkg_defender.daemon.service.platform.system", return_value="Linux"):
            assert _detect_platform() == "linux"

    def test_unknown_returns_linux(self) -> None:
        """Unknown platform system → 'linux' (default fallback)."""
        from pkg_defender.daemon.service import _detect_platform

        with patch("pkg_defender.daemon.service.platform.system", return_value="FreeBSD"):
            assert _detect_platform() == "linux"


class TestFindPqBinary:
    """Tests for _find_pkgd_binary (lines 209-216)."""

    def test_finds_binary_on_path(self, tmp_path: Path) -> None:
        """When pkgd is on PATH, returns the resolved path."""
        from pkg_defender.daemon.service import _find_pkgd_binary

        fake_pq = tmp_path / "pkgd"
        fake_pq.write_text("#!/bin/sh\n")
        fake_pq.chmod(0o755)

        # shutil is imported inside _find_pkgd_binary, so we must patch it
        # at the point where it's imported
        import shutil as real_shutil

        with patch.object(real_shutil, "which", return_value=str(fake_pq)):
            result = _find_pkgd_binary()

        assert result == fake_pq

    def test_raises_when_not_found(self) -> None:
        """When pkgd is not on PATH, raises FileNotFoundError."""
        import shutil as real_shutil

        from pkg_defender.daemon.service import _find_pkgd_binary

        with (
            patch.object(real_shutil, "which", return_value=None),
            pytest.raises(FileNotFoundError, match="Could not find 'pkgd'"),
        ):
            _find_pkgd_binary()


class TestUninstallWindows:
    """Tests for Windows uninstall (lines 311-315)."""

    def test_windows_uninstall_removes_xml(self, tmp_path: Path) -> None:
        """Windows uninstall removes the task XML file."""
        from pkg_defender.daemon.service import SYSTEMD_SERVICE_NAME

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        xml_path = data_dir / f"{SYSTEMD_SERVICE_NAME}-task.xml"
        xml_path.write_text("<Task/>")

        with (
            patch("pkg_defender.daemon.service._detect_platform", return_value="windows"),
            patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
        ):
            uninstall_service(platform_name="windows")

        assert not xml_path.exists()

    def test_windows_uninstall_nonexistent_is_noop(self, tmp_path: Path) -> None:
        """Windows uninstall when no XML exists → no error."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        with (
            patch("pkg_defender.daemon.service._detect_platform", return_value="windows"),
            patch("pkg_defender.config.settings.get_data_dir", return_value=data_dir),
        ):
            # Should not raise
            uninstall_service(platform_name="windows")

    def test_unknown_platform_raises(self) -> None:
        """Uninstall with unknown platform raises ValueError."""
        with pytest.raises(ValueError, match="Unknown platform"):
            uninstall_service(platform_name="solaris")


# ---------------------------------------------------------------------------
# daemon_loop — async lifecycle tests (runner.py lines 128-214)
# ---------------------------------------------------------------------------


class TestDaemonLoop:
    """Tests for the async daemon_loop function.

    Covers runner.py lines 128-214: sync cycle, heartbeat on success,
    error handling with backoff, graceful shutdown.
    """

    @pytest.fixture()
    def mock_config(self) -> Any:
        """Create a mock PKGDConfig for daemon tests."""
        from pkg_defender.config.settings import PKGDConfig

        config = PKGDConfig()
        config.daemon.sync_interval_hours = 4
        config.feeds.ghsa_enabled = False
        return config

    @pytest.mark.asyncio
    async def test_writes_ok_heartbeat_when_sync_succeeds(self, mock_config: Any, data_dir: Path) -> None:
        """daemon_loop syncs and writes an OK heartbeat."""
        from pkg_defender.daemon.runner import daemon_loop

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = AsyncMock(return_value={"osv": 5, "socket": 2})
        # Use MagicMock (sync) for get_failed_feeds — AsyncMock would return a coroutine
        mock_aggregator.get_failed_feeds = MagicMock(return_value={})

        # After the first sync completes and the OK heartbeat is written,
        # return normally from wait_for so the loop breaks cleanly via `break`.
        # This prevents a second iteration's startup heartbeat from overwriting
        # the OK heartbeat we want to verify.
        wait_for_call_count = 0

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            nonlocal wait_for_call_count
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            wait_for_call_count += 1
            # Close any pending coroutine so gc.collect() does not warn
            # about unawaited coroutines at test teardown.
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            if wait_for_call_count >= 2:
                # Second call: return normally to trigger `break` in the loop
                return
            raise TimeoutError()

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
        ):
            await daemon_loop(mock_config)

        # Verify heartbeat file exists (written after first successful sync)
        hb_path = data_dir / "daemon_heartbeat.json"
        assert hb_path.exists()

        # Verify heartbeat dict contains expected keys
        with open(hb_path) as f:
            hb = json.load(f)
        assert hb["status"] == "ok"

    @pytest.mark.asyncio
    async def test_sync_error_writes_error_heartbeat(self, mock_config: Any, data_dir: Path) -> None:
        """daemon_loop writes error heartbeat when aggregator fails."""
        from pkg_defender.daemon.runner import daemon_loop

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = AsyncMock(side_effect=RuntimeError("feed connection refused"))

        # After the error heartbeat is written, the backoff sleep calls
        # wait_for. Return normally so the loop breaks via `break` — this
        # prevents a second iteration's startup heartbeat from overwriting
        # the error heartbeat we want to verify.
        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            # Close any pending coroutine so gc.collect() does not warn
            # about unawaited coroutines at test teardown.
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            # Return normally to trigger `break` in the error-handler path
            return

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
        ):
            await daemon_loop(mock_config)

        # Verify error heartbeat was written
        hb_file = data_dir / "daemon_heartbeat.json"
        assert hb_file.exists()
        with open(hb_file) as f:
            hb = json.load(f)
        assert hb["status"] == "error"
        assert "feed connection refused" in hb["error"]

    @pytest.mark.asyncio
    async def test_consecutive_failures_increments(self, mock_config: Any, data_dir: Path) -> None:
        """Multiple consecutive failures produce error heartbeats for each."""
        from pkg_defender.daemon.runner import daemon_loop

        fail_count = 0

        async def always_fail(*args: Any, **kwargs: Any) -> dict[str, int]:
            nonlocal fail_count
            fail_count += 1
            if fail_count >= 3:
                raise KeyboardInterrupt()
            raise RuntimeError(f"failure #{fail_count}")

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = always_fail

        mock_conn = MagicMock()
        mock_conn.close = MagicMock()

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            # Close any pending coroutine so gc.collect() does not warn
            # about unawaited coroutines at test teardown.
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            raise TimeoutError()

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
            pytest.raises(KeyboardInterrupt),
        ):
            await daemon_loop(mock_config)

        assert fail_count == 3

    @pytest.mark.asyncio
    async def test_graceful_shutdown_during_sleep(self, mock_config: Any, data_dir: Path) -> None:
        """Shutdown signal during sleep interval exits cleanly."""
        from pkg_defender.daemon.runner import daemon_loop

        sync_call_count = 0

        async def sync_once_then_stop(*args: Any, **kwargs: Any) -> dict[str, int]:
            nonlocal sync_call_count
            sync_call_count += 1
            # After first successful sync, raise KeyboardInterrupt to simulate shutdown
            raise KeyboardInterrupt()

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = sync_once_then_stop

        mock_conn = MagicMock()
        mock_conn.close = MagicMock()

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            # Close any pending coroutine so gc.collect() does not warn
            # about unawaited coroutines at test teardown.
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            raise TimeoutError()

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
            pytest.raises(KeyboardInterrupt),
        ):
            await daemon_loop(mock_config)

        # Verify sync was called once before shutdown
        assert sync_call_count == 1

    @pytest.mark.asyncio
    async def test_feeds_built_with_ghsa_enabled(self, data_dir: Path) -> None:
        """When ghsa_enabled=True, GHSA feed is included."""
        from unittest.mock import patch

        from pkg_defender.config.settings import PKGDConfig
        from pkg_defender.daemon.runner import daemon_loop

        # Create config with ghsa_enabled=True
        config = PKGDConfig()
        config.daemon.sync_interval_hours = 4
        config.feeds.ghsa_enabled = True

        captured_feeds = []

        class MockFeedAggregator:
            def __init__(self, feeds: Any, db_path: Any, *, retention_days: int | None = None, **_kwargs: Any) -> None:
                captured_feeds.extend(feeds)

                # Raise KeyboardInterrupt to exit the daemon loop after first sync
                async def stop(*args: Any, **kwargs: Any) -> None:
                    raise KeyboardInterrupt()

                self.sync_all = stop

        # Mock write_heartbeat to avoid actual file I/O
        # Also mock wait_for to close coroutines and prevent RuntimeWarning
        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            raise TimeoutError()

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", MockFeedAggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.GHSAFeed"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.write_heartbeat"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
            pytest.raises(KeyboardInterrupt),
        ):
            await daemon_loop(config)

        # Verify GHSAFeed was included when ghsa_enabled=True
        # With ghsa_enabled=True, we should have at least 3 feeds: OSV, GHSA, Socket
        # The mock from GHSAFeed should have 'GHSAFeed' in its repr
        assert len(captured_feeds) >= 3, (
            f"Expected at least 3 feeds (OSV+GHSA+Socket), got {len(captured_feeds)}: {captured_feeds}"
        )
        # Check that one of the feeds is the GHSAFeed mock by looking at repr
        feed_reprs = [repr(f) for f in captured_feeds]
        assert any("GHSAFeed" in r for r in feed_reprs), f"Expected GHSAFeed mock in feeds, got: {feed_reprs}"

    @pytest.mark.asyncio
    async def test_daemon_logs_failed_feeds(
        self,
        mock_config: Any,
        data_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """daemon_loop logs a warning when get_failed_feeds() returns failures."""
        import logging

        from pkg_defender.daemon.runner import daemon_loop

        caplog.set_level(logging.WARNING, logger="pkg_defender.daemon.runner")

        call_count = 0

        async def sync_then_stop(*args: Any, **kwargs: Any) -> dict[str, int]:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise KeyboardInterrupt()
            return {"osv": 5, "socket": 2}

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = sync_then_stop
        # Use MagicMock (sync) for get_failed_feeds — AsyncMock would return a coroutine
        mock_aggregator.get_failed_feeds = MagicMock(return_value={"osv": "Connection timed out"})

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            raise TimeoutError()

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=data_dir),
            patch("pkg_defender.daemon.runner.get_db_path", return_value=data_dir / "threats.db"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
            pytest.raises(KeyboardInterrupt),
        ):
            await daemon_loop(mock_config)

        assert "failed feed" in caplog.text.lower()
        assert "1 failed feed" in caplog.text
        assert "osv" in caplog.text

    @pytest.mark.asyncio
    async def test_custom_db_path_is_respected(self, tmp_path: Path) -> None:
        """When config.database.path is set, daemon_loop uses it for the DB."""
        from pkg_defender.config.settings import PKGDConfig
        from pkg_defender.daemon.runner import daemon_loop

        custom_db_dir = tmp_path / "custom_db"
        custom_db_dir.mkdir()
        expected_db_path = custom_db_dir / "threats.db"

        config = PKGDConfig()
        config.daemon.sync_interval_hours = 4
        config.feeds.ghsa_enabled = False
        config.database.path = custom_db_dir  # <-- THIS IS THE CRITICAL LINE

        mock_aggregator = AsyncMock()
        mock_aggregator.sync_all = AsyncMock(return_value={"osv": 5, "socket": 2})
        mock_aggregator.get_failed_feeds = MagicMock(return_value={})

        async def fast_wait_for(coro: Any, timeout: float) -> Any:
            # Try to await the coro first — handles sync_all wrapper
            try:
                async with asyncio.timeout(0.5):
                    return await coro
            except TimeoutError:
                pass
            if hasattr(coro, "close") and callable(coro.close):
                with contextlib.suppress(Exception):
                    coro.close()
            return

        with (
            patch("pkg_defender.daemon.runner.get_data_dir", return_value=tmp_path / "data"),
            patch("pkg_defender.daemon.runner.FeedAggregator", return_value=mock_aggregator),
            patch("pkg_defender.daemon.runner.OSVFeedAdapter"),
            patch("pkg_defender.daemon.runner.SocketFeed"),
            patch("pkg_defender.daemon.runner.asyncio.wait_for", side_effect=fast_wait_for),
        ):
            await daemon_loop(config)

        # Assert: database was created at the custom path, NOT at data_dir
        assert expected_db_path.exists(), f"Database should exist at custom path: {expected_db_path}"

        # Assert: no database at the default data_dir location
        assert not (tmp_path / "data" / "threats.db").exists(), "Should NOT create database at default data_dir"


# ---------------------------------------------------------------------------
# run_daemon — entry point tests (runner.py lines 231-243)
# ---------------------------------------------------------------------------


def _mock_asyncio_run_raise(exc: BaseException) -> Callable[[Any], Any]:
    """Create a mock asyncio.run that closes coroutines before raising.

    This prevents RuntimeWarning: coroutine 'daemon_loop' was never awaited
    when tests patch asyncio.run with side_effect=Exception.
    """

    def mock_run(coro: Any) -> Any:
        # Close the coroutine to prevent the unawaited coroutine warning
        if hasattr(coro, "close") and callable(coro.close):
            with contextlib.suppress(Exception):
                coro.close()
        raise exc

    return mock_run


class TestRunDaemon:
    """Tests for the run_daemon entry point (lines 231-243)."""

    def test_keyboard_interrupt_handled(self, tmp_path: Path) -> None:
        """run_daemon propagates SystemExit(130) on KeyboardInterrupt."""
        import atexit as atexit_mod

        from pkg_defender.cli._exit_codes import EXIT_SIGINT
        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False

        with (
            patch("pkg_defender.daemon.runner.load_config", return_value=config),
            patch(
                "pkg_defender.daemon.runner.asyncio.run",
                _mock_asyncio_run_raise(KeyboardInterrupt()),
            ),
            patch("pkg_defender.daemon.runner.logging.basicConfig"),
            patch.object(atexit_mod, "register"),
            patch("pkg_defender.daemon.runner.acquire_single_instance_lock"),
            patch("pkg_defender.daemon.runner.release_lock"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                run_daemon()
            assert exc_info.value.code == EXIT_SIGINT
            assert EXIT_SIGINT == 130

    def test_system_exit_handled(self, tmp_path: Path) -> None:
        """run_daemon catches SystemExit for clean shutdown."""
        import atexit as atexit_mod

        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False

        with (
            patch("pkg_defender.daemon.runner.load_config", return_value=config),
            patch(
                "pkg_defender.daemon.runner.asyncio.run",
                _mock_asyncio_run_raise(SystemExit(0)),
            ),
            patch("pkg_defender.daemon.runner.logging.basicConfig"),
            patch.object(atexit_mod, "register"),
            patch("pkg_defender.daemon.runner.acquire_single_instance_lock"),
            patch("pkg_defender.daemon.runner.release_lock"),
        ):
            # Should re-raise SystemExit(0) - our code raises it, user sees it
            with pytest.raises(SystemExit) as exc_info:
                run_daemon()
            assert exc_info.value.code == 0

    def test_verbose_mode_sets_debug_logging(self, tmp_path: Path) -> None:
        """Verbose config sets DEBUG log level."""
        import atexit as atexit_mod

        from pkg_defender.cli._exit_codes import EXIT_SIGINT
        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = True

        with (
            patch("pkg_defender.daemon.runner.load_config", return_value=config),
            patch(
                "pkg_defender.daemon.runner.asyncio.run",
                _mock_asyncio_run_raise(KeyboardInterrupt()),
            ),
            patch("pkg_defender.daemon.runner.logging.basicConfig") as mock_basic,
            patch.object(atexit_mod, "register"),
            patch("pkg_defender.daemon.runner.acquire_single_instance_lock"),
            patch("pkg_defender.daemon.runner.release_lock"),
        ):
            with pytest.raises(SystemExit) as exc_info:
                run_daemon()
            assert exc_info.value.code == EXIT_SIGINT

        mock_basic.assert_called_once()
        call_kwargs = mock_basic.call_args[1]
        assert call_kwargs["level"] == 10  # logging.DEBUG


class TestDaemonLock:
    """Tests for flock-based single-instance daemon lock."""

    def test_acquire_creates_lock_file(self, tmp_path: Path) -> None:
        """Lock file is created at the expected path."""
        acquire_single_instance_lock(tmp_path)
        assert (tmp_path / "daemon.lock").exists()
        release_lock()

    def test_acquire_creates_directory_if_missing(self, tmp_path: Path) -> None:
        """Missing parent directory is created automatically."""
        deep_path = tmp_path / "sub" / "dir"
        assert not deep_path.exists()
        acquire_single_instance_lock(deep_path)
        assert deep_path.exists()
        assert (deep_path / "daemon.lock").exists()
        release_lock()

    def test_release_frees_lock(self, tmp_path: Path) -> None:
        """After release_lock(), a second lock can be acquired."""
        acquire_single_instance_lock(tmp_path)
        release_lock()
        # Should succeed — lock was released
        acquire_single_instance_lock(tmp_path)
        release_lock()

    def test_second_process_acquire_raises_runtime_error(self, tmp_path: Path) -> None:
        """A second daemon process cannot acquire the lock."""
        import subprocess as _sp
        import sys as _sys

        # Hold the lock in this process
        acquire_single_instance_lock(tmp_path)

        # Try to acquire from a subprocess — must fail
        result = _sp.run(
            [
                _sys.executable,
                "-c",
                f"""
import sys
sys.path.insert(0, {repr(str(Path.cwd()))})
from pkg_defender.daemon.runner import acquire_single_instance_lock, release_lock
from pathlib import Path
try:
    acquire_single_instance_lock(Path({repr(str(tmp_path))}))
    sys.stdout.write("SUCCESS")
except RuntimeError as e:
    sys.stdout.write(f"BLOCKED:{{e}}")
finally:
    release_lock()
""",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        release_lock()
        assert "BLOCKED" in result.stdout, f"Lock was not enforced. stdout={result.stdout!r}"


class TestRunDaemonExitCode:
    """Tests for run_daemon exit code propagation."""

    def test_run_daemon_returns_130_on_cancelled_error(self, tmp_path: Path) -> None:
        """run_daemon returns EXIT_SIGINT (130) on asyncio.CancelledError."""
        import atexit as atexit_mod
        import sys

        from pkg_defender.cli._exit_codes import EXIT_SIGINT
        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False

        # The `import atexit as _atexit` happens inside run_daemon.
        # We need to add atexit to sys.modules before calling run_daemon.
        original_atexit = sys.modules.get("atexit")
        sys.modules["atexit"] = atexit_mod
        try:
            with (
                patch("pkg_defender.daemon.runner.load_config", return_value=config),
                patch(
                    "pkg_defender.daemon.runner.asyncio.run",
                    side_effect=asyncio.CancelledError(),
                ),
                patch("pkg_defender.daemon.runner.logging.basicConfig"),
                patch.object(atexit_mod, "register"),
                patch("pkg_defender.daemon.runner.acquire_single_instance_lock"),
                patch("pkg_defender.daemon.runner.release_lock"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    run_daemon()
                assert exc_info.value.code == EXIT_SIGINT
        finally:
            if original_atexit is not None:
                sys.modules["atexit"] = original_atexit
            else:
                sys.modules.pop("atexit", None)

    def test_atexit_handler_registered(self, tmp_path: Path) -> None:
        """run_daemon registers atexit cleanup handler."""
        import atexit as atexit_mod
        import sys

        from pkg_defender.cli._exit_codes import EXIT_SIGINT
        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False

        mock_register = MagicMock()
        atexit_mod.register = mock_register

        # The `import atexit` happens inside run_daemon via local import.
        # We need to ensure our atexit mock is in sys.modules before run_daemon runs.
        original_atexit = sys.modules.get("atexit")
        sys.modules["atexit"] = atexit_mod
        try:
            with (
                patch("pkg_defender.daemon.runner.load_config", return_value=config),
                patch(
                    "pkg_defender.daemon.runner.asyncio.run",
                    _mock_asyncio_run_raise(KeyboardInterrupt()),
                ),
                patch("pkg_defender.daemon.runner.logging.basicConfig"),
                patch("pkg_defender.daemon.runner.acquire_single_instance_lock"),
                patch("pkg_defender.daemon.runner.release_lock"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    run_daemon()
                # Verify exit code is 130 (SIGINT)
                assert exc_info.value.code == EXIT_SIGINT

            # Verify atexit.register was called
            mock_register.assert_called_once()
        finally:
            if original_atexit is not None:
                sys.modules["atexit"] = original_atexit
            else:
                sys.modules.pop("atexit", None)


# ---------------------------------------------------------------------------
# Battery self-termination tests (SG2)
# ---------------------------------------------------------------------------


class TestDaemonBatteryTermination:
    """Tests for battery-aware daemon self-termination in run_daemon()."""

    def test_battery_termination_exits_early(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On battery + run_on_battery=False -> daemon exits before asyncio.run."""
        import atexit as atexit_mod

        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False
        config.daemon.run_on_battery = False

        acquire_mock = MagicMock()
        release_mock = MagicMock()
        asyncio_run_mock = MagicMock(side_effect=lambda coro: coro.close() if hasattr(coro, "close") else None)

        monkeypatch.setattr("pkg_defender.daemon.runner.load_config", lambda *a, **kw: config)
        monkeypatch.setattr("pkg_defender.daemon.runner._on_battery_power", lambda: True)
        monkeypatch.setattr("pkg_defender.daemon.runner.acquire_single_instance_lock", acquire_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.release_lock", release_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.asyncio.run", asyncio_run_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.logging.basicConfig", MagicMock())
        monkeypatch.setattr(atexit_mod, "register", MagicMock())

        run_daemon()

        assert acquire_mock.called, "Lock must be acquired before battery check"
        assert release_mock.called, "Lock must be released on battery termination"
        assert not asyncio_run_mock.called, "asyncio.run must NOT be called on battery"

    def test_run_on_battery_bypasses_termination(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On battery + run_on_battery=True -> daemon starts normally."""
        import atexit as atexit_mod

        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False
        config.daemon.run_on_battery = True

        acquire_mock = MagicMock()
        asyncio_run_mock = MagicMock(side_effect=lambda coro: coro.close() if hasattr(coro, "close") else None)

        monkeypatch.setattr("pkg_defender.daemon.runner.load_config", lambda *a, **kw: config)
        monkeypatch.setattr("pkg_defender.daemon.runner._on_battery_power", lambda: True)
        monkeypatch.setattr("pkg_defender.daemon.runner.acquire_single_instance_lock", acquire_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.asyncio.run", asyncio_run_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.logging.basicConfig", MagicMock())
        monkeypatch.setattr(atexit_mod, "register", MagicMock())

        run_daemon()

        assert acquire_mock.called, "Lock must be acquired"
        assert asyncio_run_mock.called, "asyncio.run must be called when battery check is bypassed"

    def test_ac_power_proceeds_normally(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """On AC power -> daemon starts normally regardless of run_on_battery."""
        import atexit as atexit_mod

        from pkg_defender.daemon.runner import run_daemon

        config = MagicMock()
        config.output.verbose = False
        config.daemon.run_on_battery = False

        acquire_mock = MagicMock()
        asyncio_run_mock = MagicMock(side_effect=lambda coro: coro.close() if hasattr(coro, "close") else None)

        monkeypatch.setattr("pkg_defender.daemon.runner.load_config", lambda *a, **kw: config)
        monkeypatch.setattr("pkg_defender.daemon.runner._on_battery_power", lambda: False)
        monkeypatch.setattr("pkg_defender.daemon.runner.acquire_single_instance_lock", acquire_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.asyncio.run", asyncio_run_mock)
        monkeypatch.setattr("pkg_defender.daemon.runner.logging.basicConfig", MagicMock())
        monkeypatch.setattr(atexit_mod, "register", MagicMock())

        run_daemon()

        assert acquire_mock.called, "Lock must be acquired"
        assert asyncio_run_mock.called, "asyncio.run must be called when on AC power"
