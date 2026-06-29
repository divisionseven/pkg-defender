"""Tests for the _on_battery_power() helper function.

Covers all platform paths:
- macOS: pmset -g ps parsing
- Linux: /sys/class/power_supply/BAT*/status (via glob)
- Windows/unknown: no detection (returns False)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pkg_defender.daemon.runner import _on_battery_power


class TestOnBatteryPowerMacOS:
    """Tests for macOS battery detection (pmset -g ps)."""

    def test_macos_on_battery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """macOS: 'Battery Power' in pmset output -> True."""
        monkeypatch.setattr(sys, "platform", "darwin")

        def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="Battery Power - 85%\n", stderr="")

        monkeypatch.setattr("pkg_defender.daemon.runner.subprocess.run", mock_run)
        assert _on_battery_power() is True

    def test_macos_on_ac(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """macOS: 'AC Power' in pmset output -> False."""
        monkeypatch.setattr(sys, "platform", "darwin")

        def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="AC Power\n", stderr="")

        monkeypatch.setattr("pkg_defender.daemon.runner.subprocess.run", mock_run)
        assert _on_battery_power() is False

    def test_macos_no_battery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """macOS: no battery-related string in output -> False."""
        monkeypatch.setattr(sys, "platform", "darwin")

        def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="No drawing from battery\n", stderr="")

        monkeypatch.setattr("pkg_defender.daemon.runner.subprocess.run", mock_run)
        assert _on_battery_power() is False

    def test_macos_subprocess_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """macOS: subprocess.SubprocessError -> False."""
        monkeypatch.setattr(sys, "platform", "darwin")

        def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.SubprocessError("pmset failed")

        monkeypatch.setattr("pkg_defender.daemon.runner.subprocess.run", mock_run)
        assert _on_battery_power() is False

    def test_macos_pmset_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """macOS: FileNotFoundError (pmset missing) -> False."""
        monkeypatch.setattr(sys, "platform", "darwin")

        def mock_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("pmset not found")

        monkeypatch.setattr("pkg_defender.daemon.runner.subprocess.run", mock_run)
        assert _on_battery_power() is False


class TestOnBatteryPowerLinux:
    """Tests for Linux battery detection (/sys/class/power_supply/BAT*/status)."""

    def test_linux_discharging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux: battery status 'Discharging' -> True."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda _: "Discharging\n")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [Path("/sys/class/power_supply/BAT0/status")])
        assert _on_battery_power() is True

    def test_linux_charging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux: battery status 'Charging' -> False."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda _: "Charging\n")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [Path("/sys/class/power_supply/BAT0/status")])
        assert _on_battery_power() is False

    def test_linux_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux: battery status 'Full' -> False."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda _: "Full\n")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [Path("/sys/class/power_supply/BAT0/status")])
        assert _on_battery_power() is False

    def test_linux_no_battery_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux: no battery files found via glob -> False."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [])
        assert _on_battery_power() is False

    def test_linux_permission_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux: PermissionError reading BAT0/status -> False."""
        monkeypatch.setattr(sys, "platform", "linux")

        def mock_glob(self: Path, pattern: str) -> list[Path]:
            return [Path("/sys/class/power_supply/BAT0/status")]

        monkeypatch.setattr(Path, "glob", mock_glob)

        def mock_read_text(_self: Path) -> str:
            raise PermissionError("Permission denied")

        monkeypatch.setattr(Path, "read_text", mock_read_text)
        assert _on_battery_power() is False

    def test_linux_bat1_only_discharging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only BAT1 exists and is discharging — main bug scenario."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda self: "Discharging\n")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [Path("/sys/class/power_supply/BAT1/status")])
        assert _on_battery_power() is True

    def test_linux_bat1_only_charging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only BAT1 exists and is charging."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda self: "Charging\n")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [Path("/sys/class/power_supply/BAT1/status")])
        assert _on_battery_power() is False

    def test_linux_dual_battery_one_discharging(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dual-battery: BAT0=Full, BAT1=Discharging — checks both."""
        monkeypatch.setattr(sys, "platform", "linux")

        def mock_read_text(self: Path) -> str:
            if "BAT0" in str(self):
                return "Full\n"
            return "Discharging\n"

        monkeypatch.setattr(Path, "read_text", mock_read_text)
        monkeypatch.setattr(
            Path,
            "glob",
            lambda self, pattern: sorted(
                [
                    Path("/sys/class/power_supply/BAT0/status"),
                    Path("/sys/class/power_supply/BAT1/status"),
                ]
            ),
        )
        assert _on_battery_power() is True

    def test_linux_dual_battery_both_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dual-battery: both batteries are Full (not discharging)."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "read_text", lambda self: "Full\n")
        monkeypatch.setattr(
            Path,
            "glob",
            lambda self, pattern: sorted(
                [
                    Path("/sys/class/power_supply/BAT0/status"),
                    Path("/sys/class/power_supply/BAT1/status"),
                ]
            ),
        )
        assert _on_battery_power() is False

    def test_linux_no_battery_dirs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No /sys/class/power_supply/ directory exists."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [])
        assert _on_battery_power() is False

    def test_linux_glob_already_covers_no_battery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit empty glob test — redundant but documents edge case."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [])
        assert _on_battery_power() is False


class TestOnBatteryPowerOther:
    """Tests for platforms without battery detection."""

    def test_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Windows: no detection -> False."""
        monkeypatch.setattr(sys, "platform", "win32")
        assert _on_battery_power() is False

    def test_unknown_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unknown platform: no detection -> False."""
        monkeypatch.setattr(sys, "platform", "freebsd")
        assert _on_battery_power() is False
