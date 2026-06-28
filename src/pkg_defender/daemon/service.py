"""Platform service generators — launchd (macOS), systemd (Linux), Task Scheduler (Windows)."""

from __future__ import annotations

import contextlib
import platform
import subprocess
from pathlib import Path

LAUNCHD_LABEL = "dev.pkg-defender.daemon"
SYSTEMD_SERVICE_NAME = "pkg-defender"


# ---------------------------------------------------------------------------
# macOS — launchd plist
# ---------------------------------------------------------------------------


def generate_launchd_plist(
    pq_binary: Path,
    config_path: Path,
    data_dir: Path,
) -> str:
    """Generate a macOS launchd plist XML for the daemon.

    Args:
        pq_binary: Absolute path to the ``pkgd`` binary.
        config_path: Absolute path to the config file.
        data_dir: Absolute path to the data directory (for log output).

    Returns:
        XML string for the launchd plist.
    """
    stdout_path = data_dir / "daemon_stdout.log"
    stderr_path = data_dir / "daemon_stderr.log"

    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>Program</key>
    <string>{pq_binary}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{pq_binary}</string>
        <string>daemon</string>
        <string>run</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{stdout_path}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_path}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PKGD_CONFIG_PATH</key>
        <string>{config_path}</string>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>{data_dir}</string>
</dict>
</plist>
"""


# ---------------------------------------------------------------------------
# Linux — systemd user unit
# ---------------------------------------------------------------------------


def generate_systemd_unit(
    pq_binary: Path,
    config_path: Path,
    data_dir: Path,
    home: str = "",
) -> str:
    """Generate a Linux systemd user unit file for the daemon.

    Args:
        pq_binary: Absolute path to the ``pkgd`` binary.
        config_path: Absolute path to the config file.
        data_dir: Absolute path to the data directory.
        home: Home directory path (resolved at generation time so
            ``$HOME/.local/bin`` resolves to an absolute path).

    Returns:
        Unit file content as a string.
    """
    return f"""\
[Unit]
Description=pkg-defender background daemon
After=network.target

[Service]
Type=simple
ExecStart={pq_binary} daemon run
Restart=on-failure
RestartSec=60
Environment=PKGD_CONFIG_PATH={config_path}
Environment=PATH=/usr/local/bin:/usr/bin:/bin:{home}/.local/bin
WorkingDirectory={data_dir}

[Install]
WantedBy=default.target
"""


# ---------------------------------------------------------------------------
# Windows — Task Scheduler XML
# ---------------------------------------------------------------------------


def generate_scheduled_task_xml(
    pq_binary: Path,
    config_path: Path,
    data_dir: Path,
) -> str:
    """Generate a Windows Task Scheduler XML for the daemon.

    Args:
        pq_binary: Absolute path to the ``pkgd`` binary.
        config_path: Absolute path to the config file.
        data_dir: Absolute path to the data directory (unused in XML,
            accepted for interface consistency with macOS/Linux generators).

    Returns:
        Task Scheduler XML string.
    """
    from datetime import UTC, datetime

    start_boundary = datetime.now(UTC).strftime("%Y-%m-%d")

    return f"""\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2"
  xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>pkg-defender background daemon — periodic feed sync</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT4H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>{start_boundary}T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions>
    <Exec>
      <Command>cmd</Command>
      <Arguments>/c "set PKGD_CONFIG_PATH={config_path} &amp; {pq_binary} daemon run"</Arguments>
    </Exec>
  </Actions>
</Task>
"""


# ---------------------------------------------------------------------------
# Install / Uninstall
# ---------------------------------------------------------------------------


def _detect_platform() -> str:
    """Detect the current platform.

    Returns:
        One of 'macos', 'linux', 'windows'.
    """
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def _find_pkgd_binary() -> Path:
    """Locate the ``pkgd`` binary on PATH.

    Returns:
        Path to the ``pkgd`` binary.

    Raises:
        FileNotFoundError: If the binary cannot be found.
    """
    import shutil

    found = shutil.which("pkgd")
    if found is None:
        raise FileNotFoundError("Could not find 'pkgd' on PATH. Install the package first: pip install -e .")
    return Path(found)


def install_service(
    platform_name: str | None = None,
    pq_binary: Path | None = None,
) -> Path:
    """Install the daemon as a system service.

    Args:
        platform_name: Platform override ('macos', 'linux', 'windows').
            If None, auto-detects the current platform.
        pq_binary: Path to the ``pkgd`` binary. If None, searches PATH.

    Returns:
        Path to the installed service file.

    Raises:
        ValueError: If platform_name is not recognised.
        FileNotFoundError: If pq_binary not found.
    """
    plat = platform_name or _detect_platform()
    binary = pq_binary or _find_pkgd_binary()

    from pkg_defender.config.settings import get_data_dir, get_default_config_path

    config_path = get_default_config_path()
    data_dir = get_data_dir()

    if plat == "macos":
        plist_dir = Path.home() / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / f"{LAUNCHD_LABEL}.plist"
        plist_path.write_text(
            generate_launchd_plist(binary, config_path, data_dir),
            encoding="utf-8",
        )
        return plist_path

    if plat == "linux":
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / f"{SYSTEMD_SERVICE_NAME}.service"
        unit_path.write_text(
            generate_systemd_unit(binary, config_path, data_dir, home=str(Path.home())),
            encoding="utf-8",
        )
        return unit_path

    if plat == "windows":
        xml_path = data_dir / f"{SYSTEMD_SERVICE_NAME}-task.xml"
        data_dir.mkdir(parents=True, exist_ok=True)
        xml_path.write_text(
            generate_scheduled_task_xml(binary, config_path, data_dir),
            encoding="utf-8",
        )
        with contextlib.suppress(FileNotFoundError, subprocess.TimeoutExpired):
            subprocess.run(
                ["schtasks", "/Create", "/TN", SYSTEMD_SERVICE_NAME, "/XML", str(xml_path), "/F"],
                check=True,
                capture_output=True,
                timeout=10,
            )
        return xml_path

    raise ValueError(f"Unknown platform: {plat!r}. Use 'macos', 'linux', or 'windows'.")


def uninstall_service(platform_name: str | None = None) -> None:
    """Uninstall the daemon system service.

    Args:
        platform_name: Platform override. If None, auto-detects.

    Raises:
        ValueError: If platform_name is not recognised.
    """
    plat = platform_name or _detect_platform()

    if plat == "macos":
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        if plist_path.exists():
            with contextlib.suppress(FileNotFoundError, subprocess.TimeoutExpired):
                subprocess.run(
                    ["launchctl", "unload", str(plist_path)],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            plist_path.unlink()

    elif plat == "linux":
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_path = unit_dir / f"{SYSTEMD_SERVICE_NAME}.service"
        if unit_path.exists():
            with contextlib.suppress(FileNotFoundError, subprocess.TimeoutExpired):
                subprocess.run(
                    ["systemctl", "--user", "disable", f"{SYSTEMD_SERVICE_NAME}.service"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            unit_path.unlink()

    elif plat == "windows":
        from pkg_defender.config.settings import get_data_dir

        xml_path = get_data_dir() / f"{SYSTEMD_SERVICE_NAME}-task.xml"
        with contextlib.suppress(FileNotFoundError, subprocess.TimeoutExpired):
            subprocess.run(
                ["schtasks", "/Delete", "/TN", SYSTEMD_SERVICE_NAME, "/F"],
                check=False,
                capture_output=True,
                timeout=10,
            )
        xml_path.unlink(missing_ok=True)

    else:
        raise ValueError(f"Unknown platform: {plat!r}. Use 'macos', 'linux', or 'windows'.")
