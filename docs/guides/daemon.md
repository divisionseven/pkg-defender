# ⚠️ Daemon [Experimental]

> **Experimental in v1.0:** The daemon is an optional feature. On-demand sync via `pkgd setup` is sufficient for most workflows and provides the same threat intelligence without the operational complexity of a background service.

The daemon is **not required** for core package protection (`pkgd install`, `pkgd audit`, `pkgd <manager> install` all work with an on-demand sync via `pkgd setup`). Only use the daemon if you need always-on automatic feed synchronization.

Run `pkg-defender` as a background service for periodic threat feed synchronization.

## When to Use Daemon vs Manual Sync

| Scenario                         | Recommended Approach                   |
| -------------------------------- | -------------------------------------- |
| Interactive use, occasional sync | `pkgd intel sync` manually             |
| CI/CD pipeline                   | `pkgd intel sync` in pipeline step     |
| Continuous protection, always-on | `pkgd daemon start`                    |
| Server/production environment    | `pkgd daemon install` (system service) |

## Daemon Commands

```bash
pkgd daemon run          # run in foreground (for service managers)
pkgd daemon start        # start as background process
pkgd daemon stop         # stop the daemon (SIGTERM → 5s grace → SIGKILL)
pkgd daemon restart      # restart the background daemon
pkgd daemon status       # show daemon status from heartbeat
pkgd daemon install      # install as system service
pkgd daemon uninstall    # uninstall system service
```

## Background Process

`pkgd daemon start` launches a detached subprocess that runs `pkgd daemon run` in the background:

```python
subprocess.Popen(
    [sys.executable, "-m", "pkg_defender.cli.main", "daemon", "run"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
```

On start, the daemon writes a PID file (`daemon.pid` in the data directory) containing the subprocess PID. The start command checks for an existing daemon via heartbeat freshness before spawning a new process. The daemon also acquires a kernel-level `fcntl.flock()` lock on `daemon.lock` at startup, enforcing single-instance guarantees even if the heartbeat file is stale or missing.

## Heartbeat Mechanism

The daemon writes a heartbeat file to the data directory after each feed sync cycle (every ``sync_interval_hours`` hours, default 4). ``pkgd daemon status`` reads this file to determine if the daemon is alive. A heartbeat is considered stale when its age exceeds ``staleness_threshold_hours`` (default 8, configured via ``feeds.staleness_threshold_hours`` or ``PKGD_FEEDS_STALENESS_HOURS``):

```console
Status:  ok
Last sync: 2026-06-01

Feed Sync Results
┌──────────┬─────────┐
│ Feed     │ Records │
├──────────┼─────────┤
│ osv      │ 15234   │
│ ghsa     │ 8921    │
│ socket   │ 3456    │
└──────────┴─────────┘
```

If no fresh heartbeat is found, the daemon is considered stopped.

## Stopping the Daemon

`pkgd daemon stop` performs a two-phase shutdown:

1. **SIGTERM (graceful):** Sends SIGTERM to the daemon process and waits up to 5 seconds for it to exit cleanly.
2. **SIGKILL (force):** If the daemon is still running after 5 seconds, sends SIGKILL.

The daemon removes its PID file on shutdown via both signal handlers and an `atexit` cleanup handler. If the PID file is stale (process already exited) or corrupt (invalid content), `daemon stop` handles both cases gracefully by cleaning up and reporting the state. A legacy fallback removes only the heartbeat file when no PID file exists.

### Stale State Cleanup

| Scenario                               | Behavior                                                                    |
| -------------------------------------- | --------------------------------------------------------------------------- |
| Valid PID file, process running        | Sends SIGTERM, waits 5s, fallback SIGKILL                                   |
| PID file exists, process already gone  | Reports "Daemon was already stopped (stale PID).", cleans up stale PID file |
| Corrupt PID file (non-numeric content) | Reports "Removed stale state (corrupt PID file).", cleans up                |
| No PID file, heartbeat exists          | Legacy fallback — removes heartbeat only                                    |
| No PID file, no heartbeat              | Reports "Daemon does not appear to be running.", returns immediately        |

## Battery Awareness

The daemon checks whether the device is running on battery power at startup. If
it is, the daemon self-terminates immediately to conserve power (unless
explicitly configured otherwise).

| Check                                                      | Behavior                            |
| ---------------------------------------------------------- | ----------------------------------- |
| AC power detected                                          | Daemon starts normally              |
| Battery power detected, `run_on_battery = false` (default) | Daemon exits with a warning message |
| Battery power detected, `run_on_battery = true`            | Daemon starts normally              |

### Platform Detection

- **macOS:** The daemon runs ``pmset -g ps`` and checks for `"Battery Power"` in
  the output.
- **Linux:** The daemon reads
   ``/sys/class/power_supply/BAT*/status`` and checks for the value
  `"Discharging"`.
- **Windows/other:** No battery detection is available — the daemon always starts
  (battery check returns `False`).

### Configuration

Daemon behavior is configured via the ``[daemon]`` section of your TOML config
file, environment variables with the ``PKGD_DAEMON_`` prefix, or ``pkgd config
set``. All daemon settings are fully supported in TOML and displayed by
``pkgd config view``, ``pkgd config list``, and ``pkgd config options``.

| Field                          | Env Variable                        | Default   | Description                              |
| ------------------------------ | ----------------------------------- | --------- | ---------------------------------------- |
| ``daemon.run_on_battery``      | ``PKGD_DAEMON_RUN_ON_BATTERY``      | ``false`` | Allow daemon to run on battery power     |
| ``daemon.sync_interval_hours`` | ``PKGD_DAEMON_SYNC_INTERVAL_HOURS`` | ``4``     | Hours between automatic feed sync cycles |

```bash
# Allow daemon to run on battery (not recommended on laptops)
export PKGD_DAEMON_RUN_ON_BATTERY=true
pkgd daemon run
```

```toml
[daemon]
run_on_battery = true
sync_interval_hours = 6
```

## Platform Service Integration

### macOS (launchd)

```bash
pkgd daemon install --platform macos
```

Creates a `~/Library/LaunchAgents/dev.pkg-defender.daemon.plist` file.

### Linux (systemd)

```bash
pkgd daemon install --platform linux
```

Creates a systemd user service unit.

### Windows (Task Scheduler)

```bash
pkgd daemon install --platform windows
```

Creates a scheduled task.

### Auto-Detection

If `--platform` is omitted, the daemon auto-detects the current platform.

## Uninstalling

```bash
pkgd daemon uninstall
```

Removes the system service. Stopping the daemon first (`pkgd daemon stop`) is recommended but not required — the uninstall command will succeed even if the daemon is running.

## Lock File (`daemon.lock`)

The `daemon.lock` file in the data directory is a normal part of daemon operation — it is used for single-instance enforcement via `fcntl.flock()`. The OS releases the lock automatically when the daemon terminates, but the empty file persists on disk. Do not delete it manually; it is recreated on the next daemon start.

## Troubleshooting

### Daemon won't start

```bash
# Check if already running
pkgd daemon status

# If running, stop it first
pkgd daemon stop
pkgd daemon start
```

### Stale PID or heartbeat

If the daemon crashed without cleaning up, stale state files are handled automatically:

```bash
# Cleans up stale PID file or heartbeat
pkgd daemon stop

# Restart
pkgd daemon start
```

`pkgd daemon stop` detects stale PID files (process gone, `ESRCH`), corrupt PID files (non-numeric content), and legacy heartbeat-only state — each is cleaned up gracefully with an appropriate message.

### Service installation fails

```bash
# Specify platform explicitly
pkgd daemon install --platform linux

# Check error output for missing permissions or paths
```

---

[← Back to Documentation](../index.md)
