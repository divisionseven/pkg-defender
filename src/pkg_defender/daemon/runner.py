"""Background daemon runner — periodic feed sync."""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkg_defender.config.settings import PKGDConfig, get_data_dir, get_db_path, load_config
from pkg_defender.db.schema import get_connection, init_db
from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter
from pkg_defender.intel.base import FeedSource
from pkg_defender.intel.ghsa import GHSAFeed
from pkg_defender.intel.mastodon import MastodonFeed
from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
from pkg_defender.intel.ossf_malicious import OSSFMaliciousFeed
from pkg_defender.intel.reddit import RedditFeed
from pkg_defender.intel.rss_feed import RSSFeed
from pkg_defender.intel.socket import SocketFeed
from pkg_defender.intel.x_twitter import XTwitterFeed
from pkg_defender.logging_filter import SecretRedactingFilter

logger = logging.getLogger(__name__)

HEARTBEAT_FILENAME = "daemon_heartbeat.json"
PID_FILENAME = "daemon.pid"

# Module-level lock file descriptor — MUST remain open to hold exclusive lock
_lock_fd: int | None = None

# Backoff schedule: 1m, 2m, 4m, 8m, 16m, capped at 30m
BACKOFF_BASE_SECONDS = 60
BACKOFF_MAX_SECONDS = 1800
BACKOFF_MULTIPLIER = 2


def write_heartbeat(data_dir: Path, status: dict[str, Any]) -> None:
    """Write daemon heartbeat as JSON to data_dir.

    Uses atomic write (temp file + rename) to prevent partial reads.

    Args:
        data_dir: Directory to write heartbeat file into.
        status: Dict with keys: last_sync, status, error, feeds.
    """
    heartbeat_path = data_dir / HEARTBEAT_FILENAME
    data_dir.mkdir(parents=True, exist_ok=True)

    # Atomic write: write to temp, then rename
    fd, tmp_path = tempfile.mkstemp(dir=data_dir, prefix=".heartbeat_", suffix=".tmp")
    try:
        with open(fd, "w", encoding="utf-8") as fh:
            json.dump(status, fh, indent=2, default=str)
            fh.flush()
        Path(tmp_path).rename(heartbeat_path)
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def read_heartbeat(data_dir: Path, staleness_threshold_hours: int | None = None) -> dict[str, Any] | None:
    """Read daemon heartbeat from data_dir.

    Returns None if file is missing or stale (>staleness_threshold_hours since last write).

    Args:
        data_dir: Directory containing the heartbeat file.
        staleness_threshold_hours: Hours before heartbeat is considered stale.
            If None, loads from config (default 8).

    Returns:
        Parsed heartbeat dict, or None if missing/stale.
    """
    heartbeat_path = data_dir / HEARTBEAT_FILENAME

    if not heartbeat_path.exists():
        return None

    try:
        with open(heartbeat_path, encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None

    last_sync_str = data.get("last_sync")
    if not last_sync_str:
        return None

    try:
        last_sync = datetime.fromisoformat(last_sync_str)
        if last_sync.tzinfo is None:
            last_sync = last_sync.replace(tzinfo=UTC)
        age = datetime.now(UTC) - last_sync
        if staleness_threshold_hours is None:
            config = load_config()
            staleness_threshold_hours = config.feeds.staleness_threshold_hours
        if age.total_seconds() > staleness_threshold_hours * 3600:
            return None
    except (ValueError, TypeError):
        return None

    return data


def is_daemon_running(data_dir: Path) -> bool:
    """Check if the daemon appears to be active.

    Args:
        data_dir: Directory containing the heartbeat file.

    Returns:
        True if a fresh heartbeat exists.
    """
    return read_heartbeat(data_dir) is not None


def acquire_single_instance_lock(data_dir: Path) -> None:
    """Acquire exclusive file lock to enforce single daemon instance.

    Uses fcntl.flock() for kernel-level mutual exclusion. The lock is
    automatically released by the OS when the process terminates, even
    on SIGKILL (eliminating PID-reuse and TOCTOU races inherent in
    PID-file approaches).

    Args:
        data_dir: Directory to store the lock file.

    Raises:
        RuntimeError: If another daemon instance is already running.
    """
    global _lock_fd  # noqa: PLW0603

    data_dir.mkdir(parents=True, exist_ok=True)
    lock_path = data_dir / "daemon.lock"

    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd = fd
    except (BlockingIOError, PermissionError):
        raise RuntimeError("Another daemon instance is already running.") from None


def release_lock() -> None:
    """Release the exclusive daemon lock.

    Closes the lock file descriptor, which causes the kernel to release
    the flock. Safe to call multiple times — idempotent via the
    _lock_fd is-not-None guard.
    """
    global _lock_fd  # noqa: PLW0603

    if _lock_fd is not None:
        with suppress(OSError):
            os.close(_lock_fd)
        _lock_fd = None


def _on_battery_power() -> bool:
    """Check if the device is running on battery power.

    Returns True only if a battery is present AND currently discharging.
    Returns False if on AC power, no battery found, or detection fails.

    Platform support:
    - macOS: uses ``pmset -g ps``
    - Linux: reads ``/sys/class/power_supply/BAT*/status`` via glob
    - Windows/other: returns ``False`` (no detection available)
    """
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["pmset", "-g", "ps"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "Battery Power" in result.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.debug("Battery power check failed", exc_info=True)
            return False
    elif sys.platform == "linux":
        bat_paths = sorted(Path("/sys/class/power_supply").glob("BAT*/status"))
        if not bat_paths:
            return False
        try:
            return any(path.read_text().strip() == "Discharging" for path in bat_paths)
        except OSError:
            logger.debug("Battery power check failed", exc_info=True)
            return False
    else:
        return False


def _remove_pid_file() -> None:
    """Remove the daemon PID file if it exists."""
    pid_path = get_data_dir() / PID_FILENAME
    try:
        pid_path.unlink(missing_ok=True)
    except OSError:
        logger.debug("Could not remove PID file", exc_info=True)


def _cleanup_stuck_syncing_feeds(db_path: Path, config: PKGDConfig | None = None) -> None:
    """Reset any 'syncing' feed_state rows to 'idle' on daemon startup.

    This is a forward-looking defense-in-depth fix: 'syncing' is a valid
    status in the schema CHECK constraint but is never set by production
    code today. When a future change adds a status='syncing' marker before
    feed.fetch(), a crash mid-sync would leave feeds stuck indefinitely.
    This cleanup ensures self-healing on daemon restart.

    Safe to run on databases with no 'syncing' rows (no-op) and safe to
    call multiple times (idempotent).

    Args:
        db_path: Path to the SQLite threats database.
        config: Optional PKGDConfig. If provided, its database settings
            override the hardcoded PRAGMA defaults.
    """
    conn = get_connection(db_path, config=config.database if config is not None else None)
    try:
        conn.execute("UPDATE feed_state SET status='idle', updated_at=datetime('now') WHERE status='syncing'")
        conn.commit()
    finally:
        conn.close()


async def daemon_loop(config: PKGDConfig) -> None:
    """Run the daemon: periodic feed sync with heartbeat and graceful shutdown.

    Args:
        config: Resolved PKGDConfig instance.
    """
    data_dir = get_data_dir()
    db_path = get_db_path(config)

    feeds: list[FeedSource] = [OSVFeedAdapter()]
    if config.feeds.ghsa_enabled:
        feeds.append(GHSAFeed())
    if config.feeds.socket_enabled:
        feeds.append(SocketFeed())
    if config.feeds.npm_advisory_enabled:
        feeds.append(NpmAdvisoryFeed())
    if config.feeds.mastodon_enabled:
        feeds.append(MastodonFeed())
    if config.feeds.reddit_enabled:
        feeds.append(RedditFeed())
    if config.feeds.rss_enabled:
        feeds.append(RSSFeed())
    if config.feeds.x_twitter_enabled:
        feeds.append(XTwitterFeed())
    if config.feeds.ossf_malicious_enabled:
        feeds.append(OSSFMaliciousFeed())
    aggregator = FeedAggregator(
        feeds,
        db_path,
        retention_days=config.database.retention_days,
    )

    # Ensure DB tables exist before cleanup attempt
    init_db(db_path).close()

    # Reset any stuck 'syncing' feed states from a previous crash
    _cleanup_stuck_syncing_feeds(db_path, config=config)

    # Shutdown flag set by signal handlers
    shutdown = asyncio.Event()

    def _request_shutdown() -> None:
        logger.info("Shutdown signal received")
        shutdown.set()
        # Release exclusive lock on signal shutdown
        release_lock()
        _remove_pid_file()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, _request_shutdown)
    if hasattr(signal, "SIGTERM"):
        loop.add_signal_handler(signal.SIGTERM, _request_shutdown)

    consecutive_failures = 0

    logger.info("Daemon started (sync interval: %dh)", config.daemon.sync_interval_hours)

    # Wrap the main loop in try/except/finally to ensure DB cleanup on all exit paths
    try:
        while not shutdown.is_set():
            try:
                logger.info("Starting feed sync cycle")
                _sync_start = datetime.now(UTC)

                # Write startup heartbeat so `daemon status` can see we're alive during first sync
                write_heartbeat(
                    data_dir,
                    {
                        "last_sync": _sync_start.isoformat(),
                        "status": "syncing",
                        "error": None,
                        "feeds": {},
                    },
                )

                feeds_result = await asyncio.wait_for(
                    aggregator.sync_all(),
                    timeout=config.feeds.feed_sync_timeout if config.feeds.feed_sync_timeout > 0 else None,
                )

                heartbeat_data: dict[str, Any] = {
                    "last_sync": datetime.now(UTC).isoformat(),
                    "status": "ok",
                    "error": None,
                    "feeds": feeds_result,
                }

                write_heartbeat(data_dir, heartbeat_data)

                logger.info(
                    "event=feed_sync_complete feeds=%s counts=%s duration_ms=%d",
                    list(feeds_result.keys()),
                    feeds_result,
                    int((datetime.now(UTC) - _sync_start).total_seconds() * 1000),
                )

                consecutive_failures = 0

                # Log any per-feed failures that occurred during the sync
                failed = aggregator.get_failed_feeds()
                if failed:
                    logger.warning(
                        "Feed sync completed with %d failed feed(s): %s",
                        len(failed),
                        ", ".join(failed.keys()),
                    )

            except TimeoutError:
                consecutive_failures += 1
                backoff = min(
                    BACKOFF_BASE_SECONDS * (BACKOFF_MULTIPLIER ** (consecutive_failures - 1)),
                    BACKOFF_MAX_SECONDS,
                )
                logger.error(
                    "Feed sync timed out after %ds (attempt %d, backoff %ds)",
                    config.feeds.feed_sync_timeout,
                    consecutive_failures,
                    backoff,
                )
                logger.error(
                    "event=feed_sync_timeout timeout=%d attempt=%d backoff_seconds=%d",
                    config.feeds.feed_sync_timeout,
                    consecutive_failures,
                    backoff,
                )

                timeout_heartbeat: dict[str, Any] = {
                    "last_sync": datetime.now(UTC).isoformat(),
                    "status": "error",
                    "error": f"Feed sync timed out after {config.feeds.feed_sync_timeout}s",
                    "feeds": {},
                }

                write_heartbeat(data_dir, timeout_heartbeat)

                try:
                    await asyncio.wait_for(shutdown.wait(), timeout=backoff)
                    break
                except TimeoutError:
                    pass
                continue
            except Exception as exc:
                consecutive_failures += 1
                backoff = min(
                    BACKOFF_BASE_SECONDS * (BACKOFF_MULTIPLIER ** (consecutive_failures - 1)),
                    BACKOFF_MAX_SECONDS,
                )
                logger.error(
                    "Sync failed (attempt %d, backoff %ds): %s",
                    consecutive_failures,
                    backoff,
                    exc,
                )
                logger.error(
                    "event=feed_sync_error attempt=%d backoff_seconds=%d error=%s",
                    consecutive_failures,
                    backoff,
                    exc,
                )

                error_heartbeat: dict[str, Any] = {
                    "last_sync": datetime.now(UTC).isoformat(),
                    "status": "error",
                    "error": str(exc),
                    "feeds": {},
                }

                write_heartbeat(data_dir, error_heartbeat)

                # Sleep with backoff, but still respect shutdown
                try:
                    await asyncio.wait_for(shutdown.wait(), timeout=backoff)
                    break  # shutdown was set
                except TimeoutError:
                    pass  # backoff elapsed, retry
                continue

            # Normal sleep between cycles
            sleep_seconds = config.daemon.sync_interval_hours * 3600
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=sleep_seconds)
                break  # shutdown was set
            except TimeoutError:
                pass  # interval elapsed, next sync
        # end while
    except asyncio.CancelledError:
        # Signal shutdown path — ensure cleanup
        _request_shutdown()
        raise
    logger.info("Daemon stopped")


def run_daemon(config_path: Path | None = None) -> None:
    """Entry point for running the daemon in the foreground.

    Loads config, sets up logging, and runs the async daemon loop.
    Catches KeyboardInterrupt for clean shutdown.

    Args:
        config_path: Explicit config file path, or None for default.
    """
    import atexit as _atexit

    # Register atexit handler for critical cleanup
    def _cleanup() -> None:
        """Cleanup handler for daemon shutdown.

        Note: Exception suppression preserves the original exit code.
        If an exception is raised here after SystemExit was raised,
        Python's exit code comes from the SystemExit, not any cleanup
        exception. The bare except (or pass) ensures cleanup failures
        don't override the intentional exit code.
        """
        with suppress(BaseException):
            release_lock()
        _remove_pid_file()

    _atexit.register(_cleanup)

    config = load_config(config_path)

    logging.basicConfig(
        level=logging.DEBUG if config.output.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Add secret redaction filter to root logger
    root_logger = logging.getLogger()
    root_logger.addFilter(SecretRedactingFilter())

    # Write PID file BEFORE daemon starts — acquires exclusive lock
    # If another instance is running, this raises RuntimeError
    acquire_single_instance_lock(get_data_dir())

    # SG2: Self-terminate on battery unless explicitly allowed
    if not config.daemon.run_on_battery and _on_battery_power():
        logger.warning(
            "Running on battery power - daemon will not start to conserve power. "
            "Set daemon.run_on_battery=true to override."
        )
        release_lock()
        return

    # Import exit code inside try block to avoid circular import
    from pkg_defender.cli._exit_codes import EXIT_SIGINT as _EXIT_SIGINT

    try:
        asyncio.run(daemon_loop(config))
    except asyncio.CancelledError:
        # asyncio.run() converts KeyboardInterrupt to CancelledError.
        # Handle both to ensure consistent exit code 130.
        logger.info("Daemon interrupted")
        raise SystemExit(_EXIT_SIGINT) from None
    except KeyboardInterrupt:
        logger.info("Daemon interrupted")
        raise SystemExit(_EXIT_SIGINT) from None
    except SystemExit:
        logger.info("Daemon exiting")
        raise
