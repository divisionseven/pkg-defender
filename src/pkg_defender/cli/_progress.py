# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Progress indicator utilities for CLI commands.

Supports NO_COLOR environment variable (checked at module init).
"""

from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from pkg_defender.cli._exit_codes import EXIT_SIGINT

# Module-level console for stderr output
# Respects NO_COLOR environment variable (always wins, checked at module init)
_no_color = os.environ.get("NO_COLOR") is not None
_console = Console(stderr=True, no_color=_no_color)

# Per-feed descriptive messages for sync completion.
# Keys: feed_name.  Values: dict with '>0' and '==0' template strings.
# {feed_name} is replaced with the display name, {N} with the record count.
# {N:,} formats with comma separators; {N} formats as raw integer.
FEED_DESCRIPTIVE_MESSAGES: dict[str, dict[str, str]] = {
    "osv": {
        ">0": "{feed_name}: {N:,} vulnerabilities loaded",
        "==0": "{feed_name}: database unchanged \u2014 already up to date",
    },
    "ossf_malicious": {
        ">0": "{feed_name}: {N:,} malicious package records loaded",
        "==0": "{feed_name}: data unchanged \u2014 already up to date",
    },
    "ghsa": {
        ">0": "{feed_name}: {N} advisories updated since last sync",
        "==0": "{feed_name}: no advisories updated since last sync",
    },
    "homebrew": {
        ">0": "{feed_name}: {N} VULNERABILITIES FOUND in installed packages",
        "==0": "{feed_name}: no vulnerabilities found in installed packages",
    },
    "rss": {
        ">0": "{feed_name}: {N} entries matched keywords",
        "==0": "{feed_name}: no entries matched keywords",
    },
    "mastodon": {
        ">0": "{feed_name}: {N} posts mentioning packages",
        "==0": "{feed_name}: no package mentions found",
    },
    "reddit": {
        ">0": "{feed_name}: {N} posts matching keywords",
        "==0": "{feed_name}: no posts matching keywords",
    },
    "x_twitter": {
        ">0": "{feed_name}: {N} tweets mentioning packages",
        "==0": "{feed_name}: no matching tweets found",
    },
    "npm_advisory": {
        ">0": "{feed_name}: {N} advisories found",
        "==0": "{feed_name}: no advisories found",
    },
    "socket": {
        ">0": "{feed_name}: bulk fetch not supported",
        "==0": "{feed_name}: bulk fetch not supported",
    },
}

# Display name overrides — maps internal feed keys to user-facing names.
_DISPLAY_NAME_MAP: dict[str, str] = {
    "x_twitter": "twitter",
    "npm_advisory": "npm",
}


def format_feed_message(feed_name: str, record_count: int) -> str:
    """Return the descriptive sync-completion message for a feed.

    Args:
        feed_name: Feed identifier (e.g. ``"osv"``, ``"homebrew"``).
        record_count: Number of records synced (0 means no new data).

    Returns:
        A human-readable status string describing what the feed did.
    """
    display_name = _DISPLAY_NAME_MAP.get(feed_name, feed_name)
    mapping = FEED_DESCRIPTIVE_MESSAGES.get(feed_name)
    if mapping is None:
        # Fallback for unknown feeds
        if record_count > 0:
            suffix = "record" if record_count == 1 else "records"
            return f"{display_name}: {record_count:,} {suffix}"
        return f"{display_name}: 0 records"
    template = mapping[">0"] if record_count > 0 else mapping["==0"]
    return template.format(feed_name=display_name, N=record_count)


def handle_feed_complete(
    progress: Progress | None,
    task: Any,
    feed_name: str,
    record_count: int,
) -> None:
    """Advance a sync progress bar and print a feed-completion message.

    Shared between ``intel.py`` and ``dispatcher.py`` to prevent the
    feed-completion callbacks from diverging.

    Args:
        progress: Progress instance (or None for no-op).
        task: Task ID within the progress bar.
        feed_name: Feed identifier (e.g. ``"osv"``, ``"homebrew"``).
        record_count: Number of records that were synced.
    """
    if progress is not None:
        progress.update(task, advance=1)
        if record_count == -1:
            progress.console.print(f"  [red]\u2717[/red] {feed_name}: sync failed \u2014 see log for details")
        elif feed_name == "homebrew" and record_count > 0:
            progress.console.print(
                f"  [bold yellow]\u26a0[/bold yellow] {format_feed_message(feed_name, record_count)}"
            )
        else:
            progress.console.print(f"  [green]\u2713[/green] {format_feed_message(feed_name, record_count)}")


def handle_feed_error(
    progress: Progress | None,
    task: Any,
    feed_name: str,
    error: Exception,
) -> None:
    """Print a feed-failure message to the progress console.

    Shared between ``intel.py`` and ``dispatcher.py``, analogous to
    ``handle_feed_complete`` but for the ``error_callback`` path.

    Args:
        progress: Progress instance (or None for no-op).
        task: Task ID within the progress bar.
        feed_name: Feed identifier (e.g. ``"osv"``, ``"homebrew"``).
        error: The exception that caused the failure.
    """
    if progress is not None:
        error_type = type(error).__name__
        error_msg = str(error)
        # Truncate long error messages to avoid cluttering the progress bar
        if len(error_msg) > 80:
            error_msg = error_msg[:77] + "..."
        progress.console.print(f"  [red]\u2717[/red] {feed_name}: {error_type}: {error_msg}")


def set_progress_no_color(enabled: bool = True) -> None:
    """Set no_color flag on the module-level console and update _no_color.

    Called from main.py after config.output.color is loaded, when the
    config says color should be disabled and no explicit override is active.
    """
    global _no_color
    _no_color = enabled
    _console.no_color = enabled


def _is_tty() -> bool:
    """Check if stderr is connected to a terminal."""
    try:
        return sys.stderr is not None and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def should_show_progress() -> bool:
    """Determine if progress indicators should be shown.

    Returns:
        True if progress should be shown, False otherwise.
    """
    if not _is_tty():
        return False

    from pkg_defender.display import is_quiet_mode

    return not is_quiet_mode()


def _sigint_handler(
    signum: int,
    frame: object,
    progress: Progress,
    original_handler: signal._HANDLER,
) -> None:
    """Handle SIGINT gracefully during progress.

    Stops the spinner, restores the original SIGINT handler, then
    calls ``sys.exit(EXIT_SIGINT)`` so the process exits with code 130.

    ``SystemExit`` (raised by ``sys.exit``) is a ``BaseException`` and
    propagates through Click and ``run_cli()``'s ``except Exception``
    handler, producing the correct exit code.
    """
    progress.stop()
    signal.signal(signal.SIGINT, original_handler)
    sys.exit(EXIT_SIGINT)


@contextmanager
def progress_context(
    description: str,
    transient: bool = True,
) -> Generator[Progress | None, None, None]:
    """Context manager for displaying progress with graceful SIGINT handling.

    Args:
        description: Text to display alongside spinner
        transient: If True, remove progress bar after completion

    Yields:
        Progress instance if progress should be shown, None otherwise.

    Behavior:
        - Renders to stderr (not stdout)
        - Shows plain text (no spinner) when stdout is not a TTY
        - Suppressed when quiet mode is enabled
        - SIGINT (Ctrl+C) is caught and re-raised after cleanup
    """
    if not should_show_progress():
        yield None
        return

    # Configure rich Progress with spinner, text, and time columns
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeRemainingColumn(),
        console=Console(stderr=True, no_color=_no_color),
        auto_refresh=True,
        transient=transient,
        disable=False,
    )

    # Set up SIGINT handler
    original_sigint_handler = signal.getsignal(signal.SIGINT)

    try:
        signal.signal(
            signal.SIGINT,
            lambda signum, frame: _sigint_handler(signum, frame, progress, original_sigint_handler),
        )
        progress.start()
        progress.add_task(description, total=None)
        yield progress
    except KeyboardInterrupt:
        raise
    finally:
        with suppress(Exception):
            progress.stop()
        signal.signal(signal.SIGINT, original_sigint_handler)


def with_progress(
    func: Callable[..., Any],
    description: str,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Decorator for running a function with progress indicator.

    Args:
        func: Async function to run
        description: Text to display alongside spinner

    Returns:
        Result of the wrapped function
    """
    import asyncio

    async def _wrapper() -> Any:
        with progress_context(description) as progress:
            task_id = (progress.tasks[0].id if progress.tasks else None) if progress else None
            result = await func(*args, **kwargs)
            if progress and task_id is not None:
                progress.update(task_id, completed=True)
            return result

    return asyncio.run(_wrapper())


@contextmanager
def feed_sync_progress(
    total_feeds: int,
) -> Generator[Progress | None, None, None]:
    """Brandbox-style per-feed progress bar for feed sync.

    Creates a Progress bar with SpinnerColumn (cyan), TextColumn (bold),
    BarColumn (30-wide), MofNCompleteColumn, and TimeElapsedColumn.
    The caller creates a task on the yielded Progress and advances it
    via a ``progress_callback`` passed to ``FeedAggregator.sync_all()``.

    Args:
        total_feeds: Total number of feeds to sync (sets the bar total).

    Yields:
        Progress instance if progress should be shown, None otherwise.
    """
    if not should_show_progress():
        yield None
        return

    console = Console(stderr=True, no_color=_no_color)
    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30, style="dim", complete_style="cyan"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    with progress:
        yield progress


@contextmanager
def download_progress(
    description: str,
) -> Generator[Callable[[int, int | None], None] | None, None, None]:
    """Context manager for tracking download progress with Rich progress bar.

    Yields a callback(downloaded_bytes, total_bytes) that advances a Rich
    progress bar showing cumulative bytes downloaded and transfer speed.

    Uses advance-only mode (total=None) because sequential multi-file
    downloads have different content lengths — cumulative context is
    more useful than per-file completion.

    Yields None when progress should not be shown (non-TTY or quiet mode).

    Args:
        description: Text to display alongside the progress bar.

    Yields:
        A callback to report (downloaded_bytes, total_bytes), or None.
    """
    if not should_show_progress():
        yield None
        return

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=_console,
    )

    task_id = progress.add_task(description, total=None)

    def _callback(downloaded: int, total: int | None = None) -> None:
        """Advance the progress bar by downloaded bytes."""
        progress.update(task_id, advance=downloaded)

    with progress:
        yield _callback
