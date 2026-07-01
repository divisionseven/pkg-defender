"""ASCII banner loading for CLI help output."""

import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Any, Final

__all__ = ["Path", "get_banner", "get_terminal_width", "should_use_color", "reset_width_cache"]

# Banner directory relative to package root
# Path(__file__) gives src/pkg_defender/cli/banners.py
# .parent = src/pkg_defender/cli
# .parent.parent = src/pkg_defender
# .parent.parent.parent = src
# .parent.parent.parent.parent = project root (where docs/ lives)
_BANNER_DIR = Path(__file__).parent.parent.parent.parent / "docs" / "assets" / "brand" / "banners"

# Column width thresholds (exact, no buffer)
WIDTH_60: Final = 60
WIDTH_85: Final = 85

# Threshold boundaries (exact terminal width)
# < 70 → NO BANNER (return empty string)
# 70-94 → 60-column banner
# ≥ 95 → 85-column banner (max available)
THRESHOLD_NO_BANNER: Final = 70  # Terminal < 70: no banner
THRESHOLD_60: Final = 95  # Terminal 70-94: 60-column (max 94)
# Terminal ≥ 95: 85-column banner (max available)


# Cache for terminal width (updated via SIGWINCH)
_cached_width: int | None = None


def _handle_winch(signum: int, frame: Any) -> None:
    """Handle SIGWINCH signal to invalidate terminal width cache."""
    global _cached_width
    _cached_width = None  # Invalidate cache to force recalculation


def reset_width_cache() -> None:
    """Reset the terminal width cache. Useful for testing."""
    global _cached_width
    _cached_width = None


# Register handler only if SIGWINCH exists (not on Windows)
if hasattr(signal, "SIGWINCH"):
    signal.signal(signal.SIGWINCH, _handle_winch)


def get_terminal_width() -> int:
    """Get terminal width with COLUMNS env var priority.

    Per shutil documentation, COLUMNS env var takes precedence over
    shutil.get_terminal_size().columns.

    Returns:
        Terminal width in columns (default 80 if undetectable).
    """
    global _cached_width
    if _cached_width is not None:
        return _cached_width

    # COLUMNS env var has highest priority per shutil docs
    columns_env = os.environ.get("COLUMNS")
    if columns_env is not None:
        try:
            result = int(columns_env)
            _cached_width = result
            return result
        except ValueError:
            pass

    # Fallback to shutil detection
    try:
        size = shutil.get_terminal_size()
        if size.columns > 0:
            _cached_width = size.columns
            return size.columns
    except OSError:
        pass

    _cached_width = 80
    return 80


def should_use_color() -> bool:
    """Determine if color output should be used.

    Respects:
    - NO_COLOR env var (standard per https://no-color.org/)
    - FORCE_COLOR env var (override)
    - TERM=dumb env var (POSIX standard - disable colors)
    - stdout.isatty() (disable if not connected to terminal)

    Returns:
        True if color should be used, False otherwise.
    """
    if "--no-color" in sys.argv:
        return False

    if os.environ.get("NO_COLOR") is not None:
        return False

    # Check this before FORCE_COLOR since a dumb terminal cannot display ANSI at all
    if os.environ.get("TERM") == "dumb":
        return False

    if os.environ.get("FORCE_COLOR") is not None:
        return True

    # Only check if stdout is not None (handles redirected cases)
    if sys.stdout is not None:
        try:
            if not sys.stdout.isatty():
                return False
        except ValueError:
            # ValueError can occur if stdout is closed or wrapped in certain ways
            return False

    # Default to color enabled
    return True


def _select_width_category(width: int) -> str:
    """Select banner width category based on terminal width.

    EXACT thresholds (no buffer):
    - width < 70 → "" (no banner)
    - 70 ≤ width ≤ 94 → "60" (60-column banner)
    - width ≥ 95 → "85" (85-column banner - max available)

    Returns:
        Width category string ("60", "85") or "" for no banner.
    """
    if width < THRESHOLD_NO_BANNER:
        return ""  # No banner for narrow terminals
    elif width < THRESHOLD_60:
        return "60"  # 70-94: 60-column
    else:
        return "85"  # ≥95: 85-column (max)


def get_banner() -> str:
    """Load and return the appropriate ASCII banner for help output.

    Selects banner based on:
    1. Terminal width (60, 85, or 100 column variants, or none if < 70)
    2. Color preference (color or plain variants based on NO_COLOR)

    Returns:
        Banner string with trailing newline, or empty string if no banner should
        be shown or if load fails.
    """
    width = get_terminal_width()
    use_color = should_use_color()
    width_cat = _select_width_category(width)

    if not width_cat:
        return ""

    subdir = "color" if use_color else "plain"

    # Construct filename: pkgd_logo_ascii_{plain|color}_w{width}.txt
    variant = "color" if use_color else "plain"
    filename = f"pkgd_logo_ascii_{variant}_w{width_cat}.txt"

    filepath = _BANNER_DIR / subdir / filename

    try:
        return filepath.read_text(encoding="utf-8")
    except OSError:
        # Banner file not found or unreadable — return empty string
        return ""
