"""Tests for handle_feed_complete sentinel value and progress bar behavior.

Targets: _progress.handle_feed_complete

Coverage goals:
  - Sentinel -1 produces red error message (not green)
  - record_count == 0 still produces green "up to date" message
  - record_count > 0 still produces green success message
  - homebrew with record_count > 0 still produces yellow warning
  - progress.update(task, advance=1) called regardless of record_count
  - progress=None is a no-op
"""

from __future__ import annotations

from unittest.mock import MagicMock

from pkg_defender.cli._progress import handle_feed_complete


class TestHandleFeedComplete:
    """Tests for handle_feed_complete()."""

    def test_handle_feed_complete_sentinel_minus_one(self) -> None:
        """record_count=-1 prints red error with ✗ and 'sync failed'."""
        progress = MagicMock()
        task = MagicMock()

        handle_feed_complete(progress, task, "osv", -1)

        progress.update.assert_called_once_with(task, advance=1)
        progress.console.print.assert_called_once()
        msg = progress.console.print.call_args[0][0]
        assert "[red]" in msg
        assert "\u2717" in msg
        assert "sync failed" in msg

    def test_handle_feed_complete_zero_records(self) -> None:
        """record_count=0 prints green checkmark with 'already up to date' message."""
        progress = MagicMock()
        task = MagicMock()

        handle_feed_complete(progress, task, "osv", 0)

        progress.update.assert_called_once_with(task, advance=1)
        progress.console.print.assert_called_once()
        msg = progress.console.print.call_args[0][0]
        assert "[green]" in msg
        assert "\u2713" in msg
        assert "sync failed" not in msg

    def test_handle_feed_complete_positive_records(self) -> None:
        """Positive record_count prints green checkmark with count."""
        progress = MagicMock()
        task = MagicMock()

        handle_feed_complete(progress, task, "osv", 5)

        progress.update.assert_called_once_with(task, advance=1)
        progress.console.print.assert_called_once()
        msg = progress.console.print.call_args[0][0]
        assert "[green]" in msg
        assert "\u2713" in msg
        assert "5" in msg

    def test_handle_feed_complete_homebrew_vulnerable(self) -> None:
        """homebrew with >0 records prints yellow warning."""
        progress = MagicMock()
        task = MagicMock()

        handle_feed_complete(progress, task, "homebrew", 3)

        progress.update.assert_called_once_with(task, advance=1)
        progress.console.print.assert_called_once()
        msg = progress.console.print.call_args[0][0]
        assert "[bold yellow]" in msg
        assert "\u26a0" in msg
        assert "VULNERABILITIES" in msg

    def test_handle_feed_complete_always_advances(self) -> None:
        """progress.update(task, advance=1) is called regardless of record_count."""
        progress = MagicMock()
        task = MagicMock()

        handle_feed_complete(progress, task, "osv", -1)
        progress.update.assert_called_once_with(task, advance=1)

        progress.reset_mock()
        handle_feed_complete(progress, task, "osv", 0)
        progress.update.assert_called_once_with(task, advance=1)

        progress.reset_mock()
        handle_feed_complete(progress, task, "osv", 10)
        progress.update.assert_called_once_with(task, advance=1)

        progress.reset_mock()
        handle_feed_complete(progress, task, "homebrew", 5)
        progress.update.assert_called_once_with(task, advance=1)

    def test_handle_feed_complete_none_progress(self) -> None:
        """progress=None is a no-op — no exception, no console.print call."""
        # Should not raise
        handle_feed_complete(None, MagicMock(), "osv", -1)
        handle_feed_complete(None, MagicMock(), "osv", 0)
        handle_feed_complete(None, MagicMock(), "osv", 10)

        # Also verify that a fake progress object was never created
        # (no AttributeError from .console.print on None)
        assert True
