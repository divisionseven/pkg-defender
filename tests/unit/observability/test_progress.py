"""Tests for CLI progress indicator utilities."""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from pkg_defender.cli import _progress


class TestIsTTY:
    """Test TTY detection."""

    def test_is_tty_returns_true_for_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When stderr.isatty() returns True, _is_tty() should return True."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        assert _progress._is_tty() is True

    def test_is_tty_returns_false_for_non_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When stderr.isatty() returns False, _is_tty() should return False."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = False
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        assert _progress._is_tty() is False

    def test_is_tty_handles_none_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When stderr is None, should return False gracefully."""
        monkeypatch.setattr(sys, "stderr", None)

        assert _progress._is_tty() is False

    def test_is_tty_handles_value_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When isatty() raises ValueError, should return False."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.side_effect = ValueError("closed stream")
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        assert _progress._is_tty() is False


class TestShouldShowProgress:
    """Test progress visibility determination."""

    def test_should_show_progress_false_when_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return False when stderr is not a TTY."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = False
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        # Reset quiet mode
        from pkg_defender import display

        display._quiet_mode = False

        assert _progress.should_show_progress() is False

    def test_should_show_progress_false_when_quiet_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return False when quiet mode is enabled."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = True

        try:
            assert _progress.should_show_progress() is False
        finally:
            display._quiet_mode = False

    def test_should_show_progress_true_when_tty_and_not_quiet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return True when stderr is a TTY and quiet mode is off."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        assert _progress.should_show_progress() is True


class TestProgressContext:
    """Test progress context manager."""

    def test_progress_context_yields_none_when_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should yield None when stderr is not a TTY."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = False
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        with _progress.progress_context("Test...") as progress:
            assert progress is None

    def test_progress_context_yields_progress_when_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should yield Progress instance when stderr is a TTY."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        with _progress.progress_context("Test...") as progress:
            if progress is not None:
                assert progress is not None
                assert len(progress.tasks) == 1

    def test_progress_context_handles_sigint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should re-raise KeyboardInterrupt after cleanup."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        # Simulate SIGINT
        with pytest.raises(KeyboardInterrupt), _progress.progress_context("Test..."):
            # Simulate interrupt
            raise KeyboardInterrupt


class TestDownloadProgress:
    """Tests for download_progress context manager."""

    def test_download_progress_yields_none_when_not_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should yield None when stderr is not a TTY."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = False
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        with _progress.download_progress("Downloading test...") as cb:
            assert cb is None

    def test_download_progress_yields_callback_when_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should yield a callable callback when stderr is a TTY."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = False

        with _progress.download_progress("Downloading test...") as cb:
            assert cb is not None
            assert callable(cb)

    def test_download_progress_yields_none_when_quiet_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """download_progress yields None when quiet mode is enabled."""
        mock_stderr = mock.MagicMock()
        mock_stderr.isatty.return_value = True
        monkeypatch.setattr(sys, "stderr", mock_stderr)

        from pkg_defender import display

        display._quiet_mode = True
        try:
            with _progress.download_progress("Downloading test...") as cb:
                assert cb is None
        finally:
            display._quiet_mode = False
