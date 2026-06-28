"""Regression tests for SIGINT (Ctrl+C) handling in CLI commands.

NOTE: These tests verify CLI entry point signal handling (the click command
runner). Daemon-level SIGINT handling is tested in test_daemon.py.
"""

from __future__ import annotations

import signal
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from pkg_defender.cli._exit_codes import EXIT_SIGINT


class TestSIGINTHandling:
    """Test SIGINT (Ctrl+C) handling in CLI commands.

    These tests verify the EXIT_SIGINT constant and ensure the CLI
    properly handles keyboard interrupts. Daemon-level tests are
    in test_daemon.py.
    """

    def test_exit_sigint_constant_is_130(self, runner: CliRunner) -> None:
        """Verify EXIT_SIGINT constant equals 130.

        Regression test: ensures the exit code constant used when
        handling SIGINT (Ctrl+C) is correctly set to 130.
        """
        assert EXIT_SIGINT == 130, "EXIT_SIGINT should be 130"

    def test_sigint_handler_exits_130(self) -> None:
        """_sigint_handler calls sys.exit(EXIT_SIGINT), not raise KeyboardInterrupt.

        Regression test for #8.6: verifies the SIGINT handler raises SystemExit
        with code 130 instead of KeyboardInterrupt (which Click converts to exit
        code 1).
        """
        from pkg_defender.cli._progress import _sigint_handler

        mock_progress = MagicMock()
        original_handler = signal.SIG_DFL

        with pytest.raises(SystemExit) as exc_info:
            _sigint_handler(signal.SIGINT, None, mock_progress, original_handler)

        assert exc_info.value.code == EXIT_SIGINT
        mock_progress.stop.assert_called_once()

    def test_sigint_handler_restores_original_handler(self) -> None:
        """_sigint_handler restores the original SIGINT handler before exiting.

        Regression test for #8.6: ensures the handler cleanup sequence is
        correct — the original handler must be restored before sys.exit so
        that subsequent SIGINTs are handled by the restored handler.
        """
        from pkg_defender.cli._progress import _sigint_handler

        mock_progress = MagicMock()
        original_handler = signal.SIG_IGN

        # Save the current handler so we can restore after the test
        saved_handler = signal.getsignal(signal.SIGINT)
        try:
            with pytest.raises(SystemExit):
                _sigint_handler(signal.SIGINT, None, mock_progress, original_handler)

            assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN
        finally:
            signal.signal(signal.SIGINT, saved_handler)
