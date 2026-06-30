"""Tests for exception handling, signal handling, and run_cli error paths.

These functions are invoked at runtime when things go wrong —
testing them ensures exit codes, user-facing messages, and traceback
disclosure all behave correctly under failure conditions.
"""

from __future__ import annotations

import os
import signal
from unittest import mock

import click
import pytest

from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR, EXIT_SIGINT
from pkg_defender.cli.main import _handle_exception, _handle_sigint, run_cli

pytestmark = pytest.mark.unit


class TestHandleException:
    """Tests for ``_handle_exception`` — the unexpected-exception handler.

    Covers both debug=True (full traceback) and debug=False (user-friendly
    message) paths. The function is a standalone utility called from
    ``run_cli()``, so it's tested directly.
    """

    def test_returns_exit_general_error_when_debug_false(self) -> None:
        """Non-debug mode returns ``EXIT_GENERAL_ERROR`` and echoes an error message."""
        e = ValueError("test")

        with mock.patch("click.echo") as mock_echo:
            result = _handle_exception(e, debug=False)

        assert result == EXIT_GENERAL_ERROR
        mock_echo.assert_any_call("Error: test", err=True)
        # Second call should contain the --debug hint
        hint_found = any("--debug" in str(call_args) for call_args, _ in mock_echo.call_args_list)
        assert hint_found, "Expected click.echo to be called with --debug hint"

    def test_returns_exit_general_error_when_debug_true(self) -> None:
        """Debug mode returns ``EXIT_GENERAL_ERROR`` and echoes traceback output."""
        e = ValueError("test")

        with mock.patch("click.echo") as mock_echo:
            result = _handle_exception(e, debug=True)

        assert result == EXIT_GENERAL_ERROR
        mock_echo.assert_called_once_with(mock.ANY, err=True)

    def test_prints_friendly_message_when_debug_false(self) -> None:
        """Non-debug error message includes the exception text and a --debug hint."""
        e = RuntimeError("something broke")

        with mock.patch("click.echo") as mock_echo:
            _handle_exception(e, debug=False)

        # First call: error text
        first_call_args = mock_echo.call_args_list[0][0] if mock_echo.call_args_list else ""
        assert "something broke" in str(first_call_args)
        # Second call: --debug hint
        second_call_args = mock_echo.call_args_list[1][0] if len(mock_echo.call_args_list) > 1 else ""
        assert "--debug" in str(second_call_args)

    def test_uses_traceback_module_when_debug_true(self) -> None:
        """Debug mode calls ``traceback.format_exc()`` and echoes its output."""
        e = RuntimeError("crash")

        with (
            mock.patch("click.echo") as mock_echo,
            mock.patch("traceback.format_exc", return_value="TRACEBACK") as mock_tb,
        ):
            _handle_exception(e, debug=True)

        mock_tb.assert_called_once()
        mock_echo.assert_called_once_with("TRACEBACK", err=True)


class TestHandleSigint:
    """Tests for ``_handle_sigint`` — the SIGINT (Ctrl+C) signal handler.

    Verifies the handler exits with the correct signal-specific exit code
    and that ``run_cli()`` registers it as the SIGINT handler.
    """

    def test_calls_sys_exit_with_sigint_code(self) -> None:
        """Signal handler calls ``sys.exit(EXIT_SIGINT)`` when SIGINT is received."""
        with mock.patch("sys.exit") as mock_exit:
            mock_exit.side_effect = SystemExit

            with pytest.raises(SystemExit):
                _handle_sigint(signal.SIGINT, None)

        mock_exit.assert_called_once_with(EXIT_SIGINT)

    def test_signal_handler_registered_in_run_cli(self) -> None:
        """``run_cli()`` registers ``_handle_sigint`` as the SIGINT handler."""
        with mock.patch("signal.signal") as mock_signal:
            run_cli(["--help"], standalone=False)

        mock_signal.assert_called_once_with(signal.SIGINT, _handle_sigint)


class TestRunCliErrorHandlers:
    """Tests for error-handling paths in ``run_cli()``.

    Verifies that ``click.UsageError`` is caught and returned cleanly,
    unexpected exceptions are routed through ``_handle_exception``, and
    the ``PKGD_DEBUG`` env var is correctly passed to the handler.
    """

    def test_handles_usage_error_gracefully(self) -> None:
        """``click.UsageError`` caught by ``run_cli()`` returns the error's exit code."""

        class _FixedExitCode(click.UsageError):
            exit_code = 42

        usage_error = _FixedExitCode("test")

        with mock.patch(
            "pkg_defender.cli.main.cli.main",
            side_effect=usage_error,
        ):
            result = run_cli(["ignored"], standalone=False)

        assert result == 42

    def test_handles_unexpected_exception_returns_error_code(self) -> None:
        """Generic ``Exception`` in ``cli.main()`` routes to ``_handle_exception``."""
        with (
            mock.patch(
                "pkg_defender.cli.main.cli.main",
                side_effect=RuntimeError("crash"),
            ),
            mock.patch(
                "pkg_defender.cli.main._handle_exception",
                return_value=EXIT_GENERAL_ERROR,
            ) as mock_handle,
        ):
            result = run_cli(["ignored"], standalone=False)

        assert result == EXIT_GENERAL_ERROR
        mock_handle.assert_called_once_with(mock.ANY, mock.ANY)

    def test_debug_env_var_passed_to_exception_handler(self) -> None:
        """When ``PKGD_DEBUG=1`` is set, ``_handle_exception`` receives ``debug=True``."""
        with (
            mock.patch.dict(os.environ, {"PKGD_DEBUG": "1"}),
            mock.patch(
                "pkg_defender.cli.main.cli.main",
                side_effect=RuntimeError("crash"),
            ),
            mock.patch(
                "pkg_defender.cli.main._handle_exception",
                return_value=EXIT_GENERAL_ERROR,
            ) as mock_handle,
        ):
            result = run_cli(["ignored"], standalone=False)

        assert result == EXIT_GENERAL_ERROR
        mock_handle.assert_called_once_with(mock.ANY, True)
