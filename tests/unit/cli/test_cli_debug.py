"""Tests for --debug flag and programmatic entry point."""

import logging
import os
from unittest.mock import patch

import pytest

from pkg_defender.cli._exit_codes import EXIT_SUCCESS
from pkg_defender.cli.main import cli, run_cli


class TestRunCli:
    """Test run_cli() programmatic entry point."""

    def test_run_cli_returns_int(self) -> None:
        """Test run_cli returns integer exit code."""
        result = run_cli(["--help"], standalone=False)
        assert isinstance(result, int)

    def test_help_returns_zero(self) -> None:
        """Test --help returns 0."""
        result = run_cli(["--help"], standalone=False)
        assert result == EXIT_SUCCESS

    def test_standalone_mode_exits(self) -> None:
        """Test run_cli with standalone=True calls sys.exit()."""
        with pytest.raises(SystemExit):
            run_cli(["--help"], standalone=True)

    def test_returns_correct_exit_code(self) -> None:
        """Test run_cli returns the correct exit code."""
        # --help should return 0
        result = run_cli(["--help"], standalone=False)
        assert result == 0


class TestDebugFlag:
    """Test --debug flag behavior."""

    def test_debug_flag_sets_env_var(self) -> None:
        """Test --debug sets PKGD_DEBUG environment variable."""
        with patch.dict(os.environ, {}, clear=True):
            run_cli(["--debug", "status"], standalone=False)
            assert os.environ.get("PKGD_DEBUG") == "1"

    def test_debug_flag_accepted_by_cli(self) -> None:
        """Test --debug flag is accepted by CLI."""
        # Run without SystemExit to verify flag parsing works
        result = run_cli(["--help", "--debug"], standalone=False)
        assert result == 0

    def test_debug_short_flag(self) -> None:
        """Test -d short flag is accepted."""
        result = run_cli(["--help", "-d"], standalone=False)
        assert result == 0


class TestVerbosityLogLevels:
    """Test that verbosity flags correctly set Python logging levels.

    All handler-level checks use logging.getLogger() (root logger) because
    setup_logging() attaches handlers to the root logger, not named loggers.
    """

    def test_vv_sets_debug_logger_level(self) -> None:
        """-vv should set console handler to DEBUG."""
        import tempfile
        from pathlib import Path

        from pkg_defender.cli.main import setup_logging

        data_dir = Path(tempfile.mkdtemp())
        setup_logging(verbosity=2, data_dir=data_dir)
        root_logger = logging.getLogger()
        handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert handler.level == logging.DEBUG

    def test_v_sets_info_logger_level(self) -> None:
        """-v should set console handler to INFO."""
        import tempfile
        from pathlib import Path

        from pkg_defender.cli.main import setup_logging

        data_dir = Path(tempfile.mkdtemp())
        setup_logging(verbosity=1, data_dir=data_dir)
        root_logger = logging.getLogger()
        handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert handler.level == logging.INFO

    def test_default_sets_error_logger_level(self) -> None:
        """No verbosity flag should set console handler to ERROR."""
        import tempfile
        from pathlib import Path

        from pkg_defender.cli.main import setup_logging

        data_dir = Path(tempfile.mkdtemp())
        setup_logging(verbosity=0, data_dir=data_dir)
        root_logger = logging.getLogger()
        handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert handler.level == logging.ERROR


class TestDebugFlagBehavior:
    """Test --debug flag behavior beyond exit codes."""

    def test_debug_flag_does_not_set_debug_level(self, runner) -> None:
        """--debug alone should NOT set DEBUG log level."""
        result = runner.invoke(cli, ["--debug", "status"])
        assert result.exit_code == 0
        # Verify the console handler is NOT at DEBUG level.
        # Handlers are on root logger (see main.py:51-74).
        root_logger = logging.getLogger()
        handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert handler.level != logging.DEBUG, "--debug should not set DEBUG level"

    def test_vv_with_debug_sets_debug_level(self, runner) -> None:
        """-vv (with or without --debug) should set DEBUG level."""
        result = runner.invoke(cli, ["-vv", "status"])
        assert result.exit_code == 0
        root_logger = logging.getLogger()
        handler = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)][0]
        assert handler.level == logging.DEBUG

    def test_debug_flag_still_sets_env_var(self) -> None:
        """--debug must still set PKGD_DEBUG=1 for traceback behavior.

        Uses --debug with a real subcommand (status), NOT --help, because
        --help causes cli() to exit at line 331 before PKGD_DEBUG is set at line 390.
        See main.py:390-391.
        """
        with patch.dict(os.environ, {}, clear=True):
            run_cli(["--debug", "status"], standalone=False)
            assert os.environ.get("PKGD_DEBUG") == "1"
