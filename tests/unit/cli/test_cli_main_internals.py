"""Tests for internal utility functions and code paths in ``cli/main.py``.

Covers ``_get_first_line``, ``_strip_ansi``, ``_format_epilog_preserve_newlines``,
``_command_format_epilog_preserve_newlines``, ``_expand_subcommands``, the
``config.output.color`` branching logic, and the outdated-tools inline output.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import click
import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import (
    _expand_subcommands,
    _format_epilog_preserve_newlines,
    _get_first_line,
    _strip_ansi,
    cli,
)
from pkg_defender.config.settings import PKGDConfig

pytestmark = pytest.mark.unit


class TestGetFirstLine:
    """Tests for ``_get_first_line`` — first-line extraction from docstrings.

    A pure utility function used by ``GroupedHelpFormatter`` to display
    short help text for each command.
    """

    def test_returns_first_line_when_multiline_docstring(self) -> None:
        """Multiline docstring returns only the first line."""
        result = _get_first_line("Line one\nLine two")
        assert result == "Line one"

    def test_returns_empty_string_when_docstring_none(self) -> None:
        """``None`` docstring returns empty string without raising."""
        result = _get_first_line(None)
        assert result == ""

    def test_strips_whitespace_from_first_line(self) -> None:
        """Leading and trailing whitespace is stripped from the first line."""
        result = _get_first_line("   Hello world   \nNext line")
        assert result == "Hello world"


class TestStripAnsi:
    """Tests for ``_strip_ansi`` — ANSI escape sequence removal.

    A pure utility function used by the epilog formatter to strip ANSI
    codes when ``--no-color`` or ``NO_COLOR`` is active.
    """

    def test_returns_text_unchanged_when_no_ansi(self) -> None:
        """Plain text without ANSI codes is returned unchanged."""
        result = _strip_ansi("plain text")
        assert result == "plain text"

    def test_strips_ansi_escape_sequences(self) -> None:
        """ANSI escape sequences are removed, leaving the visible text."""
        result = _strip_ansi("\x1b[31mred\x1b[0m")
        assert result == "red"

    def test_returns_empty_string_when_empty(self) -> None:
        """Empty string returns empty string without raising."""
        result = _strip_ansi("")
        assert result == ""


class TestFormatEpilogPreserveNewlines:
    """Tests for ``_format_epilog_preserve_newlines`` (group-level).

    Verifies that multi-line epilogs preserve their newline structure
    and that the function returns early when ``epilog is None``.
    """

    def test_preserves_newlines_in_epilog(self) -> None:
        """Multi-line epilog writes each line separately with newlines between."""
        mock_group = mock.MagicMock(spec=click.Group)
        mock_group.epilog = "Line 1\nLine 2"
        mock_ctx = mock.MagicMock()
        mock_formatter = mock.MagicMock()

        _format_epilog_preserve_newlines(mock_group, mock_ctx, mock_formatter)

        calls = mock_formatter.write.call_args_list
        assert mock.call("Line 1") in calls, "Expected write('Line 1')"
        assert mock.call("\n") in calls, "Expected write('\\n') between lines"
        assert mock.call("Line 2") in calls, "Expected write('Line 2')"

    def test_returns_early_when_epilog_none(self) -> None:
        """When epilog is ``None``, no formatter methods are called."""
        mock_group = mock.MagicMock(spec=click.Group)
        mock_group.epilog = None
        mock_ctx = mock.MagicMock()
        mock_formatter = mock.MagicMock()

        _format_epilog_preserve_newlines(mock_group, mock_ctx, mock_formatter)

        mock_formatter.indentation.assert_not_called()
        mock_formatter.write.assert_not_called()


class TestCommandFormatEpilogPreserveNewlines:
    """Tests for ``_command_format_epilog_preserve_newlines`` (command-level).

    Verifies that when color is disabled, ANSI escape sequences in the
    epilog are stripped before writing. Uses the non-monkeypatched
    function from ``main``, which accesses ``should_use_color`` at call
    time.
    """

    def test_strips_ansi_when_color_disabled(self) -> None:
        """When ``should_use_color()`` returns ``False``, ANSI codes are stripped."""
        with mock.patch("pkg_defender.cli.main.should_use_color", return_value=False):
            mock_cmd = mock.MagicMock(spec=click.Command)
            mock_cmd.epilog = "\x1b[31mWarning\x1b[0m"
            mock_ctx = mock.MagicMock()
            mock_formatter = mock.MagicMock()

            # Import the command-level function (not the group-level one)
            from pkg_defender.cli.main import _command_format_epilog_preserve_newlines

            _command_format_epilog_preserve_newlines(mock_cmd, mock_ctx, mock_formatter)

            # Verify the written text does NOT contain ANSI codes
            for call_args, _ in mock_formatter.write.call_args_list:
                text = str(call_args[0]) if call_args else ""
                assert "\x1b" not in text, f"ANSI escape sequence found in written text: {text!r}"
            # Verify the visible content was preserved
            found_warning = any("Warning" in str(args[0]) for args, _ in mock_formatter.write.call_args_list if args)
            assert found_warning, "Expected 'Warning' text to be preserved"


class TestColorConfigMode:
    """Tests for the ``config.output.color`` branching logic in ``cli()``.

    Verifies that when config disables color output, the three no-color
    initializers are called; when config enables color, they are not;
    and the ``--no-color`` CLI flag correctly overrides ``config.output.color``.
    """

    def test_calls_no_color_functions_when_config_color_false(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        isolated_env: dict[str, Path],
    ) -> None:
        """``config.output.color=False`` triggers no-color functions (without ``NO_COLOR``)."""
        monkeypatch.delenv("NO_COLOR", raising=False)

        config = PKGDConfig()
        config.output.color = False

        with (
            mock.patch("pkg_defender.cli.main.load_config", return_value=config),
            mock.patch("pkg_defender.cli.common.set_console_no_color") as mock_set_console,
            mock.patch("pkg_defender.display.set_no_color") as mock_set_display,
            mock.patch("pkg_defender.cli._progress.set_progress_no_color") as mock_set_progress,
        ):
            result = runner.invoke(cli, ["status"])

        assert result.exit_code == 0
        mock_set_console.assert_called_once()
        mock_set_display.assert_called_once()
        mock_set_progress.assert_called_once()

    def test_skips_no_color_functions_when_config_color_true(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``config.output.color=True`` skips no-color functions."""
        config = PKGDConfig()
        config.output.color = True

        with (
            mock.patch("pkg_defender.cli.main.load_config", return_value=config),
            mock.patch("pkg_defender.cli.common.set_console_no_color") as mock_set_console,
            mock.patch("pkg_defender.display.set_no_color") as mock_set_display,
            mock.patch("pkg_defender.cli._progress.set_progress_no_color") as mock_set_progress,
        ):
            result = runner.invoke(cli, ["status"])

        assert result.exit_code == 0
        mock_set_console.assert_not_called()
        mock_set_display.assert_not_called()
        mock_set_progress.assert_not_called()

    def test_respects_no_color_flag_over_config_color(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``--no-color`` CLI flag takes precedence over ``config.output.color=True``."""
        config = PKGDConfig()
        config.output.color = True

        with (
            mock.patch("pkg_defender.cli.main.load_config", return_value=config),
            mock.patch("pkg_defender.cli.common.set_console_no_color") as mock_set_console,
            mock.patch("pkg_defender.display.set_no_color") as mock_set_display,
            mock.patch("pkg_defender.cli._progress.set_progress_no_color") as mock_set_progress,
        ):
            result = runner.invoke(cli, ["--no-color", "status"])

        assert result.exit_code == 0
        mock_set_console.assert_called_once()
        mock_set_display.assert_called_once()
        mock_set_progress.assert_called_once()


class TestOutdatedToolsPrinting:
    """Tests for the outdated-tools printing logic in ``cli()``.

    Verifies that when ``-v`` is active and ``check_outdated_tools()``
    returns results, a warning is printed; when ``--quiet`` is set, the
    warning is suppressed; and when no tools are outdated, nothing is
    printed.
    """

    def test_prints_outdated_tools_when_verbose(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``-v`` triggers outdated-tools check and prints results."""
        outdated_tools = [
            {"tool": "pip", "installed": "20.0", "minimum": "21.0"},
        ]

        with (
            mock.patch(
                "pkg_defender.cli._dependency_check.check_outdated_tools",
                return_value=outdated_tools,
            ),
            mock.patch("pkg_defender.cli.main.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["-v", "status"])

        assert result.exit_code == 0
        found = any(
            "pip" in str(args) and "20.0" in str(args) and "21.0" in str(args) for args, _ in mock_print.call_args_list
        )
        assert found, "Expected console.print to contain outdated tool details"

    def test_does_not_print_outdated_tools_when_quiet(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """``--quiet`` suppresses outdated-tools warnings even when ``-v`` is set."""
        outdated_tools = [
            {"tool": "pip", "installed": "20.0", "minimum": "21.0"},
        ]

        with (
            mock.patch(
                "pkg_defender.cli._dependency_check.check_outdated_tools",
                return_value=outdated_tools,
            ),
            mock.patch("pkg_defender.cli.main.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["--quiet", "-v", "status"])

        assert result.exit_code == 0
        mock_print.assert_not_called()

    def test_does_not_print_outdated_tools_when_none_outdated(
        self,
        runner: CliRunner,
        isolated_env: dict[str, Path],
    ) -> None:
        """When no tools are outdated, no warning is printed."""
        with (
            mock.patch(
                "pkg_defender.cli._dependency_check.check_outdated_tools",
                return_value=[],
            ),
            mock.patch("pkg_defender.cli.main.console.print") as mock_print,
        ):
            result = runner.invoke(cli, ["-v", "status"])

        assert result.exit_code == 0
        # Other console.print calls (from command output) are acceptable;
        # just ensure no outdated-tool-specific text appears
        for args, _ in mock_print.call_args_list:
            text = str(args)
            assert "Warning: Outdated tools detected" not in text, (
                "Outdated tools warning should not appear when none are outdated"
            )


class TestExpandSubcommands:
    """Tests for ``_expand_subcommands`` — Click group subcommand expansion.

    Verifies that subcommands of a ``click.Group`` are expanded with
    ``"{group} {sub}"`` keys in the returned dict.
    """

    def test_expands_group_subcommands(self) -> None:
        """``click.Group`` commands are expanded with ``"{group} {sub}"`` keys."""
        mock_sub1 = mock.MagicMock(spec=click.Command)
        mock_sub1.hidden = False
        mock_sub2 = mock.MagicMock(spec=click.Command)
        mock_sub2.hidden = False

        mock_group = mock.MagicMock(spec=click.Group)
        mock_group.list_commands.return_value = ["sub1", "sub2"]
        mock_group.get_command.side_effect = lambda ctx, name: {
            "sub1": mock_sub1,
            "sub2": mock_sub2,
        }[name]

        mock_simple = mock.MagicMock(spec=click.Command)

        mock_ctx = mock.MagicMock()
        commands: dict[str, click.Command] = {
            "group": mock_group,
            "simple": mock_simple,
        }

        result = _expand_subcommands(commands, mock_ctx)

        assert "group" in result
        assert "group sub1" in result
        assert "group sub2" in result
        assert "simple" in result
        assert result["group sub1"] is mock_sub1
        assert result["group sub2"] is mock_sub2
