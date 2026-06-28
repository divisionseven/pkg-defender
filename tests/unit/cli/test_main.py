"""Tests for CLI main module - minimal."""

from unittest import mock

import pytest
from click.testing import CliRunner

from pkg_defender.cli.main import cli


class TestMainBasics:
    """Basic tests for main CLI."""

    def test_import(self) -> None:
        """CLI module is importable and cli is not None."""
        assert cli is not None

    def test_cli_name(self) -> None:
        """CLI group name is ``cli`` or ``pkgd``."""
        assert cli.name == "cli" or cli.name == "pkgd"


class TestHelpOutput:
    """Tests for CLI help output formatting."""

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["status", "--help"], id="status"),
            pytest.param(["health", "--help"], id="health"),
            pytest.param(["audit", "--help"], id="audit"),
            pytest.param(["setup", "--help"], id="setup"),
            pytest.param(["config", "--help"], id="config-group"),
            pytest.param(["daemon", "--help"], id="daemon-group"),
            pytest.param(["intel", "--help"], id="intel-group"),
            pytest.param(["config", "view", "--help"], id="config-view"),
            pytest.param(["daemon", "run", "--help"], id="daemon-run"),
            pytest.param(["intel", "sync", "--help"], id="intel-sync"),
        ],
    )
    def test_subcommand_help_ends_with_newline(self, runner: CliRunner, args: list[str]) -> None:
        """Subcommand help output must end with a trailing newline for POSIX compliance.

        Regression test for Item 9 fix: removed ``nl=False`` from ``click.echo()``
        in ``_command_format_help_with_leading_newline()`` (src/pkg_defender/cli/main.py:545).

        Root cause: ``click.echo(output, nl=False, color=...)`` suppressed the
        trailing newline in the patched ``format_help``, producing help output
        that violated POSIX expectations (missing final ``\\n``).

        This test FAILS before the fix (no trailing ``\\n``) and PASSES after.
        Parametrized over leaf, group, and nested subcommands for defense-in-depth.
        """
        result = runner.invoke(cli, args)
        assert result.exit_code == 0
        assert result.output.endswith("\n"), (
            f"Help output for {args} must end with newline, got: {repr(result.output[-30:])}"
        )

    def test_main_help_ends_with_newline(self, runner: CliRunner) -> None:
        """Main group help (``pkgd --help``) must also end with a trailing newline.

        Note: The main group was NOT affected by the ``nl=False`` bug (it uses
        Click's default ``print_help`` path, not the patched ``format_help``).
        This test verifies adjacent correctness for the primary entry point.
        """
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert result.output.endswith("\n"), f"Main help output must end with newline, got: {repr(result.output[-30:])}"

    def test_help_does_not_load_config(self, runner: CliRunner) -> None:
        """Verify --help does not trigger config loading.

        CliRunner does NOT modify ``sys.argv``, so the production guard
        (``"--help" in sys.argv``) would see the pytest command line instead
        of the simulated ``--help`` invocation. We mock ``sys.argv`` to match
        what a real ``pkgd --help`` shell invocation would pass.

        Rationale: The ``_custom_format_help`` guard checks ``sys.argv`` to
        determine whether ``--help`` is being shown, and only loads config
        when the banner would actually be displayed (not during ``--help``).
        """
        import sys

        with (
            mock.patch("pkg_defender.cli.common.load_config") as mock_load,
            mock.patch.object(sys, "argv", ["pkgd", "--help"]),
        ):
            result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        mock_load.assert_not_called()
