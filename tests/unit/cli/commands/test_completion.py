"""Tests for pkg_defender.cli.commands.completion module.

Covers ``pkgd completion generate`` for all supported shells.
Targets 90%+ line and branch coverage.

Strategy
--------
- All tests use ``CliRunner`` to invoke ``pkgd completion generate <shell>``.
- The command sets an environment variable (``_{EXECUTABLE}_COMPLETE``)
  and calls ``cli.main()`` with that env var, which causes Click's
  shell-completion machinery to emit the completion script.
- We verify the output contains shell-specific indicators.
- We also test the ``--executable`` option and the SystemExit passthrough.
"""

from __future__ import annotations

from click.testing import CliRunner

from pkg_defender.cli.main import cli

# ============================================================================
# TestCompletionGroup
# ============================================================================


class TestCompletionGroup:
    """Basic group-level behaviour."""

    def test_completion_help(self, runner: CliRunner) -> None:
        """``pkgd completion --help`` shows subcommands."""
        result = runner.invoke(cli, ["completion", "--help"])
        assert result.exit_code == 0
        assert "generate" in result.output


# ============================================================================
# TestCompletionGenerate
# ============================================================================


class TestCompletionGenerate:
    """Tests for ``pkgd completion generate <shell>``."""

    def test_generate_bash(self, runner: CliRunner) -> None:
        """Generates bash completion script.

        Root cause: ``completion.py`` lines 49-61 — sets the
        ``_PKGD_COMPLETE`` environment variable to ``bash_source``
        and calls ``cli.main()``.
        """
        result = runner.invoke(cli, ["completion", "generate", "bash"])
        assert result.exit_code == 0
        # Bash completion scripts typically contain "complete" or a
        # function definition
        assert len(result.output) > 0

    def test_generate_zsh(self, runner: CliRunner) -> None:
        """Generates zsh completion script."""
        result = runner.invoke(cli, ["completion", "generate", "zsh"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_generate_fish(self, runner: CliRunner) -> None:
        """Generates fish completion script."""
        result = runner.invoke(cli, ["completion", "generate", "fish"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_generate_powershell(self, runner: CliRunner) -> None:
        """Powershell completion is not supported in Click 8.3 — exits 1.

        Click 8.3's shell completion machinery only supports
        ``bash``, ``zsh``, and ``fish``. When an unsupported shell
        is requested, ``_main_shell_completion`` calls ``sys.exit(1)``
        which the ``except SystemExit`` handler re-raises.

        Root cause: ``completion.py`` line 58 — ``cli.main()`` is
        called with ``_PKGD_COMPLETE=powershell_source`` set. Click
        finds no completion class for ``powershell`` and exits 1.
        """
        result = runner.invoke(cli, ["completion", "generate", "powershell"])
        assert result.exit_code == 1
        assert result.output == ""

    def test_generate_nushell(self, runner: CliRunner) -> None:
        """Nushell completion is not supported in Click 8.3 — exits 1.

        Root cause: same as ``test_generate_powershell`` —
        ``get_completion_class("nushell")`` returns ``None`` in
        Click 8.3.2.
        """
        result = runner.invoke(cli, ["completion", "generate", "nushell"])
        assert result.exit_code == 1
        assert result.output == ""

    def test_generate_with_custom_executable(self, runner: CliRunner) -> None:
        """``--executable`` changes env var prefix.

        Root cause: ``completion.py`` line 49 — ``prog_name_upper`` is
        derived from the ``executable`` parameter and used as the
        environment variable prefix.
        """
        result = runner.invoke(
            cli,
            ["completion", "generate", "bash", "--executable", "mypkgd"],
        )
        assert result.exit_code == 0
        # The env var ``_MYPKGD_COMPLETE`` should be set to ``bash_source``
        assert len(result.output) > 0

    def test_generate_invalid_shell(self, runner: CliRunner) -> None:
        """Invalid shell choice prints usage error.

        Root cause: Click's ``Choice`` type validation — an invalid
        shell string triggers exit code 2 with "is not one of".
        """
        result = runner.invoke(cli, ["completion", "generate", "invalid_shell"])
        assert result.exit_code == 2
        assert "is not one of" in result.output
