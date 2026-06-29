"""Tests for the ``pkgd hooks`` command (shell function generation)."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from pkg_defender.cli.main import cli


def test_hooks_command_exists(runner: CliRunner) -> None:
    """Smoke test: ``pkgd hooks`` exits successfully."""
    result = runner.invoke(cli, ["hooks"])
    # The command should run without errors regardless of the environment.
    assert result.exit_code == 0, f"pkgd hooks failed with exit code {result.exit_code}: {result.output}"
    assert result.output.strip() != "", "pkgd hooks produced no output"


def test_hooks_help_shows_description(runner: CliRunner) -> None:
    """``--help`` shows function-generation help text (not stub text)."""
    result = runner.invoke(cli, ["hooks", "--help"])
    assert result.exit_code == 0, f"pkgd hooks --help failed: {result.output}"
    output = result.output.lower()

    # Must not contain the old stub language
    assert "future release" not in output, f"Should not contain old stub text: {result.output}"

    # Must describe shell function generation
    assert "function" in output, f"Should describe shell function generation: {result.output}"
    assert "shell" in output, f"Should mention shell: {result.output}"


def test_hooks_help_shows_shell_option(runner: CliRunner) -> None:
    """``--help`` mentions the ``--shell`` option."""
    result = runner.invoke(cli, ["hooks", "--help"])
    assert result.exit_code == 0, f"pkgd hooks --help failed: {result.output}"

    assert "--shell" in result.output, f"Should show --shell option: {result.output}"


def test_hooks_detects_shells_and_managers(runner: CliRunner) -> None:
    """Output contains 'Shell Detection' and 'Package Manager Detection'."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="zsh"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed") as mock_installed,
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):
        # Only bash and zsh are installed
        mock_installed.side_effect = lambda s: s in ("bash", "zsh")

        # Only pip and npm detected via subprocess (others via which return None)
        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] in ("pip", "npm") else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0, f"pkgd hooks failed: {result.output}"
        assert "Shell Detection" in result.output
        assert "Package Manager Detection" in result.output
        assert "pip() {" in result.output
        assert "npm() {" in result.output


def test_hooks_shows_aliases_for_detected_managers(runner: CliRunner) -> None:
    """Output contains shell function definitions for each detected manager."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] in ("brew", "cargo", "gem") else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        # Each detected manager should have a function definition
        assert "brew() {" in result.output
        assert "cargo() {" in result.output
        assert "gem() {" in result.output
        # Each function should have both pkgd and command branches
        assert "pkgd brew" in result.output
        assert "command brew" in result.output
        # Non-detected managers should NOT appear
        assert "pip() {" not in result.output


def test_hooks_shows_rc_instructions(runner: CliRunner) -> None:
    """Output contains RC file references and source commands."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="zsh"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed") as mock_installed,
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):
        mock_installed.side_effect = lambda s: s in ("bash", "zsh")

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        assert "~/.zshrc" in result.output
        assert "source ~/.zshrc" in result.output
        assert "~/.bashrc" in result.output
        assert "source ~/.bashrc" in result.output


def test_hooks_shell_option_override(runner: CliRunner) -> None:
    """``--shell fish`` shows fish-specific function syntax."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "fish"])

        assert result.exit_code == 0
        # Fish uses: function pip ... end  (no = sign)
        assert "function pip" in result.output
        assert "pkgd pip" in result.output
        # Bash/zsh syntax should NOT appear
        assert "pip() {" not in result.output


def test_hooks_shell_option_invalid(runner: CliRunner) -> None:
    """``--shell invalid`` raises BadParameter (exit code 2)."""
    result = runner.invoke(cli, ["hooks", "--shell", "invalid"])
    assert result.exit_code == 2, f"Expected exit code 2 for invalid shell, got {result.exit_code}: {result.output}"


def test_hooks_fish_syntax(runner: CliRunner) -> None:
    """Fish functions use the correct format (switch/case with ``command`` bypass)."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="fish"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] in ("pip", "npm", "brew") else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "fish"])

        assert result.exit_code == 0
        assert "function pip" in result.output
        assert "function npm" in result.output
        assert "function brew" in result.output
        assert "pkgd pip" in result.output
        assert "pkgd npm" in result.output
        assert "pkgd brew" in result.output
        assert "command pip" in result.output
        assert "command npm" in result.output
        assert "command brew" in result.output


def test_hooks_powershell_syntax(runner: CliRunner) -> None:
    """Powershell functions use conditional logic with ``-in`` and ``Get-Command`` bypass."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="powershell"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "npm" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "powershell"])

        assert result.exit_code == 0
        assert "function npm {" in result.output
        assert "-in @" in result.output
        assert "Get-Command npm -CommandType Application" in result.output
        assert "@args" in result.output


def test_hooks_nushell_syntax(runner: CliRunner) -> None:
    """Nushell functions use ``def`` with ``^`` bypass and ``match`` branching."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="nushell"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "cargo" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "nushell"])

        assert result.exit_code == 0
        assert "def cargo [" in result.output
        assert "^pkgd" in result.output
        assert "^cargo" in result.output


def test_hooks_no_managers_detected(runner: CliRunner) -> None:
    """Graceful handling when no package managers are detected."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 1  # All manager detections fail
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        assert "No supported package managers detected" in result.output


def test_hooks_no_shells_detected(runner: CliRunner) -> None:
    """Graceful handling when no shells are detected."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="zsh"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=False),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        # Even with no shells from is_shell_installed, detect_shell provides one
        assert "Shell Detection" in result.output
        assert "zsh" in result.output


def test_hooks_shell_option_bash_syntax(runner: CliRunner) -> None:
    """``--shell bash`` produces bash-style functions with case/``command``."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="zsh"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "bash"])

        assert result.exit_code == 0
        assert "pip() {" in result.output
        assert "pkgd pip" in result.output
        assert "command pip" in result.output
        # Should NOT contain zsh RC file reference
        assert "~/.zshrc" not in result.output
        assert "~/.bashrc" in result.output


def test_hooks_output_exit_code_success(runner: CliRunner) -> None:
    """Happy path exits with code 0."""
    result = runner.invoke(cli, ["hooks"])
    assert result.exit_code == 0


def test_hooks_detection_falls_back_to_which_when_subprocess_fails(
    runner: CliRunner,
) -> None:
    """Managers without detection commands are checked via ``which()``."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which") as mock_which,
    ):
        # Only subprocess detections all fail
        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        # Only pip3 is found via which
        mock_which.side_effect = lambda m: f"/usr/bin/{m}" if m == "pip3" else None

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        # pip3 should be detected via which, not subprocess
        assert "pip3" in result.output


def test_hooks_shell_option_unsupported_choice(runner: CliRunner) -> None:
    """Unsupported shell choice raises click.BadParameter."""
    result = runner.invoke(cli, ["hooks", "--shell", "tcsh"])
    assert result.exit_code == 2
    assert "invalid" in result.output.lower() or "not one of" in result.output.lower()


def test_hooks_emits_aliases_for_all_shell_syntaxes(
    runner: CliRunner,
) -> None:
    """Each supported shell uses the correct function format."""
    test_cases: list[tuple[str, str, str, str]] = [
        ("bash", "pip() {", "pkgd pip", "command pip"),
        ("zsh", "pip() {", "pkgd pip", "command pip"),
        ("fish", "function pip", "pkgd pip", "command pip"),
        ("powershell", "function pip {", "pkgd pip", "Get-Command pip"),
        ("nushell", "def pip [", "^pkgd", "^pip"),
    ]

    for shell, func_pattern, pkgd_pattern, bypass_pattern in test_cases:
        with (
            patch("pkg_defender.cli.commands.hooks.detect_shell", return_value=shell),
            patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
            patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
            patch("pkg_defender.cli.commands.hooks.which", return_value=None),
        ):

            def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
                class _Result:
                    returncode = 0 if cmd[0] == "pip" else 1
                    stdout = ""
                    stderr = ""

                return _Result()

            mock_run.side_effect = _fake_subprocess_run

            result = runner.invoke(cli, ["hooks", "--shell", shell])
            assert result.exit_code == 0, f"Shell {shell} failed: {result.output}"
            assert func_pattern in result.output, (
                f"Shell {shell}: expected function pattern {func_pattern!r} in output, got: {result.output}"
            )
            assert pkgd_pattern in result.output, (
                f"Shell {shell}: expected pkgd reference {pkgd_pattern!r} in output, got: {result.output}"
            )
            assert bypass_pattern in result.output, (
                f"Shell {shell}: expected bypass pattern {bypass_pattern!r} in output, got: {result.output}"
            )


def test_hooks_emits_aliases_for_all_registered_managers(
    runner: CliRunner,
) -> None:
    """Every executable in UNIFIED_MANAGER_REGISTRY generates a valid function.

    This is a parameterised check across all 19 registered managers.  If a new
    manager is added to the registry but the hooks command is not updated to
    handle it, this test will fail.
    """
    # Use the exact same source of truth that hooks.py uses
    from pkg_defender.cli._manager_constants import (
        MANAGER_DETECTION_COMMANDS as HOOK_DETECT_CMDS,
    )
    from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY

    all_managers: list[str] = list(UNIFIED_MANAGER_REGISTRY.keys())

    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which") as mock_which,
    ):
        # Managers with a detection command succeed via subprocess.
        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] in HOOK_DETECT_CMDS else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        # Managers WITHOUT a detection command are found via which().
        def _fake_which(mgr: str) -> str | None:
            if mgr not in HOOK_DETECT_CMDS:
                return f"/usr/bin/{mgr}"
            return None

        mock_which.side_effect = _fake_which

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0, f"hooks failed: {result.output}"

        for mgr in all_managers:
            # Each manager should have a bash function definition
            assert f"{mgr}() {{" in result.output, (
                f"Missing function definition for registered manager {mgr!r}. Expected '{mgr}() {{' in output."
            )


def test_hooks_current_shell_marker(runner: CliRunner) -> None:
    """Detection summary shows ``(current)`` next to the active shell."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="zsh"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed") as mock_installed,
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):
        mock_installed.side_effect = lambda s: s in ("bash", "zsh")

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks"])

        assert result.exit_code == 0
        # The shell returned by detect_shell should have "(current)" marker
        assert "(current)" in result.output, f"Expected '(current)' marker in detection output: {result.output}"


def test_hooks_extracts_dangerous_commands() -> None:
    """_get_dangerous_commands_for_manager returns correct commands for brew and uv."""
    from pkg_defender.cli.commands.hooks import _get_dangerous_commands_for_manager

    # Brew: single-word only
    single, multi = _get_dangerous_commands_for_manager("brew")
    assert isinstance(single, list)
    assert isinstance(multi, list)
    assert "install" in single
    assert "upgrade" in single
    assert multi == []

    # uv: both single and multi-word
    single, multi = _get_dangerous_commands_for_manager("uv")
    assert "add" in single
    assert "pip_install" in multi
    assert "pip_sync" in multi
    assert "tool_install" in multi
    assert "tool_upgrade" in multi

    # Unknown manager: empty
    single, multi = _get_dangerous_commands_for_manager("nonexistent")
    assert single == []
    assert multi == []


def test_hooks_empty_managers_no_error() -> None:
    """Zero dangerous subcommands -> unconditional pass-through (no crash)."""
    from pkg_defender.cli.commands.hooks import _generate_shell_function

    result = _generate_shell_function("bash", "pip", [], [])
    assert "pkgd" not in result, "Pass-through should not reference pkgd"
    assert "command pip" in result, "Pass-through should call command pip"
    assert "case" not in result, "Pass-through should not have case statement"


def test_hooks_generated_function_contains_both_branches() -> None:
    """Generated bash function has both pkgd (dangerous) and command (safe) branches."""
    from pkg_defender.cli.commands.hooks import (
        _generate_shell_function,
        _get_dangerous_commands_for_manager,
    )

    single, multi = _get_dangerous_commands_for_manager("brew")
    func = _generate_shell_function("bash", "brew", single, multi)

    assert "pkgd brew" in func
    assert "command brew" in func


def test_hooks_generates_function_multiword() -> None:
    """UV multi-word template renders correctly across all shell formats."""
    from pkg_defender.cli.commands.hooks import (
        _generate_shell_function,
        _get_dangerous_commands_for_manager,
    )

    single, multi = _get_dangerous_commands_for_manager("uv")

    assert len(multi) > 0, "UV should have multi-word dangerous commands"

    for shell in ("bash", "zsh", "fish", "powershell", "nushell"):
        func = _generate_shell_function(shell, "uv", single, multi)
        assert "pkgd uv" in func, f"Shell {shell}: should contain pkgd uv"
        assert "pip_install" in func, f"Shell {shell}: should contain pip_install pattern"


def test_hooks_targeted_shell_marker(runner: CliRunner) -> None:
    """Detection summary shows ``(targeted)`` when ``--shell`` is used."""
    with (
        patch("pkg_defender.cli.commands.hooks.detect_shell", return_value="bash"),
        patch("pkg_defender.cli.commands.hooks.is_shell_installed", return_value=True),
        patch("pkg_defender.cli.commands.hooks.subprocess.run") as mock_run,
        patch("pkg_defender.cli.commands.hooks.which", return_value=None),
    ):

        def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> object:
            class _Result:
                returncode = 0 if cmd[0] == "pip" else 1
                stdout = ""
                stderr = ""

            return _Result()

        mock_run.side_effect = _fake_subprocess_run

        result = runner.invoke(cli, ["hooks", "--shell", "nushell"])

        assert result.exit_code == 0
        # The --shell target should have "(targeted)" marker
        assert "(targeted)" in result.output, f"Expected '(targeted)' marker in detection output: {result.output}"
        # Non-targeted shells should NOT have "(targeted)"
        assert "(current)" not in result.output, "Should not have '(current)' when --shell is used"
