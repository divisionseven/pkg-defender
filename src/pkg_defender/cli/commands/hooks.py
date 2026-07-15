# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd hooks command — shell function generation.

Provides the ``pkgd hooks`` subcommand which detects installed shells and
package managers on the user's system, then prints shell-specific wrapper
functions that can be copied into the user's RC file.
"""

from __future__ import annotations

import subprocess
from shutil import which

import click

from pkg_defender.cli._manager_constants import MANAGER_DETECTION_COMMANDS
from pkg_defender.cli.common import console
from pkg_defender.cli.main import cli
from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY
from pkg_defender.shells.detect import SUPPORTED_SHELLS, detect_shell, is_shell_installed

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_EXECUTABLES: tuple[str, ...] = tuple(UNIFIED_MANAGER_REGISTRY.keys())
"""All CLI-addressable manager names that can be aliased."""

_SUBCMD_SEPARATORS: dict[str, str] = {
    "bash": "|",
    "zsh": "|",
    "fish": " ",
    "nushell": " | ",
}
"""Shell-specific separators for case/switch pattern lists."""

SHELL_FUNCTION_TEMPLATES: dict[str, dict[str, str]] = {
    "bash": {
        "function_template": """\
{manager}() {{
    case "$1" in
        {subcmds})
            pkgd {manager} "$@"
            ;;
        *)
            command {manager} "$@"
            ;;
    esac
}}""",
        "multi_word_template": """\
{manager}() {{
    _key="$1"
    [ $# -ge 2 ] && _key="$1_$2"
    case "$_key" in
        {subcmds})
            pkgd {manager} "$@"
            ;;
        *)
            command {manager} "$@"
            ;;
    esac
}}""",
        "pass_through": """\
{manager}() {{
    command {manager} "$@"
}}""",
        "rc_file": "~/.bashrc",
        "source_cmd": "source ~/.bashrc",
    },
    "zsh": {
        "function_template": """\
{manager}() {{
    case "$1" in
        {subcmds})
            pkgd {manager} "$@"
            ;;
        *)
            command {manager} "$@"
            ;;
    esac
}}""",
        "multi_word_template": """\
{manager}() {{
    _key="$1"
    [ $# -ge 2 ] && _key="$1_$2"
    case "$_key" in
        {subcmds})
            pkgd {manager} "$@"
            ;;
        *)
            command {manager} "$@"
            ;;
    esac
}}""",
        "pass_through": """\
{manager}() {{
    command {manager} "$@"
}}""",
        "rc_file": "~/.zshrc",
        "source_cmd": "source ~/.zshrc",
    },
    "fish": {
        "function_template": """\
function {manager}
    switch $argv[1]
        case {subcmds}
            pkgd {manager} $argv
        case '*'
            command {manager} $argv
    end
end""",
        "multi_word_template": """\
function {manager}
    set -l key "$argv[1]"
    if test (count $argv) -ge 2
        set key "$argv[1]_$argv[2]"
    end
    switch $key
        case {subcmds}
            pkgd {manager} $argv
        case '*'
            command {manager} $argv
    end
end""",
        "pass_through": """\
function {manager}
    command {manager} $argv
end""",
        "rc_file": "~/.config/fish/config.fish",
        "source_cmd": "source ~/.config/fish/config.fish",
    },
    "powershell": {
        "function_template": """\
function {manager} {{
    if ($args[0] -in @({subcmds})) {{
        & pkgd {manager} @args
    }} else {{
        & (Get-Command {manager} -CommandType Application) @args
    }}
}}""",
        "multi_word_template": """\
function {manager} {{
    $key = if ($args.Count -ge 2) {{ "$($args[0])_$($args[1])" }} else {{ $args[0] }}
    if ($key -in @({subcmds})) {{
        & pkgd {manager} @args
    }} else {{
        & (Get-Command {manager} -CommandType Application) @args
    }}
}}""",
        "pass_through": """\
function {manager} {{
    & (Get-Command {manager} -CommandType Application) @args
}}""",
        "rc_file": "$PROFILE",
        "source_cmd": ". $PROFILE",
    },
    "nushell": {
        "function_template": """\
def {manager} [...args: string] {{
    if (($args | length) == 0) {{
        ^{manager}
    }} else if ($args.0 in [{subcmds}]) {{
        ^pkgd {manager} ...$args
    }} else {{
        ^{manager} ...$args
    }}
}}""",
        "multi_word_template": """\
def {manager} [...args: string] {{
    if (($args | length) == 0) {{
        ^{manager}
    }} else {{
        let key = if ($args | length) >= 2 {{
            $"($args.0)_($args.1)"
        }} else {{
            $args.0
        }}
        if ($key in [{subcmds}]) {{
            ^pkgd {manager} ...$args
        }} else {{
            ^{manager} ...$args
        }}
    }}
}}""",
        "pass_through": """\
def {manager} [...args: string] {{
    ^{manager} ...$args
}}""",
        "rc_file": "~/.config/nushell/config.nu",
        "source_cmd": "source ~/.config/nushell/config.nu",
    },
}
"""Shell function templates, RC file paths, and source commands per shell.

Each shell has three templates:
- function_template: For managers with only single-word dangerous subcommands.
- multi_word_template: For managers with multi-word dangerous subcommands (only uv).
- pass_through: For managers with zero dangerous subcommands."""


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _detect_installed_shells(target_shell: str | None) -> list[str]:
    """Detect installed shells or return a specific target shell.

    If *target_shell* is provided (from the ``--shell`` flag), returns a
    single-element list with that shell.  Otherwise iterates over all
    :data:`SUPPORTED_SHELLS` and checks each via :func:`is_shell_installed`.
    The currently-active shell (from :func:`detect_shell`) is always included
    even if :func:`is_shell_installed` returns ``False`` for it (the current
    shell is, by definition, installed).

    Args:
        target_shell: Optional shell name to target (from ``--shell`` flag).

    Returns:
        List of installed (or targeted) shell names.
    """
    if target_shell is not None:
        return [target_shell]

    shells: list[str] = []
    for shell in SUPPORTED_SHELLS:
        if is_shell_installed(shell):
            shells.append(shell)

    current = detect_shell()
    if current not in shells:
        shells.append(current)

    return shells


def _detect_installed_managers() -> list[str]:
    """Detect which package managers are installed on the system.

    For every entry in :data:`SUPPORTED_EXECUTABLES`:
    * If the manager has a detection command in
      :data:`MANAGER_DETECTION_COMMANDS`, it is run via :func:`subprocess.run`.
    * Otherwise (``uv``, ``yarn``, ``pnpm``, ``pip3``) the manager is checked
      via :func:`shutil.which`.

    Returns:
        List of detected package manager names.
    """
    detected: list[str] = []

    for manager in SUPPORTED_EXECUTABLES:
        if manager in MANAGER_DETECTION_COMMANDS:
            cmd = MANAGER_DETECTION_COMMANDS[manager]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                if proc.returncode == 0:
                    detected.append(manager)
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                continue
        else:
            if which(manager) is not None:
                detected.append(manager)

    return detected


# ---------------------------------------------------------------------------
# Shell function generation helpers
# ---------------------------------------------------------------------------


def _get_dangerous_commands_for_manager(
    manager_name: str,
) -> tuple[list[str], list[str]]:
    """Get dangerous single-word and multi-word subcommands for a manager.

    Args:
        manager_name: The CLI manager name (e.g., "pip", "brew", "uv").

    Returns:
        Tuple of (single_word_dangerous, multi_word_dangerous) where each
        element is a sorted list of dangerous subcommands. Multi-word entries
        use underscore joining (e.g., "pip_install").
    """
    from pkg_defender.models.command import DANGEROUS_INTENTS

    adapter_cls = UNIFIED_MANAGER_REGISTRY.get(manager_name)
    if adapter_cls is None:
        return [], []

    # Intent map may be class-level or instance-level
    intent_map: dict[str, object] = getattr(adapter_cls, "COMMAND_INTENT_MAP", {})

    single_word: list[str] = []
    multi_word: list[str] = []

    for subcmd, intent in intent_map.items():
        if intent not in DANGEROUS_INTENTS:
            continue
        if " " in subcmd:
            # Multi-word: "pip install" -> "pip_install" for shell matching
            multi_word.append(subcmd.replace(" ", "_"))
        else:
            single_word.append(subcmd)

    single_word.sort()
    multi_word.sort()
    return single_word, multi_word


def _pass_through_function(shell: str, manager: str) -> str:
    """Generate an unconditional pass-through function for a manager.

    Used when a manager has zero dangerous subcommands - the function just
    forwards everything directly to the real binary with no interception.

    Args:
        shell: Shell name (e.g., "bash", "zsh", "fish").
        manager: Manager name (e.g., "pip", "brew").

    Returns:
        The complete pass-through shell function as a string.
    """
    _pass_through: dict[str, str] = {
        "bash": f'{manager}() {{ command {manager} "$@"; }}',
        "zsh": f'{manager}() {{ command {manager} "$@"; }}',
        "fish": f"function {manager}; command {manager} $argv; end",
        "powershell": f"function {manager} {{ & (Get-Command {manager} -CommandType Application) @args }}",
        "nushell": f"def {manager} [...args: string] {{ ^{manager} ...$args }}",
    }
    return _pass_through.get(shell, "")


def _generate_shell_function(
    shell: str,
    manager: str,
    single_word: list[str],
    multi_word: list[str],
) -> str:
    """Generate a shell function string for the given manager.

    Args:
        shell: Shell name (e.g., "bash", "zsh", "fish").
        manager: Manager name (e.g., "pip", "brew", "uv").
        single_word: Sorted list of dangerous single-word subcommands.
        multi_word: Sorted list of dangerous multi-word subcommands.

    Returns:
        The complete shell function as a string.
    """
    templates = SHELL_FUNCTION_TEMPLATES.get(shell)
    if templates is None:
        return ""

    # No dangerous commands -> unconditional pass-through function
    if not single_word and not multi_word:
        return _pass_through_function(shell, manager)

    # Combine all dangerous subcommands for shell pattern matching
    all_patterns = sorted(set(single_word + multi_word))

    if shell == "powershell":
        # PowerShell -in @(...) requires quoted items
        subcmd_str = ", ".join(f"'{p}'" for p in all_patterns)
    else:
        sep = _SUBCMD_SEPARATORS.get(shell, "|")
        subcmd_str = sep.join(all_patterns)

    if multi_word:
        # Managers with multi-word subcommands (uv) need composite key logic
        return templates["multi_word_template"].format(
            manager=manager,
            subcmds=subcmd_str,
        )

    return templates["function_template"].format(
        manager=manager,
        subcmds=subcmd_str,
    )


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@cli.command(name="hooks")
@click.option(
    "-s",
    "--shell",
    "target_shell",
    type=click.Choice(list(SUPPORTED_SHELLS), case_sensitive=False),
    default=None,
    help="Target shell (default: auto-detect current and all installed shells)",
)
@click.pass_context
def hooks(ctx: click.Context, target_shell: str | None) -> None:
    """Generate shell functions that wrap package manager commands for threat protection.

    Detects installed shells and package managers on your system, then prints
    shell-specific functions that you can copy into your RC file.  This lets you
    use your normal package manager commands (e.g. ``pip install``,
    ``npm install``) while pkgd transparently wraps them.

    Examples:

    \b
        pkgd hooks
        pkgd hooks --shell fish
        pkgd hooks -s powershell

    EXIT CODES:
        0    Shell functions generated successfully

    SEE ALSO:
        pkgd completion generate

    \f
    """
    # -- Detection phase -------------------------------------------------------
    current_shell = detect_shell()
    shells = _detect_installed_shells(target_shell)
    managers = _detect_installed_managers()

    # -- Shell detection summary -----------------------------------------------
    console.print("\n[bold]Shell Detection:[/]")
    for shell in SUPPORTED_SHELLS:
        if shell in shells:
            if target_shell:
                marker = "[green]✓ (targeted)[/]"
            elif shell == current_shell:
                marker = "[green]✓ (current)[/]"
            else:
                marker = "[green]✓[/]"
        else:
            marker = "[dim]−[/]"
        console.print(f"  {marker} {shell}")

    # -- Package manager detection summary -------------------------------------
    console.print("\n[bold]Package Manager Detection:[/]")
    if managers:
        for mgr in sorted(managers):
            console.print(f"  [green]✓[/] {mgr}")
    else:
        console.print("  [dim]No supported package managers detected.[/]")

    # -- Shell function output -------------------------------------------------
    console.print("\n[bold]Shell Functions[/]\n")

    if not shells:
        console.print("  [yellow]No supported shells detected.[/]")
    else:
        for shell in shells:
            templates = SHELL_FUNCTION_TEMPLATES[shell]
            console.print(f"[underline]{shell} ({templates['rc_file']}):[/]")

            for mgr in sorted(managers) if managers else []:
                single, multi = _get_dangerous_commands_for_manager(mgr)
                func_text = _generate_shell_function(shell, mgr, single, multi)
                for line in func_text.split("\n"):
                    console.print(f"  {line}", markup=False)
                console.print()

            console.print()

    # -- RC instructions -------------------------------------------------------
    console.print("[bold]Installation Instructions[/]\n")

    if not shells:
        console.print("  [yellow]No known shells were detected on this system.[/]")
        console.print("  Use [bold]--shell[/] to specify a target shell manually.")
    else:
        for shell in shells:
            templates = SHELL_FUNCTION_TEMPLATES[shell]
            console.print(f"  {shell}: add to {templates['rc_file']}, then run: {templates['source_cmd']}")

    console.print(
        "\n[dim]Tip: You only need to add aliases for the shells and package managers you actually use.[/dim]"
    )
