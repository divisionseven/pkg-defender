"""pkgd setup command."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import click
import tomlkit
from rich.prompt import Prompt

from pkg_defender.cli._exit_codes import EXIT_PARTIAL_FAILURE as _EXIT_PARTIAL_FAILURE
from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli._manager_constants import MANAGER_DETECTION_COMMANDS
from pkg_defender.cli.common import (
    SUPPORTED_SHELLS,
    _generate_config_template,
    _print_clipboard_security_tip,
    _write_config_toml,
    console,
    get_data_dir,
    get_db_path,
    get_default_config_path,
    init_db,
    is_running_in_ci,
)
from pkg_defender.cli.main import cli
from pkg_defender.shells.detect import detect_shell, is_shell_installed
from pkg_defender.shells.install import install_completion


def _resolve_config_write_path(ctx: click.Context) -> Path:
    """Resolve config path for writing: --config > PKGD_CONFIG_PATH > default.

    Matches the precedence used by load_config() for reading.

    Args:
        ctx: Click context with --config flag stored in ctx.obj.

    Returns:
        Resolved Path for config file.
    """
    # 1. Check --config flag (stored in ctx.obj)
    config_file = ctx.obj.get("config_file") if ctx.obj else None
    if config_file:
        return Path(config_file)

    # 2. Check PKGD_CONFIG_PATH env var
    if env_path := os.environ.get("PKGD_CONFIG_PATH"):
        return Path(env_path)

    # 3. Fall back to default
    return get_default_config_path()


def _overlay_existing_values(template: tomlkit.TOMLDocument, existing: tomlkit.TOMLDocument) -> None:
    """Overlay existing user values onto a template document.

    Walks the existing document's key-value pairs and overwrites matching
    keys in the template. This preserves the template's structure and
    comments while restoring the user's configured values.

    For sub-tables (e.g., ``cooldown.overrides``), recurses into the
    container. For all other values, the existing value wins.

    Args:
        template: The freshly generated template document (mutated in place).
        existing: The parsed existing config document.
    """
    for key in existing:
        if key not in template:
            # Key from existing that doesn't exist in template — preserve it
            template[key] = existing[key]
            continue

        existing_val = existing[key]
        template_val = template[key]

        if isinstance(existing_val, dict) and isinstance(template_val, dict):
            # Recurse into sub-tables
            _overlay_existing_values(template_val, existing_val)  # type: ignore[arg-type]
        elif not isinstance(existing_val, dict):
            # Scalar value — existing wins
            template[key] = existing_val


def _prompt_for_tokens(config_path: Path | None = None) -> None:
    """Prompt user to configure optional API tokens after setup.

    Args:
        config_path: Path to config file. If None, uses get_default_config_path().
    """
    if config_path is None:
        config_path = get_default_config_path()

    if config_path.exists():
        with open(config_path, "rb") as fh:
            doc = tomlkit.parse(fh.read().decode("utf-8"))
    else:
        doc = tomlkit.document()

    feeds = doc.get("feeds", {})

    missing: list[tuple[str, str, str, str, str]] = []

    if not feeds.get("ghsa_token"):
        missing.append(
            (
                "feeds.ghsa_token",
                "GHSA Token",
                "GitHub Advisory",
                "GHSA & OSSF feed rate limit increase (~60 \u2192 5,000/hr)",
                "https://github.com/settings/tokens",
            )
        )

    if not feeds.get("socket_api_key"):
        missing.append(
            (
                "feeds.socket_api_key",
                "Socket.dev API Key",
                "Socket threat feed",
                "enables the feed",
                "https://socket.dev/docs/api",
            )
        )

    if not feeds.get("x_twitter_bearer_token"):
        missing.append(
            (
                "feeds.x_twitter_bearer_token",
                "X/Twitter Bearer Token",
                "X/Twitter",
                "enables X/Twitter monitoring",
                "https://developer.x.com",
            )
        )

    if not feeds.get("reddit_client_id"):
        missing.append(
            (
                "feeds.reddit_client_id",
                "Reddit Client ID",
                "Reddit",
                "enables official Reddit API",
                "https://www.reddit.com/prefs/apps",
            )
        )
    if not feeds.get("reddit_client_secret"):
        missing.append(
            (
                "feeds.reddit_client_secret",
                "Reddit Client Secret",
                "Reddit",
                "enables official Reddit API",
                "https://www.reddit.com/prefs/apps",
            )
        )

    if not missing:
        return

    console.print()
    console.print("[bold]=== Optional API Keys ===[/bold]")
    for i, (_key, name, feed, benefit, _url) in enumerate(missing, 1):
        console.print(f"  [{i}] {name} ({feed}) - {benefit}")

    console.print()
    selection = console.input("[cyan]Enter numbers to configure (comma-separated), or press Enter to skip: [/cyan]")

    if not selection.strip():
        return

    try:
        selected_indices = set(int(x.strip()) for x in selection.split(",") if x.strip())
    except ValueError:
        console.print("[yellow]Invalid input. Skipping token configuration.[/]")
        return

    for i, (key, name, _feed, _benefit, url) in enumerate(missing, 1):
        if i not in selected_indices:
            continue

        console.print()
        console.print(f"Configuring [bold]{name}[/bold]")
        console.print(f"Documentation: [cyan][link={url}]{url}[/link][/cyan]")

        token_value = Prompt.ask(
            f"[red]Enter {name}:[/red]",
            password=True,
        )
        confirmed_value = Prompt.ask(
            f"[red]Repeat {name} for confirmation:[/red]",
            password=True,
        )
        if token_value != confirmed_value:
            console.print("[yellow]Values do not match. Skipping.[/]")
            continue

        parts = key.split(".")
        if len(parts) == 2:
            section, field = parts
            if section not in doc:
                doc[section] = tomlkit.table()
            doc[section][field] = token_value

    _write_config_toml(config_path, tomlkit.dumps(doc))
    console.print()
    console.print("[green]Token configuration saved![/]")
    console.print()

    _print_clipboard_security_tip()


def _prompt_ossf_exclusion(config_path: Path | None = None) -> list[str] | None:
    """Ask user how they want to handle the OSSF Malicious Packages feed.

    Only prompts when:
    - No GitHub token is configured (OSSF sync is slow without it)
    - The OSSF feed is currently enabled (default: True)

    Returns:
        None:              Sync all feeds now — Option A, or no prompt needed
        ["ossf_malicious"]: Skip OSSF from this sync only — Option B (defer to daemon)

    When the user chooses Option C (permanently disable), this function writes
    ``ossf_malicious_enabled = False`` to the config and returns ``None``, since
    the config change handles the exclusion for all future syncs.

    Args:
        config_path: Path to config file. If None, uses get_default_config_path().
    """
    if config_path is None:
        config_path = get_default_config_path()

    if config_path.exists():
        with open(config_path, "rb") as fh:
            doc = tomlkit.parse(fh.read().decode("utf-8"))
    else:
        doc = tomlkit.document()

    feeds = doc.get("feeds", {})

    # Only ask if no token and OSSF is enabled
    has_token = bool(feeds.get("ghsa_token"))
    ossf_enabled = feeds.get("ossf_malicious_enabled", True)

    if has_token or not ossf_enabled:
        return None

    console.print()
    console.print("[bold yellow]\u26a0 OSSF Malicious Packages Feed[/bold yellow]")
    console.print(
        "[bold]Trust us... you WILL want a GitHub Personal Access Token for this feed![/bold]\n\n"
        "Without a GitHub token, unauthenticated requests are rate-limited significantly by GitHub.\n"
        "Since the OSSF Malicious Packages Feed downloads files individually, the full sync can be very slow.\n\n"
        "[bold red]With a token, the full OSSF sync can take ~10-20 minutes. Without a token, the full sync can take\n"
        "up to ~45-75 minutes depending on your network speeds and GitHub's current rate-limit status.[/bold red]\n\n"
        "If you would like to go back and add a GitHub token, you can quit and run [bold cyan]pkgd setup[/bold cyan]\n"
        "again to securely add it, which will speed up future GHSA & OSSF syncs and allow you to keep the feed enabled."
    )
    console.print()
    console.print("How would you like to handle this?")
    console.print("  [1] Sync all feeds now (including OSSF) [bold]-- slow but complete[/bold]")
    console.print("  [2] Defer OSSF to daemon (sync now without OSSF, daemon will sync it later)")
    console.print("  [3] Permanently disable OSSF feed (won't sync until you re-enable it)")

    choice = Prompt.ask(
        "[cyan]Enter your choice[/cyan]",
        choices=["1", "2", "3"],
        default="1",
    )

    if choice == "1":
        # Option A: Sync all feeds now (including OSSF)
        return None

    if choice == "2":
        # Option B: Skip OSSF from this sync only
        console.print()
        console.print("[green]OSSF feed excluded from this sync only.[/]")
        console.print()
        console.print("[bold]Background sync setup:[/]")
        console.print(
            "  The [cyan]pkgd daemon[/cyan] will automatically sync OSSF in the "
            "background at regular intervals, using your GitHub token if configured."
        )
        console.print("  Run [bold cyan]pkgd daemon start[/bold cyan] to enable automatic sync.")
        console.print()
        return ["ossf_malicious"]

    # Option C: Permanently disable OSSF feed
    if "feeds" not in doc or not isinstance(doc.get("feeds"), dict):
        doc["feeds"] = tomlkit.table()
    doc["feeds"]["ossf_malicious_enabled"] = False
    _write_config_toml(config_path, tomlkit.dumps(doc))

    console.print()
    console.print("[green]OSSF feed has been permanently disabled.[/]")
    console.print()
    console.print(
        "  To re-enable it later, run: [bold cyan]pkgd config set feeds.ossf_malicious_enabled true[/bold cyan]"
    )
    console.print()
    return None


@cli.command(name="setup")
@click.option(
    "--shell",
    "-s",
    "shell_override",
    default=None,
    type=click.Choice(["zsh", "bash", "fish", "powershell", "nushell"]),
    help="Override auto-detected shell",
)
@click.option("--dry-run", "-n", is_flag=True, help="Show what would be changed without modifying files")
@click.option(
    "--init",
    "-i",
    "init_mode",
    is_flag=True,
    default=False,
    help="Create pkgd.toml in current directory with defaults (non-interactive).",
)
@click.option(
    "--force",
    "-f",
    "force_init",
    is_flag=True,
    default=False,
    help="Overwrite existing pkgd.toml when used with --init.",
)
@click.pass_context
def setup(
    ctx: click.Context,
    shell_override: str | None,
    dry_run: bool,
    init_mode: bool = False,
    force_init: bool = False,
) -> None:
    """Interactive first-run setup wizard.

    Runs an interactive setup wizard that:
    1. Detects your shell and installs tab completions automatically
    2. Creates a configuration file (``pkgd.toml``) with defaults
    3. Detects available package managers on your system
    4. Prompts for optional API tokens (GHSA, Socket.dev, Reddit, X/Twitter)
    5. Initialises the threat database
    6. Runs initial threat feed sync

    Use ``--dry-run`` to preview without making changes.
    Use ``--init`` to create ``pkgd.toml`` non-interactively.

    Examples:

    \b
        pkgd setup
        pkgd setup --dry-run
        pkgd setup --shell zsh

    EXIT CODES:
        0    Setup completed successfully
        2    Invalid arguments or shell not supported
        8    Setup completed with warnings (partial failure)

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location
        PKGD_DATABASE_PATH  Custom database path (overrides default location)
        NO_COLOR           Disable colored output

    FILES CREATED/MODIFIED:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml
        Database in platform data dir (threats.db)    Database (after first sync)
        Shell completion scripts (installed automatically)
        ~~~

    \f
    """
    warnings: list[str] = []

    in_ci = is_running_in_ci(ctx)

    if in_ci:
        console.print("[dim]CI mode detected \u2014 running non-interactive setup[/dim]")

    # --init mode: create pkgd.toml in CWD and return
    if force_init and not init_mode:
        click.echo("Error: --force requires --init", err=True)
        raise SystemExit(_EXIT_USAGE_ERROR)

    if init_mode:
        from pkg_defender.config.settings import PROJECT_CONFIG_NAME

        init_config_path = Path.cwd() / PROJECT_CONFIG_NAME

        if init_config_path.exists() and not force_init:
            click.echo(
                f"Error: {PROJECT_CONFIG_NAME} already exists in {Path.cwd()}. Use --force to overwrite.",
                err=True,
            )
            raise SystemExit(_EXIT_USAGE_ERROR)

        from tomlkit import dumps as _tomlkit_dumps

        doc = _generate_config_template()
        _write_config_toml(init_config_path, _tomlkit_dumps(doc))

        console.print(f"[green]Created[/] {init_config_path}")
        console.print()
        console.print(
            f"[dim]This project config will be used automatically when running "
            f"pkgd from {Path.cwd()} or any subdirectory.[/dim]"
        )
        console.print()
        console.print("[dim]To customize, edit the file or run:[/dim]")
        console.print("[dim]  pkgd config set <key> <value>[/dim]")
        return

    detected: str | None = shell_override or detect_shell()

    console.print()
    console.print("[bold]PKG-Defender Setup Wizard[/]")
    console.print()

    if detected not in SUPPORTED_SHELLS:
        console.print(f"[yellow]  Shell '{detected}' is not supported.[/]")
        console.print(f"  Supported shells: {', '.join(sorted(SUPPORTED_SHELLS))}")
        raise SystemExit(_EXIT_USAGE_ERROR)

    if not is_shell_installed(detected):
        console.print(f"[yellow]  Shell '{detected}' is not installed, skipping completion installation.[/]")
        detected = None
    else:
        console.print(f"  [green]Detected shell:[/] {detected}")

        if not dry_run:
            try:
                install_completion(detected, dry_run=False)
                console.print(f"  [green]Completion installed:[/] {detected}")
            except Exception as exc:
                warnings.append(f"  Completion install failed: {exc}")
        else:
            from pkg_defender.shells.install import get_shell_config_path

            completion_path = get_shell_config_path(detected)
            console.print(f"  [dim]Would install completion to:[/dim] {completion_path}")

    config_path = _resolve_config_write_path(ctx)

    if not dry_run:
        from tomlkit import dumps as _tomlkit_dumps
        from tomlkit import parse as _tomlkit_parse

        doc = _generate_config_template()

        try:
            if config_path.exists():
                existing_raw = config_path.read_bytes()
                existing_doc = _tomlkit_parse(existing_raw.decode("utf-8"))
                _overlay_existing_values(doc, existing_doc)

            _write_config_toml(config_path, _tomlkit_dumps(doc))
        except (OSError, PermissionError, ValueError) as exc:
            click.echo(f"Warning: Config file write failed: {exc}", err=True)
            warnings.append(f"  Config file write failed: {exc}")
        else:
            console.print(f"  Config file written to: {config_path}")

    if dry_run:
        console.print()
        console.print("[bold]Dry-run \u2014 no files will be modified.[/]")
        console.print()
        console.print("  Config file will be created if needed.")
        console.print()

        console.print("  Apply these changes?")
        confirm = in_ci or click.confirm("  Apply these changes?", default=True)
        if not confirm:
            console.print("  [dim]Aborted.[/]")
            return

    console.print()
    console.print("  Checking for package managers...")

    for mgr, cmd in MANAGER_DETECTION_COMMANDS.items():
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if proc.returncode == 0:
                console.print(f"  [green]{mgr}[/]: found")
            else:
                console.print(f"  [dim]{mgr}[/]: not found")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print(f"  [dim]{mgr}[/]: not found")

    exclude_feeds: list[str] | None = None
    if in_ci:
        console.print("[dim]Skipping token prompts in CI mode (configure via env vars)[/dim]")
    else:
        try:
            _prompt_for_tokens(config_path=config_path)
            exclude_feeds = _prompt_ossf_exclusion(config_path=config_path)
        except Exception as exc:
            warnings.append(f"  Token configuration save failed: {exc}")

    console.print()
    console.print("[bold yellow]\u26a0 Data Download Notice[/]")
    console.print("This will download ~350 MB of threat intelligence data (depending on configured feeds).")
    console.print()

    if in_ci:
        db_path = os.environ.get("PKGD_DATA_DIR") or os.environ.get("PKGD_DATABASE_PATH")
        if db_path:
            os.environ["PKGD_DATABASE_PATH"] = db_path
            console.print(f"  [dim]Using database path from env: {db_path}[/dim]")
        else:
            console.print(f"[dim]Database location: {get_db_path()}[/dim]")
        console.print()
    else:
        console.print("[bold]=== Database Location ===[/]")
        console.print(f"[1] Default location ({get_data_dir()})")
        console.print("[2] Custom location")
        console.print()

        db_choice = (
            Prompt.ask(
                "[cyan]Enter your choice[/cyan]",
                choices=["1", "2"],
            )
            or "1"
        )

        if db_choice == "2":
            console.print()
            custom_path = Prompt.ask("Enter custom database path (directory)")
            if custom_path:
                os.environ["PKGD_DATABASE_PATH"] = custom_path
                console.print(f"  Using custom database path: [cyan]{custom_path}[/]")
                console.print("  (This will be saved to your config after first sync)")
                console.print()
        else:
            console.print(f"[dim]Database location: {get_db_path()}[/dim]")
            console.print()

    try:
        init_db(get_db_path()).close()
    except Exception as exc:
        warnings.append(f"  Database initialization failed: {exc}")

    console.print()
    console.print("Running full threat feed sync...")
    console.print("[dim](This may take a few minutes to fetch all vulnerability data)[/]")

    try:
        ctx.obj = ctx.obj or {}
        from pkg_defender.cli.commands.intel import intel_sync

        ctx.invoke(
            intel_sync,
            output_format="rich",
            json_flag=False,
            pretty_output=False,
            exclude_feeds=exclude_feeds or (),
        )
    except SystemExit as e:
        if e.code is not None and e.code != 0:
            warnings.append(f"  Intel sync failed (exit code {e.code})")
            console.print("  You can run [bold]pkgd intel sync[/] later.")
    except Exception as exc:
        warnings.append(f"  Intel sync failed: {exc}")
        console.print("  You can run [bold]pkgd intel sync[/] later.")

    if config_path is not None:
        console.print()
        console.print(f"  Config file: [cyan]{config_path}[/cyan]")

    if warnings:
        console.print()
        console.print("[bold yellow]Setup complete with warnings[/]")
        for w in warnings:
            console.print(f"  [yellow]{w}[/]")
        console.print("  [dim]You can re-run 'pkgd setup' to retry failed steps, or address issues manually.[/dim]")
    else:
        console.print()
        console.print("[bold green]Setup complete![/]")
    console.print()
    console.print("[bold]Next steps:[/]")
    console.print("  1. Restart your shell or source your shell configuration file")
    console.print("  2. Run [bold][teal]pkgd status[/] to verify everything is working")
    console.print("  3. Run [bold][teal]pkgd audit .[/] to scan a project for threats")
    console.print()
    console.print("[dim]Completions are installed automatically. Try: pkgd <TAB>[/dim]")
    console.print()
    console.print()

    if warnings:
        raise SystemExit(_EXIT_PARTIAL_FAILURE)
