"""pkgd config group and subcommands."""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Any

import click
from rich.box import SIMPLE as _SIMPLE_BOX
from rich.table import Table as _Table
from rich.text import Text

from pkg_defender.cli._exit_codes import EXIT_CONFIG_ERROR as _EXIT_CONFIG_ERROR
from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli.common import (
    _get_config_from_context,
    _get_config_value_by_key,
    _print_clipboard_security_tip,
    _validate_config_key,
    _write_config_toml,
    console,
    create_table,
    format_json,
    get_default_config_path,
    is_quiet_mode,
    stdout_console,
)
from pkg_defender.cli.group import ManagerGroup
from pkg_defender.cli.main import cli
from pkg_defender.config.settings import (
    _ENV_EXPLICIT_OVERRIDES,
    BypassConfig,
    CooldownConfig,
    DaemonConfig,
    DatabaseConfig,
    FeedConfig,
    OutputConfig,
    PKGDConfig,
    section_mapping,
)

SECRET_FIELDS: frozenset[str] = frozenset(
    {
        "ghsa_token",
        "x_twitter_bearer_token",
        "socket_api_key",
        "reddit_client_id",
        "reddit_client_secret",
    }
)

# Reverse lookup: (section_or_None, field) → actual env var name
# Built from _ENV_EXPLICIT_OVERRIDES to correctly resolve non-standard env var names.
# Sorted by (section, field) for readability.
_EXPLICIT_ENV_LOOKUP: dict[tuple[str | None, str], str] = {
    (section, field): env_var
    for env_var, section, field in sorted(_ENV_EXPLICIT_OVERRIDES, key=lambda x: (x[1] or "", x[2]))
}

logger = logging.getLogger(__name__)


@cli.group(cls=ManagerGroup, name="config", epilog="See also: pkgd health, pkgd setup")
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """Configuration commands."""
    if ctx.invoked_subcommand is None:
        if "--help" not in sys.argv and "-h" not in sys.argv:
            click.echo(ctx.get_help())
            ctx.exit(0)
        return


@config_group.command(name="view")
@click.option(
    "--json",
    "json_flag",
    is_flag=True,
    default=False,
    help="Output JSON instead of a table.",
)
@click.pass_context
def config_view(ctx: click.Context, json_flag: bool = False) -> None:
    """Display current configuration.

    Shows all configuration settings for pkg-defender including cooldown
    rules, feed settings, output preferences, and database options.

    Secret values (API tokens) are shown as [SECRET] or [not set] for security.

    Examples:

    \b
        pkgd config view
        pkgd config view | grep cooldown
        pkgd config view --json

    EXIT CODES:
        0    Success

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location (default: platform-dependent, see `pkgd config path`)

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    config = _get_config_from_context(ctx)

    # Determine output format: subcommand --json flag, then global --json
    output_format = "json" if json_flag else ctx.obj.get("output_format")

    if output_format == "json":
        sections = [
            ("cooldown", config.cooldown, CooldownConfig),
            ("feeds", config.feeds, FeedConfig),
            ("output", config.output, OutputConfig),
            ("database", config.database, DatabaseConfig),
            ("bypass", config.bypass, BypassConfig),
            ("daemon", config.daemon, DaemonConfig),
        ]
        data: dict[str, Any] = {}
        for section_name, section_obj, section_cls in sections:
            section_data: dict[str, Any] = {}
            for f in dc_fields(section_cls):
                value = getattr(section_obj, f.name, None)
                if isinstance(value, Path):
                    value = str(value)
                if f.name in SECRET_FIELDS and value:
                    value = "[SECRET]"
                section_data[f.name] = value
            data[section_name] = section_data
        # Root-level fields
        data["command_timeout_seconds"] = config.command_timeout_seconds
        data["fail_on_threat_enabled"] = config.fail_on_threat_enabled
        data["fail_on_warn_enabled"] = config.fail_on_warn_enabled
        data["registry_api_timeout"] = config.registry_api_timeout
        data["per_ecosystem_registry_timeout"] = config.per_ecosystem_registry_timeout
        data["enable_homebrew_formula_commit"] = config.enable_homebrew_formula_commit
        click.echo(format_json(data, pretty=False), nl=False)
        return

    table = create_table(title="[i]Configuration[/i]", show_header=True, header_style="italic")
    table.add_column("Section", style="bold")
    table.add_column("Key")
    table.add_column("Value")

    table.add_row("cooldown", "default_days", str(config.cooldown.default_days))
    table.add_row("cooldown", "enabled", str(config.cooldown.enabled))
    table.add_row("cooldown", "strict_mode", str(config.cooldown.strict_mode))
    table.add_row("cooldown", "bypass_require_reason", str(config.cooldown.bypass_require_reason))
    table.add_row(
        "cooldown",
        "bypass_log_retention_days",
        str(config.cooldown.bypass_log_retention_days),
    )
    if config.cooldown.overrides:
        for pkg, days in config.cooldown.overrides.items():
            table.add_row("cooldown.overrides", pkg, str(days))
    table.add_row("feeds", "osv_enabled", str(config.feeds.osv_enabled))
    table.add_row(
        "daemon",
        "sync_interval_hours",
        str(config.daemon.sync_interval_hours),
    )
    table.add_row(
        "feeds",
        "staleness_threshold_hours",
        str(config.feeds.staleness_threshold_hours),
    )
    table.add_row("feeds", "ghsa_enabled", str(config.feeds.ghsa_enabled))
    table.add_row(
        "feeds",
        "ghsa_token",
        Text("[SECRET]") if config.feeds.ghsa_token else Text("[not set]"),
    )
    table.add_row("feeds", "mastodon_enabled", str(config.feeds.mastodon_enabled))
    table.add_row("feeds", "mastodon_instance", config.feeds.mastodon_instance)
    table.add_row("feeds", "reddit_enabled", str(config.feeds.reddit_enabled))
    table.add_row("feeds", "rss_enabled", str(config.feeds.rss_enabled))
    table.add_row(
        "feeds",
        "rss_urls",
        f"{len(config.feeds.rss_urls)} feeds configured",
    )
    rss_keywords = config.feeds.rss_keywords
    if isinstance(rss_keywords, str):
        rss_keywords = [kw.strip() for kw in rss_keywords.split(",") if kw.strip()]
    keywords_display = ", ".join(rss_keywords) if rss_keywords else "[not set]"
    table.add_row(
        "feeds",
        "rss_keywords",
        keywords_display,
    )
    table.add_row(
        "feeds",
        "rss_max_age_hours",
        f"{config.feeds.rss_max_age_hours} hours ({config.feeds.rss_max_age_hours // 24} days)",
    )

    console.print()
    console.print("[bold]\U0001f4a1 Helpful Tips:[/bold]")
    console.print("[dim]\U0001f4a1 Update RSS filters with:[/dim]")
    console.print('[dim]  pkgd config set feeds.rss_keywords "keyword1, keyword2, ..."[/dim]')
    console.print("[dim]  pkgd config set feeds.rss_max_age_hours 72  # hours[/dim]")

    table.add_row("feeds", "x_twitter_enabled", str(config.feeds.x_twitter_enabled))
    table.add_row(
        "feeds",
        "x_twitter_bearer_token",
        Text("[SECRET]") if config.feeds.x_twitter_bearer_token else Text("[not set]"),
    )
    table.add_row(
        "feeds",
        "socket_api_key",
        Text("[SECRET]") if config.feeds.socket_api_key else Text("[not set]"),
    )
    table.add_row(
        "feeds",
        "npm_advisory_enabled",
        str(config.feeds.npm_advisory_enabled),
    )
    table.add_row(
        "feeds",
        "ossf_malicious_enabled",
        str(config.feeds.ossf_malicious_enabled),
    )
    table.add_row("output", "color", str(config.output.color))
    table.add_row("output", "json_mode", str(config.output.json_mode))
    table.add_row("output", "verbose", str(config.output.verbose))
    table.add_row("daemon", "run_on_battery", str(config.daemon.run_on_battery))
    table.add_row("database", "wal_mode", str(config.database.wal_mode))
    table.add_row("database", "busy_timeout_ms", str(config.database.busy_timeout_ms))
    table.add_row("security", "command_timeout_seconds", str(config.command_timeout_seconds))
    table.add_row("security", "fail_on_threat_enabled", str(config.fail_on_threat_enabled))
    table.add_row("security", "fail_on_warn_enabled", str(config.fail_on_warn_enabled))
    table.add_row("security", "registry_api_timeout", str(config.registry_api_timeout))
    table.add_row(
        "security",
        "per_ecosystem_registry_timeout",
        str(config.per_ecosystem_registry_timeout),
    )
    table.add_row(
        "security",
        "enable_homebrew_formula_commit",
        str(config.enable_homebrew_formula_commit),
    )

    click.echo()
    stdout_console.print(table)


@config_group.command(name="list")
@click.option(
    "--json",
    "json_flag",
    is_flag=True,
    default=False,
    help="Output JSON instead of a table.",
)
@click.pass_context
def config_list(ctx: click.Context, json_flag: bool = False) -> None:
    """List all configuration values with their sources.

    Shows every configuration option with its current value and the
    source it came from (default or environment variable). The source
    column indicates whether each value comes from the built-in default
    or an environment variable override.

    Examples:

    \b
        pkgd config list
        pkgd config list --json

    EXIT CODES:
        0    Success

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    config = _get_config_from_context(ctx)

    # JSON output path
    # --json subcommand flag takes priority, then global --json
    output_format = "json" if json_flag else ctx.obj.get("output_format")
    if output_format == "json":
        sections = [
            ("cooldown", config.cooldown, CooldownConfig),
            ("feeds", config.feeds, FeedConfig),
            ("output", config.output, OutputConfig),
            ("database", config.database, DatabaseConfig),
            ("bypass", config.bypass, BypassConfig),
            ("daemon", config.daemon, DaemonConfig),
        ]
        env_prefixes = {
            "cooldown": "PKGD_COOLDOWN",
            "feeds": "PKGD_FEEDS",
            "output": "PKGD_OUTPUT",
            "database": "PKGD_DATABASE",
            "bypass": "PKGD_BYPASS",
            "daemon": "PKGD_DAEMON",
        }
        data: dict[str, Any] = {}
        for section_name, section_obj, section_cls in sections:
            section_data: dict[str, Any] = {}
            for f in dc_fields(section_cls):
                value = getattr(section_obj, f.name, None)
                if isinstance(value, Path):
                    value = str(value)
                if f.name in SECRET_FIELDS and value:
                    value = "[SECRET]"
                env_key = _EXPLICIT_ENV_LOOKUP.get((section_name, f.name))
                if env_key is None:
                    env_key = f"{env_prefixes[section_name]}_{f.name.upper()}"
                source = "env" if env_key in os.environ else "default"
                section_data[f.name] = {"value": value, "source": source}
            data[section_name] = section_data
        # Root-level fields
        for root_key in (
            "command_timeout_seconds",
            "fail_on_threat_enabled",
            "fail_on_warn_enabled",
            "registry_api_timeout",
            "per_ecosystem_registry_timeout",
            "enable_homebrew_formula_commit",
        ):
            value = getattr(config, root_key, None)
            if isinstance(value, Path):
                value = str(value)
            env_key = _EXPLICIT_ENV_LOOKUP.get((None, root_key), "")
            source = "env" if (env_key and env_key in os.environ) else "default"
            data[root_key] = {"value": value, "source": source}
        click.echo(format_json(data, pretty=False), nl=False)
        return

    table = create_table(
        title="[i]Configuration Values[/i]",
        show_header=True,
        header_style="italic",
    )
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_column("Source")

    def _add_rows(
        section: str,
        config_obj: Any,
        config_cls: type,
        env_prefix: str,
    ) -> None:
        for f in dc_fields(config_cls):
            key = f"{section}.{f.name}"
            value = getattr(config_obj, f.name, None)
            if f.name in SECRET_FIELDS and value:
                value = "[SECRET]"

            env_key = _EXPLICIT_ENV_LOOKUP.get((section, f.name))
            if env_key is None:
                env_key = f"{env_prefix}_{f.name.upper()}"
            source = f"env:{env_key}" if env_key in os.environ else "default"
            table.add_row(key, str(value), source)

    _add_rows("cooldown", config.cooldown, CooldownConfig, "PKGD_COOLDOWN")
    _add_rows("feeds", config.feeds, FeedConfig, "PKGD_FEEDS")
    _add_rows("output", config.output, OutputConfig, "PKGD_OUTPUT")
    _add_rows("database", config.database, DatabaseConfig, "PKGD_DATABASE")
    _add_rows("bypass", config.bypass, BypassConfig, "PKGD_BYPASS")
    _add_rows("daemon", config.daemon, DaemonConfig, "PKGD_DAEMON")

    # Root-level fields
    for key, value in [
        ("command_timeout_seconds", config.command_timeout_seconds),
        ("fail_on_threat_enabled", config.fail_on_threat_enabled),
        ("fail_on_warn_enabled", config.fail_on_warn_enabled),
        ("registry_api_timeout", config.registry_api_timeout),
        ("per_ecosystem_registry_timeout", config.per_ecosystem_registry_timeout),
        ("enable_homebrew_formula_commit", config.enable_homebrew_formula_commit),
    ]:
        env_key = _EXPLICIT_ENV_LOOKUP.get((None, key), "")
        source = f"env:{env_key}" if (env_key and env_key in os.environ) else "default"
        table.add_row(key, str(value), source)

    stdout_console.print()
    stdout_console.print(table)
    stdout_console.print()


# ---------------------------------------------------------------------------
# Helper: render type annotation as a user-friendly string
# ---------------------------------------------------------------------------


def _render_type_name(field_info: dataclasses.Field[Any]) -> str:  # noqa: PGH003
    """Render a field's type annotation as a user-friendly string.

    Args:
        field_info: The dataclass field whose type to render.

    Returns:
        A string representation of the type.
    """
    tp = field_info.type
    # With ``from __future__ import annotations``, tp is always a string
    return str(tp)


# ---------------------------------------------------------------------------
# Helper: render default value for display
# ---------------------------------------------------------------------------


def _render_default(field_info: dataclasses.Field[Any]) -> str:  # noqa: PGH003
    """Render a field's default value for display in the options table.

    Args:
        field_info: The dataclass field whose default to render.

    Returns:
        A string representation of the default.
    """
    if field_info.metadata.get("secret", False):
        return "[red]SECRET[/red]"

    # Check for default_factory
    if field_info.default_factory is not dataclasses.MISSING:
        try:
            factory = field_info.default_factory
            if (isinstance(factory, type) and factory in (list, dict, set)) or callable(factory):
                result = factory()
            else:
                return "(computed)"
            return str(result)
        except Exception:
            logger.debug("_render_default: factory call failed for field", exc_info=True)
            return "(computed)"

    # Check for simple default
    if field_info.default is not dataclasses.MISSING:
        value = field_info.default
        if value is None:
            return "None"
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return f"'{value}'" if value else '""'
        if isinstance(value, (list, dict)) and not value:
            return "[]" if isinstance(value, list) else "{}"
        return str(value)

    return "(required)"


# ---------------------------------------------------------------------------
# ``pkgd config options`` — list all configurable options with descriptions
# ---------------------------------------------------------------------------


@config_group.command(name="options")
@click.pass_context
def config_options(ctx: click.Context) -> None:
    """List all configurable options with descriptions and defaults.

    Lists every configurable field across all configuration sections,
    showing its dotted path, type, default value, and description.

    Combine with 'pkgd config get <key>' to see the current value.

    Examples:

    \b
        pkgd config options
        pkgd config options | grep secret

    EXIT CODES:
        0    Success

    \f
    """
    config_obj = _get_config_from_context(ctx)

    config_classes: list[tuple[str, Any, type]] = [
        ("Root", config_obj, PKGDConfig),
        ("Cooldown", config_obj.cooldown, CooldownConfig),
        ("Feeds", config_obj.feeds, FeedConfig),
        ("Output", config_obj.output, OutputConfig),
        ("Database", config_obj.database, DatabaseConfig),
        ("Bypass", config_obj.bypass, BypassConfig),
        ("Daemon", config_obj.daemon, DaemonConfig),
    ]

    for section_name, _section_obj, section_cls in config_classes:
        output_table = _Table(
            title=section_name,
            title_style="bold",
            box=_SIMPLE_BOX,
            show_header=True,
            header_style="bold cyan",
        )
        output_table.add_column("Option", style="cyan", no_wrap=True)
        output_table.add_column("Type", style="yellow")
        output_table.add_column("Default", style="white")
        output_table.add_column("Description", style="dim")

        for f in dc_fields(section_cls):
            if f.metadata.get("internal"):
                continue  # skip internal fields

            # Skip sub-dataclass fields in Root section (they are their own sections)
            if section_name == "Root" and f.name in (
                "cooldown",
                "feeds",
                "output",
                "database",
                "bypass",
                "daemon",
            ):
                continue

            key = f"{section_name.lower()}.{f.name}" if section_name != "Root" else f.name
            tp = _render_type_name(f)
            default = _render_default(f)

            desc = f.metadata.get("description", "")
            output_table.add_row(key, tp, default, desc)

        stdout_console.print(output_table)
        stdout_console.print()


@config_group.command(name="set")
@click.argument("key")
@click.argument("value", required=False)
@click.pass_context
def config_set(ctx: click.Context, key: str, value: Any | None) -> None:
    """Set a configuration value.

    Sets a configuration value in the config file. Supports dotted
    key notation for nested settings.

    Examples:

    \b
        pkgd config set feeds.rss_keywords "supply chain, CVE"
        pkgd config set feeds.rss_max_age_hours 72
        pkgd config set cooldown.default_days 3
        pkgd config set cooldown.overrides.lodash 7

    EXIT CODES:
        0    Value set successfully

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    _validate_config_key(key)

    # ── Type coercion ──────────────────────────────────────────────────────
    parts = key.split(".")
    if value is not None:
        if len(parts) == 1:
            # Root-level keys (command_timeout_seconds, fail_on_threat_enabled, fail_on_warn_enabled)
            for f in dc_fields(PKGDConfig):
                if f.name == parts[0]:
                    _type = str(f.type)
                    if _type == "bool":
                        value = str(value).lower() in ("true", "1", "yes")
                    elif _type == "int":
                        value = int(value)
                    elif _type == "float":
                        value = float(value)
                    break
        elif len(parts) == 2:
            section_name = parts[0]
            field_name = parts[1]
            section_cls = dict(section_mapping).get(section_name)
            if section_cls:
                for f in dc_fields(section_cls):
                    if f.name == field_name:
                        _type = str(f.type)
                        if _type == "bool":
                            value = str(value).lower() in ("true", "1", "yes")
                        elif _type == "int":
                            value = int(value)
                        elif _type == "float":
                            value = float(value)
                        break
    # ── End type coercion ──────────────────────────────────────────────────

    config_file = ctx.obj.get("config_file") if ctx.obj else None
    if config_file:
        config_path = Path(config_file)
    elif env_path := os.environ.get("PKGD_CONFIG_PATH"):
        config_path = Path(env_path)
    else:
        config_path = get_default_config_path()
    logger.debug("Config set: key=%s, from_file=%s", key, config_path.exists())

    from tomlkit import dumps as _tomlkit_dumps
    from tomlkit import parse as _tomlkit_parse
    from tomlkit import table as _tomlkit_table

    if config_path.exists():
        with open(config_path, "rb") as fh:
            doc = _tomlkit_parse(fh.read().decode("utf-8"))
    else:
        from tomlkit import document as _tomlkit_document

        doc = _tomlkit_document()

    if value is None:
        secret_value = click.prompt(
            f"Enter value for {key}",
            hide_input=True,
            confirmation_prompt=True,
        )
    else:
        secret_value = value

    parts = key.split(".")
    current = doc
    for part in parts[:-1]:
        if part not in current or not isinstance(current.get(part), dict):
            current[part] = _tomlkit_table()
        current = current[part]
    current[parts[-1]] = secret_value

    _write_config_toml(config_path, _tomlkit_dumps(doc))

    if not is_quiet_mode():
        click.echo()
        console.print(f"[green]Set[/] {key} = ********")
        click.echo()
    if not is_quiet_mode():
        _print_clipboard_security_tip()


@config_group.command(name="set-secret")
@click.argument("key")
@click.pass_context
def config_set_secret(ctx: click.Context, key: str) -> None:
    """Set a secret configuration value with hidden input.

    Prompts for the value with hidden input (not echoed to terminal)
    and requires typing the secret twice to confirm.

    Equivalent to:
        pkgd config set <key>

    Examples:

    \b
        pkgd config set-secret feeds.ghsa_token
        pkgd config set-secret feeds.socket_api_key

    EXIT CODES:
        0    Value set successfully

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    callback = config_set.callback
    assert callback is not None, "config_set callback must exist"
    ctx.invoke(callback, key=key, value=None)


@config_group.command(name="reset")
@click.pass_context
def config_reset(ctx: click.Context) -> None:
    """Reset configuration to defaults.

    Deletes the config file, resetting all settings to defaults.

    Examples:

    \b
        pkgd config reset
        # Will prompt for confirmation
        pkgd config reset --yes
        # Skips confirmation prompt

    EXIT CODES:
        0    Config reset successfully
        1    General error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml (deleted),
        macOS: ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    auto_confirm = ctx.obj.get("auto_confirm", False) if ctx.obj else False

    if not auto_confirm and not click.confirm("Reset all configuration to defaults?"):
        click.echo("Aborted.", err=True)
        raise SystemExit(_EXIT_GENERAL_ERROR)

    config_file = ctx.obj.get("config_file") if ctx.obj else None
    if config_file:
        if not Path(config_file).exists():
            raise click.BadParameter(f"Config file not found: {config_file}")
        config_path = Path(config_file)
    elif env_path := os.environ.get("PKGD_CONFIG_PATH"):
        config_path = Path(env_path)
    else:
        config_path = get_default_config_path()

    if config_path.exists():
        config_path.unlink(missing_ok=True)
        if not is_quiet_mode():
            click.echo()
            console.print("[green]Configuration reset to defaults.[/]")
    else:
        if not is_quiet_mode():
            click.echo()
            console.print("Configuration already at defaults.")


@config_group.command(name="get")
@click.argument("key")
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    """Get a specific configuration value.

    Returns the raw value of a configuration key. Useful for scripting
    and integration with other tools.

    Examples:

    \b
        pkgd config get cooldown.default_days
        pkgd config get feeds.osv_enabled
        pkgd config get database.wal_mode

    EXIT CODES:
        0    Value found and printed
        6    Configuration error

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location

    FILES:
        Config file: Linux ~/.config/pkg-defender/pkgd.toml, macOS ~/Library/Application Support/pkg-defender/pkgd.toml

    \f
    """
    import dataclasses

    _validate_config_key(key)

    config = _get_config_from_context(ctx)

    value = _get_config_value_by_key(config, key)

    if value is None:
        click.echo(
            f"Error: Key '{key}' has no value set. Run 'pkgd config view' to see all keys and their values.",
            err=True,
        )
        raise SystemExit(_EXIT_CONFIG_ERROR)

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            field_value = getattr(value, f.name)
            if f.name in SECRET_FIELDS and field_value:
                field_value = "[SECRET]"
            if f.name != "overrides" or field_value:
                click.echo(f"{f.name} = {field_value}")
    elif isinstance(value, list):
        click.echo(", ".join(str(v) for v in value))
    elif isinstance(value, dict):
        for k, v in value.items():
            click.echo(f"{k} = {v}")
    else:
        leaf_key = key.split(".")[-1]
        if leaf_key in SECRET_FIELDS and value:
            value = "[SECRET]"
        click.echo(value)
