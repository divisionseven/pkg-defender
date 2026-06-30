"""Shared utilities for CLI command modules.

Extracted from main.py to avoid circular imports when command modules
import from the cli package.
"""

from __future__ import annotations

import asyncio
import contextlib
import difflib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
from dataclasses import fields as dc_fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import click
import tomlkit
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pkg_defender.cli._exit_codes import EXIT_CONFIG_ERROR as _EXIT_CONFIG_ERROR
from pkg_defender.cli._exit_codes import EXIT_COOLDOWN as _EXIT_COOLDOWN
from pkg_defender.cli._exit_codes import EXIT_DB_ERROR as _EXIT_DB_ERROR
from pkg_defender.cli._exit_codes import EXIT_GENERAL_ERROR as _EXIT_GENERAL_ERROR
from pkg_defender.cli._exit_codes import EXIT_PARTIAL_FAILURE as _EXIT_PARTIAL_FAILURE
from pkg_defender.cli._exit_codes import EXIT_REGISTRY_UNREACHABLE as _EXIT_REGISTRY_UNREACHABLE
from pkg_defender.cli._exit_codes import EXIT_SUCCESS as _EXIT_SUCCESS
from pkg_defender.cli._exit_codes import EXIT_THREAT_DETECTED as _EXIT_THREAT_DETECTED
from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli._manager_constants import resolve_ecosystem
from pkg_defender.config import get_db_path, load_config
from pkg_defender.config.settings import (
    BypassConfig,
    CooldownConfig,
    DaemonConfig,
    DatabaseConfig,
    FeedConfig,
    OutputConfig,
    PKGDConfig,
    get_data_dir,
    get_default_config_path,
)
from pkg_defender.db import (
    get_connection,
    get_feed_state,  # noqa: F401
    get_version_timestamp,
    init_db,
    insert_bypass,
)
from pkg_defender.display import (
    create_table,  # noqa: F401
    display_audit_results,
    display_stale_db_warning,
    format_json,
    is_quiet_mode,
    is_verbose_mode,
    set_ascii_mode,
    set_no_color,
    set_quiet_mode,
    set_verbose_mode,
    severity_color,
)

logger = logging.getLogger(__name__)

# Exhaustive list of all symbols re-exported or defined in this module
# that are imported by command modules and tests.
__all__ = [
    # Re-exported from pkg_defender.db
    "get_connection",
    "get_feed_state",
    "get_version_timestamp",
    "init_db",
    "insert_bypass",
    # Re-exported from pkg_defender.display
    "create_table",
    "display_audit_results",
    "display_stale_db_warning",
    "format_json",
    "is_quiet_mode",
    "is_verbose_mode",
    "set_ascii_mode",
    "set_no_color",
    "set_quiet_mode",
    "set_verbose_mode",
    "severity_color",
    # Re-exported from pkg_defender.config
    "get_db_path",
    "load_config",
    # Re-exported from pkg_defender.config.settings
    "CooldownConfig",
    "DatabaseConfig",
    "FeedConfig",
    "OutputConfig",
    "PKGDConfig",
    "get_data_dir",
    "get_default_config_path",
    # Re-exported from pkg_defender.cli._manager_constants
    "resolve_ecosystem",
    # Locally defined constants and classes
    "EXIT_CODES",
    "console",
    "stdout_console",
    "stderr_console",
    "SUPPORTED_SHELLS",
    "TokenStatus",
    # Locally defined functions
    "is_running_in_ci",
    "_get_config_from_context",
    "_parse_expiry",
    "_parse_duration",
    "_format_versions",
    "_generate_config_template",
    "_deep_merge_config",
    "_write_config_toml",
    "_detect_manager_from_cwd",
    "_detect_ecosystem_from_cwd",
    "_check_and_warn_staleness",
    "_print_clipboard_security_tip",
    "_validate_config_key",
    "_get_config_value_by_key",
    "_validate_github_token",
    "_validate_socket_token",
    "_validate_x_twitter_token",
    "_validate_reddit_credentials",
    "_check_disk_space",
    "_check_permissions",
    "_get_protection_status",
    "_get_threat_counts",
    "_build_coverage_table",
    "_health_impl",
    "set_console_no_color",
    # Module-level validation sets (used by tests)
    "_VALID_CONFIG_KEYS",
]

EXIT_CODES = {
    "SUCCESS": _EXIT_SUCCESS,
    "GENERAL_ERROR": _EXIT_GENERAL_ERROR,
    "USAGE_ERROR": _EXIT_USAGE_ERROR,
    "COOLDOWN": _EXIT_COOLDOWN,
    "THREAT_DETECTED": _EXIT_THREAT_DETECTED,
    "CONFIG_ERROR": _EXIT_CONFIG_ERROR,
    "DB_ERROR": _EXIT_DB_ERROR,
    "PARTIAL_FAILURE": _EXIT_PARTIAL_FAILURE,
    "REGISTRY_UNREACHABLE": _EXIT_REGISTRY_UNREACHABLE,
    "SIGINT": 130,
}

# Two-Console architecture:
#   stdout_console — for data output (pkgd status, health, config list, etc.)
#   stderr_console — for diagnostics, progress, warnings (wrapper commands, setup, etc.)
#   console — backward-compatible alias for stderr_console (all existing importers keep working)
_no_color = os.environ.get("NO_COLOR") is not None
stdout_console = Console(stderr=False, no_color=_no_color)
stderr_console = Console(stderr=True, no_color=_no_color)
console = stderr_console


def set_console_no_color(enabled: bool = True) -> None:
    """Disable/enable color output on both Consoles using the no_color setter.

    This uses Rich Console's ``no_color`` property setter to mutate the
    *existing* Console objects in-place. All modules that already imported
    ``stdout_console``/``stderr_console`` via ``from common import ...``
    will see the change because Python's import binds references to objects,
    not attribute lookups at access time — mutating the object updates all
    references.

    Called from ``main.py``'s ``--no-color`` flag handler alongside
    ``display.set_no_color()``.

    Args:
        enabled: If True, disable color output on both Consoles.
    """
    stdout_console.no_color = enabled
    stderr_console.no_color = enabled
    # console is an alias for stderr_console, no need to update separately


SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell", "nushell")


def is_running_in_ci(ctx: click.Context) -> bool:
    """Check if running in CI mode (explicit or auto-detected).

    Args:
        ctx: Click context with CI flags stored in obj.

    Returns:
        True if CI mode is enabled or auto-detected.
    """
    obj: dict[str, Any] = ctx.obj
    ci = obj.get("ci", False)
    ci_auto = obj.get("ci_auto_detected", False)
    return bool(ci or ci_auto)


def _get_config_from_context(ctx: click.Context) -> PKGDConfig:
    """Load config using --config file from CLI if provided."""
    config_file = ctx.obj.get("config_file") if ctx.obj else None

    if config_file:
        config_path = Path(config_file)
        if not config_path.exists():
            raise click.BadParameter(f"Config file not found: {config_file}")
        return load_config(config_path)
    return load_config()


def _parse_expiry(expires: str) -> datetime:
    """Parse an expiry string like '24h', '7d', '30m' into a UTC datetime.

    Args:
        expires: Duration string. Supports: Nd (days), Nh (hours), Nm (minutes).

    Returns:
        UTC datetime representing when the bypass expires.

    Raises:
        click.BadParameter: If the format is invalid.
    """
    import re

    match = re.fullmatch(r"(\d+)([dhm])", expires.strip().lower())
    if not match:
        raise click.BadParameter(f"Invalid expiry format '{expires}'. Use Nd, Nh, or Nm (e.g., '7d', '24h', '30m').")
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "d":
        delta = timedelta(days=value)
    elif unit == "h":
        delta = timedelta(hours=value)
    else:  # unit == "m"
        delta = timedelta(minutes=value)
    return datetime.now(UTC) + delta


def _parse_duration(duration: str) -> timedelta:
    """Parse a duration string like '7d', '24h', '30m' into a timedelta.

    Args:
        duration: Duration string. Supports: Nd (days), Nh (hours), Nm (minutes).

    Returns:
        timedelta corresponding to the duration.

    Raises:
        click.BadParameter: If the format is invalid.
    """
    import re

    match = re.fullmatch(r"(\d+)([dhm])", duration.strip().lower())
    if not match:
        raise click.BadParameter(f"Invalid duration '{duration}'. Use Nd, Nh, or Nm (e.g., '7d', '24h', '30m').")
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "d":
        return timedelta(days=value)
    if unit == "h":
        return timedelta(hours=value)
    return timedelta(minutes=value)


def _format_versions(affected_versions_json: str | None, affected_ranges_json: str | None) -> str:
    """Format version info for display, preferring ranges over explicit versions."""
    try:
        ranges = json.loads(affected_ranges_json) if affected_ranges_json else []
    except (json.JSONDecodeError, TypeError):
        ranges = []
    try:
        versions = json.loads(affected_versions_json) if affected_versions_json else []
    except (json.JSONDecodeError, TypeError):
        versions = []

    if ranges:
        result = ", ".join(str(r) for r in ranges)
    elif versions:
        result = ", ".join(str(v) for v in versions[:3])
        if len(versions) > 3:
            result += f" (+{len(versions) - 3} additional)"
    else:
        return "—"

    if len(result) > 38:
        result = result[:35] + "..."
    return result


def _generate_config_template() -> tomlkit.TOMLDocument:
    """Build a fully-commented TOML config document.

    Comments are hardcoded in this function — they are the single canonical
    source for TOML formatting and documentation. Default VALUES are read
    from ``PKGDConfig()`` at runtime, NOT from a dict.

    Subtable sections (``[cooldown.overrides]``, ``[cooldown.per_ecosystem]``)
    are placed AFTER all non-subtable fields of their parent section, per TOML
    spec declaration-order rules.

    Returns:
        A tomlkit TOMLDocument with all sections, comments, and defaults.
    """
    from tomlkit import array, comment, document, nl, table

    doc = document()
    config = PKGDConfig()

    # ═══════════════════════════════════════════════════════════════════════
    # ASCII Art Banner
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment("       _/_/_/    _/    _/    _/_/_/  _/_/_/"))
    doc.add(comment("      _/    _/  _/  _/    _/        _/    _/"))
    doc.add(comment("     _/_/_/    _/_/      _/  _/_/  _/    _/"))
    doc.add(comment("    _/        _/  _/    _/    _/  _/    _/"))
    doc.add(comment("   _/        _/    _/    _/_/_/  _/_/_/"))
    doc.add(comment(""))
    doc.add(comment("        _/_/_/    _/_/    _/      _/  _/_/_/_/  _/_/_/    _/_/_/"))
    doc.add(comment("     _/        _/    _/  _/_/    _/  _/          _/    _/"))
    doc.add(comment("    _/        _/    _/  _/  _/  _/  _/_/_/      _/    _/  _/_/"))
    doc.add(comment("   _/        _/    _/  _/    _/_/  _/          _/    _/    _/"))
    doc.add(comment("    _/_/_/    _/_/    _/      _/  _/        _/_/_/    _/_/_/"))
    doc.add(comment(""))
    doc.add(comment("  PKG-Defender Configuration — By Division 7 (GitHub: divisionseven)"))
    doc.add(comment(""))
    doc.add(comment("  Generated at global system level with `pkgd setup` wizard"))
    doc.add(comment("  Generated at project level with `cd /project/path && pkgd setup --init`"))
    doc.add(comment(""))
    doc.add(comment("  Full documentation:"))
    doc.add(comment("    https://github.com/divisionseven/pkg-defender/blob/main/docs/index.md"))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # Global settings — root-level fields (BEFORE any [section] headers)
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Global settings — applied at the root level."))
    doc.add(comment(" Must be placed before any [section] headers per TOML spec."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    doc.add(comment("Timeout in seconds for command execution."))
    doc.add(comment(f"Default: {config.command_timeout_seconds}"))
    doc["command_timeout_seconds"] = config.command_timeout_seconds
    doc.add(nl())

    doc.add(comment("Whether --fail-on-threat is enabled by default."))
    doc.add(comment(f"Default: {config.fail_on_threat_enabled}"))
    doc["fail_on_threat_enabled"] = config.fail_on_threat_enabled
    doc.add(nl())

    doc.add(comment("Whether PKGD_FAIL_ON_WARN (block on warning) is active."))
    doc.add(comment(f"Default: {config.fail_on_warn_enabled}"))
    doc["fail_on_warn_enabled"] = config.fail_on_warn_enabled
    doc.add(nl())

    doc.add(comment("Timeout in seconds for individual registry API calls (resolve version, get publish time)."))
    doc.add(comment("Per-ecosystem overrides can be set via per_ecosystem_registry_timeout."))
    doc.add(comment(f"Default: {config.registry_api_timeout}"))
    doc["registry_api_timeout"] = config.registry_api_timeout
    doc.add(nl())

    doc.add(comment("Per-ecosystem override for registry API timeout (ecosystem → seconds)."))
    doc.add(comment("Examples:"))
    doc.add(comment("  npm = 5.0"))
    doc.add(comment("  pypi = 15.0"))
    per_eco_timeout_tbl = table()
    doc["per_ecosystem_registry_timeout"] = per_eco_timeout_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [cooldown] — Cooldown Gate
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Cooldown Gate — enforces a minimum age before new packages can be installed."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    cooldown_tbl = table()

    cooldown_tbl.add(nl())
    cooldown_tbl.add(comment("Minimum age in days before a new package version is allowed."))
    cooldown_tbl.add(comment(f"Default: {config.cooldown.default_days}"))
    cooldown_tbl.add("default_days", config.cooldown.default_days)
    cooldown_tbl.add(nl())

    cooldown_tbl.add(comment("Whether cooldown checking is active. Set false to disable entirely."))
    cooldown_tbl.add(comment(f"Default: {config.cooldown.enabled}"))
    cooldown_tbl.add("enabled", config.cooldown.enabled)
    cooldown_tbl.add(nl())

    cooldown_tbl.add(comment("If True, audit exits non-zero when threats are found during cooldown enforcement."))
    cooldown_tbl.add(comment("If False, audit exits zero even with threats (weakened security posture)."))
    cooldown_tbl.add(comment(f"Default: {config.cooldown.strict_mode}"))
    cooldown_tbl.add("strict_mode", config.cooldown.strict_mode)
    cooldown_tbl.add(nl())

    cooldown_tbl.add(comment("If True, a reason must be provided when bypassing the cooldown."))
    cooldown_tbl.add(comment(f"Default: {config.cooldown.bypass_require_reason}"))
    cooldown_tbl.add("bypass_require_reason", config.cooldown.bypass_require_reason)
    cooldown_tbl.add(nl())

    cooldown_tbl.add(comment("Number of days to retain bypass audit log entries."))
    cooldown_tbl.add(comment("Note: Displayed in config listings only — no auto-prune enforcement code."))
    cooldown_tbl.add(comment(f"Default: {config.cooldown.bypass_log_retention_days}"))
    cooldown_tbl.add("bypass_log_retention_days", config.cooldown.bypass_log_retention_days)
    cooldown_tbl.add(nl())

    doc["cooldown"] = cooldown_tbl

    # Subtable: [cooldown.overrides] — AFTER all non-subtable cooldown fields
    overrides_tbl = table()
    overrides_tbl.add(comment("Per-package cooldown days override (package name → days)."))
    overrides_tbl.add(comment("Package names must be quoted to avoid TOML parsing errors."))
    overrides_tbl.add(comment("Examples:"))
    overrides_tbl.add(comment('  "react" = 14'))
    overrides_tbl.add(comment('  "@babel/core" = 21'))
    overrides_tbl.add(comment('  "some-package" = 7'))
    doc["cooldown"]["overrides"] = overrides_tbl

    # Subtable: [cooldown.per_ecosystem] — AFTER all non-subtable cooldown fields
    per_eco_tbl = table()
    per_eco_tbl.add(comment("Per-ecosystem cooldown window overrides (ecosystem → days)."))
    per_eco_tbl.add(comment("Examples:"))
    per_eco_tbl.add(comment("  npm = 7"))
    per_eco_tbl.add(comment("  pypi = 14"))
    doc["cooldown"]["per_ecosystem"] = per_eco_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [feeds] — Threat Intelligence Feeds
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Threat Intelligence Feeds — structured advisories and social signals."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    feeds_tbl = table()

    feeds_tbl.add(nl())
    feeds_tbl.add(comment("Whether the OSV.dev feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.osv_enabled}"))
    feeds_tbl.add("osv_enabled", config.feeds.osv_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the GitHub Security Advisory feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.ghsa_enabled}"))
    feeds_tbl.add("ghsa_enabled", config.feeds.ghsa_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Bearer token for GitHub GraphQL API (rate limit 60→5,000/hr)."))
    feeds_tbl.add(comment("Obtain from: https://github.com/settings/tokens"))
    feeds_tbl.add(comment('Default: ""'))
    feeds_tbl.add("ghsa_token", config.feeds.ghsa_token)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the Mastodon social feed is active (disabled until OAuth exists)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.mastodon_enabled}"))
    feeds_tbl.add("mastodon_enabled", config.feeds.mastodon_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Mastodon instance hostname to query."))
    feeds_tbl.add(comment(f'Default: "{config.feeds.mastodon_instance}"'))
    feeds_tbl.add("mastodon_instance", config.feeds.mastodon_instance)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Hashtags to monitor for supply chain signals."))
    feeds_tbl.add(comment(f"Default: {config.feeds.mastodon_hashtags}"))
    mastodon_hashtags_arr = array()
    for tag in config.feeds.mastodon_hashtags:
        mastodon_hashtags_arr.append(tag)
    mastodon_hashtags_arr.multiline(True)
    feeds_tbl.add("mastodon_hashtags", mastodon_hashtags_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Max age in hours for Mastodon posts to consider."))
    feeds_tbl.add(comment(f"Default: {config.feeds.mastodon_max_age_hours}"))
    feeds_tbl.add("mastodon_max_age_hours", config.feeds.mastodon_max_age_hours)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the Reddit social feed is active (bring your own keys)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.reddit_enabled}"))
    feeds_tbl.add("reddit_enabled", config.feeds.reddit_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Subreddits to monitor for threat signals."))
    feeds_tbl.add(comment(f"Default: {config.feeds.reddit_subreddits}"))
    reddit_subs_arr = array()
    for sub in config.feeds.reddit_subreddits:
        reddit_subs_arr.append(sub)
    reddit_subs_arr.multiline(True)
    feeds_tbl.add("reddit_subreddits", reddit_subs_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Keywords to search for in subreddit posts."))
    feeds_tbl.add(comment(f"Default: {config.feeds.reddit_keywords}"))
    reddit_kw_arr = array()
    for kw in config.feeds.reddit_keywords:
        reddit_kw_arr.append(kw)
    reddit_kw_arr.multiline(True)
    feeds_tbl.add("reddit_keywords", reddit_kw_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Max age in hours for Reddit posts to consider."))
    feeds_tbl.add(comment(f"Default: {config.feeds.reddit_max_age_hours}"))
    feeds_tbl.add("reddit_max_age_hours", config.feeds.reddit_max_age_hours)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Reddit OAuth client ID (required for official API)."))
    feeds_tbl.add(comment("Obtain from: https://www.reddit.com/prefs/apps"))
    feeds_tbl.add(comment('Default: ""'))
    feeds_tbl.add("reddit_client_id", config.feeds.reddit_client_id)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Reddit OAuth client secret (required for official API)."))
    feeds_tbl.add(comment('Default: ""'))
    feeds_tbl.add("reddit_client_secret", config.feeds.reddit_client_secret)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the RSS feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.rss_enabled}"))
    feeds_tbl.add("rss_enabled", config.feeds.rss_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("RSS feed URLs to monitor for advisory data."))
    feeds_tbl.add(comment("Default: 6 feeds from socket.dev, snyk, openssf, github.blog, gitguardian, sonatype"))
    rss_urls_arr = array()
    for url in config.feeds.rss_urls:
        rss_urls_arr.append(url)
    rss_urls_arr.multiline(True)
    feeds_tbl.add("rss_urls", rss_urls_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Keywords to filter RSS entries."))
    feeds_tbl.add(comment("Default: 32 keywords covering core security terms, attack types,"))
    feeds_tbl.add(comment("ecosystem names, and incident response."))
    rss_kw_arr = array()
    for kw in config.feeds.rss_keywords:
        rss_kw_arr.append(kw)
    rss_kw_arr.multiline(True)
    feeds_tbl.add("rss_keywords", rss_kw_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Max age in hours for RSS entries to consider (default 14 days)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.rss_max_age_hours}"))
    feeds_tbl.add("rss_max_age_hours", config.feeds.rss_max_age_hours)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the X/Twitter feed is active (bring your own key)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.x_twitter_enabled}"))
    feeds_tbl.add("x_twitter_enabled", config.feeds.x_twitter_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Bearer token for X/Twitter API v2."))
    feeds_tbl.add(comment("Obtain from: https://developer.twitter.com/en/portal/dashboard"))
    feeds_tbl.add(comment('Default: ""'))
    feeds_tbl.add("x_twitter_bearer_token", config.feeds.x_twitter_bearer_token)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Trusted X/Twitter account IDs to monitor specifically."))
    feeds_tbl.add(comment("These are numeric user IDs (strings), not handles."))
    feeds_tbl.add(comment(' - CORRECT: ["123456789", "987654321"]'))
    feeds_tbl.add(comment(' - INCORRECT: ["@username", "username"]'))
    feeds_tbl.add(comment("Default: []"))
    x_accounts_arr = array()
    for acct in config.feeds.x_twitter_trusted_accounts:
        x_accounts_arr.append(acct)
    x_accounts_arr.multiline(True)
    feeds_tbl.add("x_twitter_trusted_accounts", x_accounts_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Keywords to search for in tweets."))
    feeds_tbl.add(comment(f"Default: {config.feeds.x_twitter_keywords}"))
    x_kw_arr = array()
    for kw in config.feeds.x_twitter_keywords:
        x_kw_arr.append(kw)
    x_kw_arr.multiline(True)
    feeds_tbl.add("x_twitter_keywords", x_kw_arr)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Max age in hours for tweets to consider."))
    feeds_tbl.add(comment(f"Default: {config.feeds.x_twitter_max_age_hours}"))
    feeds_tbl.add("x_twitter_max_age_hours", config.feeds.x_twitter_max_age_hours)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Hours before a feed is considered stale (triggers re-sync)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.staleness_threshold_hours}"))
    feeds_tbl.add("staleness_threshold_hours", config.feeds.staleness_threshold_hours)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("API key for Socket.dev threat feed."))
    feeds_tbl.add(comment("Obtain from: https://socket.dev/"))
    feeds_tbl.add(comment('Default: ""'))
    feeds_tbl.add("socket_api_key", config.feeds.socket_api_key)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the Socket.dev feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.socket_enabled}"))
    feeds_tbl.add("socket_enabled", config.feeds.socket_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the npm advisory feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.npm_advisory_enabled}"))
    feeds_tbl.add("npm_advisory_enabled", config.feeds.npm_advisory_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Whether the OSSF malicious packages feed is active."))
    feeds_tbl.add(comment(f"Default: {config.feeds.ossf_malicious_enabled}"))
    feeds_tbl.add("ossf_malicious_enabled", config.feeds.ossf_malicious_enabled)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("HTTP timeout in seconds for all feed/registry requests."))
    feeds_tbl.add(comment(f"Default: {config.feeds.http_timeout}"))
    feeds_tbl.add("http_timeout", config.feeds.http_timeout)
    feeds_tbl.add(nl())

    feeds_tbl.add(comment("Maximum seconds to wait for all feeds to sync (0=no timeout)."))
    feeds_tbl.add(comment(f"Default: {config.feeds.feed_sync_timeout}"))
    feeds_tbl.add("feed_sync_timeout", config.feeds.feed_sync_timeout)
    feeds_tbl.add(nl())

    doc["feeds"] = feeds_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [output] — Terminal Output Formatting
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Terminal output formatting, verbosity, and severity filter settings."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    output_tbl = table()

    output_tbl.add(nl())
    output_tbl.add(comment("Whether to use colored terminal output."))
    output_tbl.add(comment("This is the baseline value — it applies when no explicit override is active."))
    output_tbl.add(comment(f"Default: {config.output.color}"))
    output_tbl.add("color", config.output.color)
    output_tbl.add(nl())

    output_tbl.add(comment("Whether to emit JSON output (for CI consumption)."))
    output_tbl.add(comment(f"Default: {config.output.json_mode}"))
    output_tbl.add("json_mode", config.output.json_mode)
    output_tbl.add(nl())

    output_tbl.add(comment("Whether to enable verbose logging/output."))
    output_tbl.add(comment(f"Default: {config.output.verbose}"))
    output_tbl.add("verbose", config.output.verbose)
    output_tbl.add(nl())

    output_tbl.add(comment("Whether to show the ASCII banner in help output."))
    output_tbl.add(comment(f"Default: {config.output.show_ascii_banner}"))
    output_tbl.add("show_ascii_banner", config.output.show_ascii_banner)
    output_tbl.add(nl())

    output_tbl.add(comment("Severity levels to exclude from intel report output."))
    output_tbl.add(comment(f"Default: {config.output.intel_exclude_severity}"))
    intel_excl_arr = array()
    for s in config.output.intel_exclude_severity:
        intel_excl_arr.append(s)
    intel_excl_arr.multiline(True)
    output_tbl.add("intel_exclude_severity", intel_excl_arr)
    output_tbl.add(nl())

    output_tbl.add(comment("Severity levels to exclude from search output."))
    output_tbl.add(comment(f"Default: {config.output.search_exclude_severity}"))
    search_excl_arr = array()
    for s in config.output.search_exclude_severity:
        search_excl_arr.append(s)
    search_excl_arr.multiline(True)
    output_tbl.add("search_exclude_severity", search_excl_arr)
    output_tbl.add(nl())

    doc["output"] = output_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [database] — Local SQLite Database
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Local SQLite threat database storage and performance configuration."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    database_tbl = table()

    database_tbl.add(nl())
    database_tbl.add(comment("Enable WAL journal mode for SQLite."))
    database_tbl.add(comment(f"Default: {config.database.wal_mode}"))
    database_tbl.add("wal_mode", config.database.wal_mode)
    database_tbl.add(nl())

    database_tbl.add(comment("SQLite busy timeout in milliseconds."))
    database_tbl.add(comment(f"Default: {config.database.busy_timeout_ms}"))
    database_tbl.add("busy_timeout_ms", config.database.busy_timeout_ms)
    database_tbl.add(nl())

    # path is None by default — show commented-out example instead
    database_tbl.add(comment("Custom database directory path (defaults to platform data dir)."))
    database_tbl.add(comment("If set, overrides the default platform user data directory."))
    database_tbl.add(comment("Default: None (auto-resolved — field is omitted from default config)"))
    database_tbl.add(comment('path = "/your/custom/db/path"'))
    database_tbl.add(nl())

    database_tbl.add(
        comment(
            "Custom URL for database snapshot download (bypasses GitHub API). Requires a companion .sha256 file.",
        )
    )
    database_tbl.add(comment('Default: ""'))
    database_tbl.add("snapshot_url", config.database.snapshot_url)
    database_tbl.add(nl())

    database_tbl.add(comment("Number of days to retain threat records. Records with last_seen older than"))
    database_tbl.add(comment("this are deleted after each feed sync. None = feature disabled — no"))
    database_tbl.add(comment("automatic pruning. Must be an integer >= 1 if set."))
    database_tbl.add(comment("Default: None (feature disabled — field is omitted from default config)"))
    database_tbl.add(comment("retention_days = 30"))
    database_tbl.add(nl())

    doc["database"] = database_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [bypass] — Bypass Command Access Control
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Bypass command access control — opt-in only, disabled by default."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    bypass_tbl = table()

    bypass_tbl.add(nl())
    bypass_tbl.add(comment("If False, the bypass CLI command returns an error."))
    bypass_tbl.add(comment(f"Default: {config.bypass.command_enabled}"))
    bypass_tbl.add("command_enabled", config.bypass.command_enabled)
    bypass_tbl.add(nl())

    doc["bypass"] = bypass_tbl
    doc.add(nl())

    # ═══════════════════════════════════════════════════════════════════════
    # [daemon] — Background Daemon Process
    # ═══════════════════════════════════════════════════════════════════════
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(comment(" Background daemon process behavior and power management."))
    doc.add(comment("════════════════════════════════════════════════════════════════════════════════"))
    doc.add(nl())

    daemon_tbl = table()

    daemon_tbl.add(nl())
    daemon_tbl.add(comment("Allow the daemon to run on battery power."))
    daemon_tbl.add(comment("Disabled by default — daemon automatically terminates when on battery."))
    daemon_tbl.add(comment(f"Default: {config.daemon.run_on_battery}"))
    daemon_tbl.add("run_on_battery", config.daemon.run_on_battery)
    daemon_tbl.add(nl())

    daemon_tbl.add(comment("Hours between daemon feed sync cycles."))
    daemon_tbl.add(comment(f"Default: {config.daemon.sync_interval_hours}"))
    daemon_tbl.add("sync_interval_hours", config.daemon.sync_interval_hours)
    daemon_tbl.add(nl())

    doc["daemon"] = daemon_tbl

    return doc


def _write_config_toml(path: Path, content: str) -> None:
    """Write a TOML string atomically (temp file + rename).

    Validates the content string with ``tomllib.loads()`` before writing.
    If the TOML is invalid, raises ``ValueError`` and does NOT write.

    Args:
        path: Path to the config file to write.
        content: TOML string content to write.

    Raises:
        ValueError: If the content is not valid TOML.
        OSError: If the file cannot be written (permissions, disk full, etc.).
    """
    import tomllib

    # Validate TOML before writing
    try:
        tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Generated TOML is invalid: {exc}") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=".config.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as tmp_file:
            tmp_file.write(content.encode("utf-8"))
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise


def _deep_merge_config(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge overlay into base, preserving base values for existing keys.

    For nested dicts, recurse. For all other values, base wins (existing
    values are never overwritten). New keys from overlay are added to base.

    Args:
        base: Existing config dict (values to preserve).
        overlay: Defaults dict (new keys to add).

    Returns:
        Merged dict with base values preserved, overlay keys added.
    """
    merged = base.copy()
    for key, overlay_value in overlay.items():
        if key not in merged:
            merged[key] = overlay_value
        elif isinstance(overlay_value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_config(merged[key], overlay_value)
    return merged


def _detect_manager_from_cwd() -> str:
    """Detect package manager from files in the current directory.

    Returns:
        Package manager name (e.g., "npm", "pip", "cargo").
    """
    from pkg_defender.cli._manager_constants import MANAGER_MARKER_FILES

    cwd = Path.cwd()
    for manager, markers in MANAGER_MARKER_FILES.items():
        for marker in markers:
            if (cwd / marker).exists():
                return manager
    if Path("/etc/apt").exists():
        return "apt"
    return "npm"


def _detect_ecosystem_from_cwd() -> str:
    """Detect internal ecosystem identifier from files in the current directory.

    Returns:
        Internal ecosystem identifier (e.g., "npm", "pypi", "cargo").
    """
    return resolve_ecosystem(_detect_manager_from_cwd())


def _check_and_warn_staleness(
    conn: sqlite3.Connection,
    threshold_hours: int | None = None,
    config: PKGDConfig | None = None,
) -> None:
    """Check if threat DB is stale and show a warning if so."""
    if threshold_hours is None:
        if config is None:
            config = load_config()
        threshold_hours = config.feeds.staleness_threshold_hours
    state = get_feed_state(conn, "osv")
    if state is None or state.get("last_sync") is None:
        display_stale_db_warning(None)
        return

    try:
        last_sync_str = state.get("last_sync")
        if last_sync_str is None:
            display_stale_db_warning(None)
            return
        last_sync = datetime.fromisoformat(last_sync_str)
        if last_sync.tzinfo is None:
            last_sync = last_sync.replace(tzinfo=UTC)
        age = datetime.now(UTC) - last_sync
        if age > timedelta(hours=threshold_hours):
            display_stale_db_warning(last_sync)
    except (ValueError, TypeError):
        display_stale_db_warning(None)


def _print_clipboard_security_tip() -> None:
    """Print a security reminder to clear clipboard after entering sensitive keys/tokens."""
    # Suppress in quiet mode — tip is informational, not a security notification
    if is_quiet_mode():
        return

    tip_text = Text()
    tip_text.append(
        "If you used copy/paste to input your credentials, remember to clear your clipboard!\n\n"
        "Here's how to do it:\n\n",
        style="white",
    )
    tip_text.append("macOS:            ", style="bold cyan")
    tip_text.append("pbcopy < /dev/null\n", style="white bold")
    tip_text.append("                  ", style="dim")
    tip_text.append("# Or use free app: Clipy (App Store)\n\n", style="dim white")

    tip_text.append("Windows:          ", style="bold cyan")
    tip_text.append("echo off | clip\n", style="white bold")
    tip_text.append("                  ", style="dim")
    tip_text.append("# Or: Win+V \u2192 select all \u2192 Clear all\n", style="dim white")
    tip_text.append("                  ", style="dim")
    tip_text.append("# Or: Set-Clipboard -Value $null (PowerShell)\n\n", style="dim white")

    tip_text.append("Linux X11:        ", style="bold cyan")
    tip_text.append("printf '' | xclip -selection clipboard\n", style="white bold")
    tip_text.append("                  ", style="dim")
    tip_text.append("# Or: echo -n | xsel -b\n\n", style="dim white")

    tip_text.append("Linux Wayland:    ", style="bold cyan")
    tip_text.append("wl-copy --clear\n", style="white bold")
    tip_text.append("                  ", style="dim")
    tip_text.append("# most modern distros\n", style="dim white")
    tip_text.append("\n", style="dim")

    tip_text.append(
        "Why? Clipboard managers, tmux copy-mode, and other tools\n"
        "can log or retain your copied secrets. Clearing prevents this.",
        style="white",
    )

    console.print(Panel(tip_text, title="Security Tip", border_style="yellow", expand=False))


# ---------------------------------------------------------------------------
# Config key validation
# ---------------------------------------------------------------------------

_VALID_SECTIONS: set[str] = {"cooldown", "feeds", "output", "database", "bypass", "daemon"}

_VALID_CONFIG_KEYS: set[str] = set()
for _section_cls, _prefix in (
    (CooldownConfig, "cooldown"),
    (FeedConfig, "feeds"),
    (OutputConfig, "output"),
    (DatabaseConfig, "database"),
    (BypassConfig, "bypass"),
    (DaemonConfig, "daemon"),
):
    for _f in dc_fields(_section_cls):
        _VALID_CONFIG_KEYS.add(f"{_prefix}.{_f.name}")

_VALID_CONFIG_KEYS.add("command_timeout_seconds")
_VALID_CONFIG_KEYS.add("fail_on_threat_enabled")
_VALID_CONFIG_KEYS.add("fail_on_warn_enabled")
_VALID_CONFIG_KEYS.add("registry_api_timeout")
_VALID_CONFIG_KEYS.add("per_ecosystem_registry_timeout")

_LIST_CONFIG_KEYS: set[str] = set()
for _section_cls, _prefix in (
    (CooldownConfig, "cooldown"),
    (FeedConfig, "feeds"),
    (OutputConfig, "output"),
    (DatabaseConfig, "database"),
    (BypassConfig, "bypass"),
    (DaemonConfig, "daemon"),
):
    for _f in dc_fields(_section_cls):
        field_type = _f.type
        if getattr(field_type, "__origin__", None) is list:
            _LIST_CONFIG_KEYS.add(f"{_prefix}.{_f.name}")


def _validate_config_key(key: str) -> None:
    """Validate a dotted config key against known fields.

    Args:
        key: Dotted key string (e.g., ``cooldown.default_days``).

    Raises:
        SystemExit: If the key is invalid.
    """
    parts = key.split(".")

    if len(parts) == 1 and parts[0] in (
        "command_timeout_seconds",
        "fail_on_threat_enabled",
        "fail_on_warn_enabled",
        "registry_api_timeout",
        "per_ecosystem_registry_timeout",
    ):
        return

    if parts[0] not in _VALID_SECTIONS:
        suggestion = difflib.get_close_matches(parts[0], _VALID_SECTIONS, n=1, cutoff=0.6)
        msg = f"Error: Unknown config key '{key}'."
        if suggestion:
            msg += f" Did you mean section '{suggestion[0]}'?"
        msg += " Run 'pkgd config view' to see valid keys."
        click.echo(msg, err=True)
        raise SystemExit(_EXIT_CONFIG_ERROR) from None

    if parts[0] == "cooldown" and len(parts) == 3 and parts[1] == "overrides":
        return

    if len(parts) != 2:
        click.echo(
            f"Error: Unknown config key '{key}'. Run 'pkgd config view' to see valid keys.",
            err=True,
        )
        raise SystemExit(_EXIT_CONFIG_ERROR) from None

    if key not in _VALID_CONFIG_KEYS:
        all_keys = sorted(_VALID_CONFIG_KEYS)
        suggestion = difflib.get_close_matches(key, all_keys, n=1, cutoff=0.6)
        msg = f"Error: Unknown config key '{key}'."
        if suggestion:
            msg += f" Did you mean '{suggestion[0]}'?"
        msg += " Run 'pkgd config view' to see valid keys."
        click.echo(msg, err=True)
        raise SystemExit(_EXIT_CONFIG_ERROR) from None


def _get_config_value_by_key(config: PKGDConfig, key: str) -> Any:
    """Get a config value by dotted key path.

    Args:
        config: The config instance.
        key: Dotted key like "cooldown.default_days".

    Returns:
        The value at that key, or None if not found.
    """
    parts = key.split(".")

    section_map = {
        "cooldown": config.cooldown,
        "feeds": config.feeds,
        "output": config.output,
        "database": config.database,
        "bypass": config.bypass,
        "daemon": config.daemon,
    }

    if len(parts) == 1:
        return getattr(config, parts[0], None)

    if parts[0] in (
        "command_timeout_seconds",
        "fail_on_threat_enabled",
        "fail_on_warn_enabled",
        "registry_api_timeout",
        "per_ecosystem_registry_timeout",
    ):
        if len(parts) == 1:
            return getattr(config, parts[0], None)
        return None

    if parts[0] not in section_map:
        return None

    section = section_map[parts[0]]

    if len(parts) == 2:
        return getattr(section, parts[1], None)

    if parts[0] == "cooldown" and parts[1] == "overrides" and len(parts) == 3:
        return config.cooldown.overrides.get(parts[2])

    return None


# ---------------------------------------------------------------------------
# Token validation for health checks
# ---------------------------------------------------------------------------


class TokenStatus:
    """Token validation status values."""

    VALID = "valid"
    EXPIRED = "expired"
    NOT_CONFIGURED = "not_configured"
    INVALID = "invalid"
    ERROR = "error"


async def _validate_github_token(token: str) -> tuple[str, str]:
    """Validate GitHub token with a simple API call.

    Args:
        token: GitHub token to validate.

    Returns:
        Tuple of (status, message).
    """
    import aiohttp

    if not token:
        return TokenStatus.NOT_CONFIGURED, "no token configured"

    url = "https://api.github.com/user"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.get(url, headers=headers) as resp,
        ):
            if resp.status == 200:
                return TokenStatus.VALID, "token validated"
            elif resp.status == 401:
                return TokenStatus.INVALID, "unauthorized - token invalid or expired"
            elif resp.status == 403:
                return TokenStatus.EXPIRED, "forbidden - token may be expired"
            else:
                return TokenStatus.ERROR, f"HTTP {resp.status}"
    except aiohttp.ClientError as exc:
        return TokenStatus.ERROR, f"connection error: {exc!r}"
    except Exception as exc:
        return TokenStatus.ERROR, f"unexpected error: {exc!r}"


async def _validate_socket_token(api_key: str) -> tuple[str, str]:
    """Validate Socket.dev API key with a simple API call.

    Args:
        api_key: Socket.dev API key to validate.

    Returns:
        Tuple of (status, message).
    """
    import aiohttp

    if not api_key:
        return TokenStatus.NOT_CONFIGURED, "no API key configured"

    url = "https://api.socket.dev/v0/user"
    headers = {"Authorization": f"api {api_key}"}

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.get(url, headers=headers) as resp,
        ):
            if resp.status == 200:
                return TokenStatus.VALID, "API key validated"
            elif resp.status == 401:
                return TokenStatus.INVALID, "unauthorized - API key invalid"
            elif resp.status == 403:
                return TokenStatus.EXPIRED, "forbidden - API key may be expired"
            else:
                return TokenStatus.ERROR, f"HTTP {resp.status}"
    except aiohttp.ClientError as exc:
        return TokenStatus.ERROR, f"connection error: {exc!r}"
    except Exception as exc:
        return TokenStatus.ERROR, f"unexpected error: {exc!r}"


async def _validate_x_twitter_token(bearer_token: str) -> tuple[str, str]:
    """Validate X/Twitter bearer token with a simple API call.

    Args:
        bearer_token: X/Twitter bearer token to validate.

    Returns:
        Tuple of (status, message).
    """
    import aiohttp

    if not bearer_token:
        return TokenStatus.NOT_CONFIGURED, "no bearer token configured"

    url = "https://api.twitter.com/2/users/me"
    headers = {"Authorization": f"Bearer {bearer_token}"}

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.get(url, headers=headers) as resp,
        ):
            if resp.status == 200:
                return TokenStatus.VALID, "bearer token validated"
            elif resp.status == 401:
                return TokenStatus.INVALID, "unauthorized - token invalid"
            elif resp.status == 403:
                return TokenStatus.EXPIRED, "forbidden - token may be expired"
            else:
                return TokenStatus.ERROR, f"HTTP {resp.status}"
    except aiohttp.ClientError as exc:
        return TokenStatus.ERROR, f"connection error: {exc!r}"
    except Exception as exc:
        return TokenStatus.ERROR, f"unexpected error: {exc!r}"


async def _validate_reddit_credentials(client_id: str, client_secret: str) -> tuple[str, str]:
    """Validate Reddit OAuth credentials with a simple API call.

    Args:
        client_id: Reddit OAuth client ID.
        client_secret: Reddit OAuth client secret.

    Returns:
        Tuple of (status, message).
    """
    import aiohttp

    if not client_id and not client_secret:
        return TokenStatus.NOT_CONFIGURED, "no credentials configured"
    if not client_id or not client_secret:
        return TokenStatus.NOT_CONFIGURED, "partial credentials — both client_id and client_secret required"

    url = "https://www.reddit.com/api/v1/access_token"
    headers = {"User-Agent": "pkg-defender/1.0"}
    data = {"grant_type": "client_credentials"}

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.post(
                url,
                headers=headers,
                data=data,
                auth=aiohttp.BasicAuth(client_id, client_secret),
            ) as resp,
        ):
            if resp.status == 200:
                return TokenStatus.VALID, "credentials validated"
            elif resp.status == 401:
                return TokenStatus.INVALID, "unauthorized — invalid client_id or client_secret"
            else:
                return TokenStatus.ERROR, f"HTTP {resp.status}"
    except aiohttp.ClientError as exc:
        return TokenStatus.ERROR, f"connection error: {exc!r}"
    except Exception as exc:
        return TokenStatus.ERROR, f"unexpected error: {exc!r}"


# ---------------------------------------------------------------------------
# Health check helpers
# ---------------------------------------------------------------------------


def _check_disk_space() -> tuple[bool, str, int]:
    """Check available disk space at the data directory.

    Returns:
        Tuple of (has_sufficient_space, message, available_bytes).
    """
    data_dir = get_data_dir()

    try:
        usage = shutil.disk_usage(data_dir)
        available_gb = usage.free / (1024**3)

        has_sufficient = available_gb >= 1.0

        if available_gb >= 100:
            available_str = f"{available_gb:.0f} GB"
        elif available_gb >= 10:
            available_str = f"{available_gb:.1f} GB"
        else:
            available_str = f"{available_gb:.2f} GB"

        message = f"{available_str} available at {data_dir}"

        return has_sufficient, message, usage.free
    except OSError as exc:
        return False, f"unable to check disk space: {exc}", 0


def _check_permissions() -> list[tuple[str, bool, str]]:
    """Check if config and database files have proper permissions.

    Returns:
        List of (name, is_ok, detail) tuples.
    """
    checks: list[tuple[str, bool, str]] = []

    if "PKGD_CONFIG_PATH" in os.environ:
        config_path = Path(os.environ["PKGD_CONFIG_PATH"])
    else:
        config_path = get_default_config_path()
    if config_path.exists():
        readable = os.access(config_path, os.R_OK)
        writable = os.access(config_path, os.W_OK)
        if readable and writable:
            checks.append(("Config file", True, "read/write OK"))
        elif readable:
            checks.append(("Config file", False, "read-only"))
        else:
            checks.append(("Config file", False, "not readable"))

        try:
            stat_info = config_path.stat()
            mode = stat_info.st_mode & 0o777
            if mode & 0o044:
                checks.append(
                    (
                        "Config permissions",
                        False,
                        f"world-readable (mode {oct(mode)}, recommend 0o600)",
                    )
                )
        except OSError:
            pass
    else:
        checks.append(("Config file", True, "not created yet (OK)"))

    db_path = get_db_path()
    if db_path.exists():
        readable = os.access(db_path, os.R_OK)
        writable = os.access(db_path, os.W_OK)
        if readable and writable:
            checks.append(("Database file", True, "read/write OK"))
        elif readable:
            checks.append(("Database file", False, "read-only"))
        else:
            checks.append(("Database file", False, "not readable"))
    else:
        checks.append(("Database file", True, "not created yet (OK)"))

    data_dir = db_path.parent
    readable = os.access(data_dir, os.R_OK)
    writable = os.access(data_dir, os.W_OK)
    if readable and writable:
        checks.append(("Data directory", True, "read/write OK"))
    elif readable:
        checks.append(("Data directory", False, "read-only"))
    else:
        checks.append(("Data directory", False, "not accessible"))

    return checks


def _get_threat_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Query threat counts grouped by ecosystem.

    Args:
        conn: Database connection (must be open).

    Returns:
        Dict mapping ecosystem name to threat count.
        Empty dict if query fails.
    """
    try:
        cursor = conn.execute("SELECT ecosystem, COUNT(*) as count FROM threats GROUP BY ecosystem")
        return dict(cursor.fetchall())
    except Exception:
        logger.debug("health: threat count query failed")
        return {}


def _get_protection_status(config: PKGDConfig | None) -> dict[str, Any]:
    """Compute protection status summary from configuration.

    Examines critical security flags to determine overall protection level.
    Does NOT use the weakening detection dict (which flags default values).

    Args:
        config: Loaded config object, or None if config couldn't be loaded.

    Returns:
        Dict with:
            level: str — "secure" | "weakened" | "bypass_enabled" | "insecure" | "unknown"
            issues: list[str] — human-readable descriptions of any findings.
    """
    if config is None:
        return {"level": "unknown", "issues": ["Configuration could not be loaded"]}

    issues: list[str] = []

    if config.bypass.command_enabled:
        issues.append("Bypass command is enabled")
    if not config.cooldown.enabled:
        issues.append("Cooldown checking is disabled")
    elif not config.cooldown.strict_mode:
        issues.append("Cooldown strict mode is disabled")
    if not config.fail_on_threat_enabled:
        issues.append("Threat blocking is disabled")

    if not config.fail_on_threat_enabled or not config.cooldown.enabled:
        level = "insecure"
    elif config.bypass.command_enabled:
        level = "bypass_enabled"
    elif issues:
        level = "weakened"
    else:
        level = "secure"

    return {"level": level, "issues": issues}


def _build_coverage_table(threat_counts: dict[str, int]) -> Table:
    """Build a Rich Table showing adapter coverage matrix.

    Args:
        threat_counts: Dict mapping ecosystem to threat count.

    Returns:
        A rich.table.Table ready for console.print().
    """
    from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY
    from pkg_defender.registry.base import CoverageTier

    table = create_table(
        title="[i]Adapter Coverage Matrix[/i]",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Adapter", style="bold")
    table.add_column("Ecosystem")
    table.add_column("Coverage Tier")
    table.add_column("Threat Count")
    table.add_column("Cooldown Status")

    # Deduplicate: multiple manager keys map to same adapter class
    seen_classes: set[type] = set()
    rows: list[tuple[str, str, CoverageTier, int, str]] = []

    for _manager_key, adapter_cls in UNIFIED_MANAGER_REGISTRY.items():
        if adapter_cls in seen_classes:
            continue
        seen_classes.add(adapter_cls)

        adapter = adapter_cls()
        ecosystem = adapter.ecosystem
        tier = adapter.coverage_tier
        threat_count = threat_counts.get(ecosystem, 0)
        cooldown_status = "active" if tier != CoverageTier.AUDIT else "skipped"

        rows.append((adapter.manager_name, ecosystem, tier, threat_count, cooldown_status))

    # Sort: FULL first, PARTIAL second, AUDIT last; alpha within tiers
    tier_order = {CoverageTier.FULL: 0, CoverageTier.PARTIAL: 1, CoverageTier.AUDIT: 2}
    rows.sort(key=lambda r: (tier_order.get(r[2], 99), r[0]))

    # Color coding
    tier_styles = {
        CoverageTier.FULL: "[green]FULL[/]",
        CoverageTier.PARTIAL: "[yellow]PARTIAL[/]",
        CoverageTier.AUDIT: "[red]AUDIT[/]",
    }

    for adapter_name, ecosystem, tier, threat_count, cooldown_status in rows:
        table.add_row(
            adapter_name,
            ecosystem,
            tier_styles[tier],
            str(threat_count),
            cooldown_status,
        )

    return table


async def _health_impl(
    ctx: click.Context,
    output_format: str,
    pretty_output: bool,
    verbose: bool = False,
) -> None:
    """Internal async implementation of health check.

    Args:
        ctx: Click context
        output_format: Output format ("rich" or "json")
        pretty_output: Pretty-print JSON output (when using json format)
        verbose: Show additional diagnostics (coverage matrix, threat counts, feed details)
    """
    json_output = output_format == "json"
    checks: list[tuple[str, bool, str]] = []

    logger = logging.getLogger()
    _original_level = logger.level
    if json_output:
        logger.setLevel(logging.ERROR)

    health_data: dict[str, Any] = {
        "checks": {},
        "feeds": {},
        "tokens": {},
        "disk_space": {},
        "permissions": [],
    }
    all_ok = True

    config_file_ctx = ctx.obj.get("config_file") if ctx.obj else None
    if config_file_ctx:
        config_path = Path(config_file_ctx)
    elif env_path := os.environ.get("PKGD_CONFIG_PATH"):
        config_path = Path(env_path)
    else:
        config_path = get_default_config_path()
    config_ok = config_path.exists()
    checks.append(
        (
            "Config file",
            config_ok,
            str(config_path) if config_ok else "not found (using defaults)",
        )
    )
    logger.debug("Config file: exists=%s, path=%s", config_ok, str(config_path))
    health_data["checks"]["config_file"] = {
        "status": "ok" if config_ok else "fail",
        "path": str(config_path) if config_ok else None,
        "message": str(config_path) if config_ok else "not found (using defaults)",
    }
    if not config_ok:
        all_ok = False

    db_ok = False
    db_msg = ""
    conn: sqlite3.Connection | None = None
    db_path: Path | None = None
    threat_count: int = 0

    # Load config early so it's available for get_connection() PRAGMAs.
    # Wrap in try so a broken config doesn't crash the health check —
    # falls back to None (hardcoded defaults).
    try:
        config = _get_config_from_context(ctx)
    except Exception:
        config = None

    try:
        db_path = get_db_path()
        health_data["checks"]["database"] = {"path": str(db_path)}
        if db_path.exists():
            conn = get_connection(db_path, config=config.database if config is not None else None)
            conn.execute("SELECT 1")
            db_ok = True
            db_msg = str(db_path)
            health_data["checks"]["database"]["status"] = "ok"
            health_data["checks"]["database"]["path"] = str(db_path)
            try:
                count_row = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
                threat_count = int(count_row[0]) if count_row else 0
                health_data["checks"]["database"]["threat_count"] = threat_count
            except Exception:
                logger.debug("health: threat count query failed (database check)")
                health_data["checks"]["database"]["threat_count"] = None
            try:
                sync_row = conn.execute(
                    "SELECT feed_name, last_sync FROM feed_state ORDER BY last_sync DESC LIMIT 1"
                ).fetchone()
                if sync_row:
                    health_data["checks"]["database"]["last_sync"] = sync_row[1]
                    health_data["checks"]["database"]["last_sync_feed"] = sync_row[0]
            except Exception:
                logger.debug("health: last sync query failed")
                pass
        else:
            db_msg = "not found (will be created on first use)"
            health_data["checks"]["database"]["status"] = "not_found"
    except Exception as exc:
        db_msg = str(exc)
        health_data["checks"]["database"]["status"] = "error"
        health_data["checks"]["database"]["error"] = str(exc)
    checks.append(("Database", db_ok, db_msg))
    logger.debug("Database: ok=%s, threat_count=%s", db_ok, threat_count)

    wal_ok = False
    wal_msg = ""
    if db_ok and conn is not None:
        try:
            result = conn.execute("PRAGMA journal_mode").fetchone()
            wal_ok = result is not None and result[0] == "wal"
            wal_msg = result[0] if result else "unknown"
            health_data["checks"]["database"]["wal_mode"] = result[0] if result else None
        except Exception as exc:
            wal_msg = str(exc)
            health_data["checks"]["database"]["wal_mode_error"] = str(exc)
    else:
        wal_msg = "N/A (no database)"
        health_data["checks"]["database"]["wal_mode"] = None
    checks.append(("WAL mode", wal_ok, wal_msg))

    osv_ok = False
    osv_msg = "never synced"
    health_data["feeds"]["osv"] = {"configured": False, "last_sync": None, "status": "unknown"}
    if db_ok and conn is not None:
        try:
            state = get_feed_state(conn, "osv")
            health_data["feeds"]["osv"]["configured"] = True
            if state and state.get("last_sync"):
                osv_ok = True
                osv_msg = f"last synced: {state['last_sync']}"
                health_data["feeds"]["osv"]["last_sync"] = state["last_sync"]
                health_data["feeds"]["osv"]["status"] = state.get("status", "unknown")
            else:
                osv_msg = "never synced"
                health_data["feeds"]["osv"]["status"] = "never_synced"
        except Exception as exc:
            osv_msg = str(exc)
            health_data["feeds"]["osv"]["error"] = str(exc)
    else:
        osv_msg = "N/A (no database)"
    checks.append(("OSV feed", osv_ok, osv_msg))

    feed_checks: list[tuple[str, bool, str, str]] = []
    audit_checks: list[tuple[str, bool, str, str]] = []
    try:
        from pkg_defender.intel.aggregator import OSVFeedAdapter
        from pkg_defender.intel.ghsa import GHSAFeed
        from pkg_defender.intel.mastodon import MastodonFeed
        from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
        from pkg_defender.intel.reddit import RedditFeed
        from pkg_defender.intel.rss_feed import RSSFeed
        from pkg_defender.intel.socket import SocketFeed
        from pkg_defender.intel.x_twitter import XTwitterFeed

        feed_classes: list[tuple[str, type]] = [
            ("osv", OSVFeedAdapter),
            ("ghsa", GHSAFeed),
            ("socket", SocketFeed),
            ("reddit", RedditFeed),
            ("rss", RSSFeed),
            ("mastodon", MastodonFeed),
            ("x_twitter", XTwitterFeed),
        ]

        audit_sources_list: list[tuple[str, type]] = [
            ("npm_advisory", NpmAdvisoryFeed),
        ]

        for feed_name, feed_cls in feed_classes:
            try:
                feed_instance = feed_cls()
                is_configured = feed_instance.is_configured(config)

                last_sync = "never"
                sync_status = "N/A"
                if db_ok and conn is not None:
                    try:
                        state = get_feed_state(conn, feed_name)
                        if state:
                            ls = state.get("last_sync")
                            if ls:
                                last_sync = ls[:19]
                            sync_status = state.get("status", "unknown") or "unknown"
                    except Exception:
                        logger.debug("health: feed state query failed for %s", feed_name)
                        pass

                if not is_configured:
                    sync_status = "not configured"

                feed_checks.append((feed_name, is_configured, last_sync, sync_status))
            except Exception:
                logger.debug("health: feed config load failed for %s", feed_name)
                feed_checks.append((feed_name, False, "error", "config load failed"))

        for feed_name, feed_cls in audit_sources_list:
            try:
                feed_instance = feed_cls()
                is_configured = feed_instance.is_configured(config)

                last_sync = "not configured"
                sync_status = "N/A"
                if db_ok and conn is not None:
                    try:
                        state = get_feed_state(conn, feed_name)
                        if state:
                            ls = state.get("last_sync")
                            if ls:
                                last_sync = ls[:19]
                            sync_status = state.get("status", "unknown") or "unknown"
                    except Exception:
                        logger.debug("health: audit source state query failed for %s", feed_name)
                        pass

                if not is_configured:
                    sync_status = "not configured"

                audit_checks.append((feed_name, is_configured, last_sync, sync_status))
            except Exception:
                logger.debug("health: audit source config load failed for %s", feed_name)
                audit_checks.append((feed_name, False, "error", "config load failed"))
    except Exception:
        logger.debug("health: outer feed/source enumeration failed")
        pass

    logger.debug("Feeds: %s threat feeds, %s audit sources", len(feed_checks), len(audit_checks))

    token_checks: list[tuple[str, str, str, str]] = []

    logger.debug("Token validation: %s checks to run", 3 if config is not None else 0)

    if config is not None:
        # Run all 4 token validators concurrently via gather.
        # return_exceptions=True ensures one failure doesn't orphan other coroutines
        # and doesn't propagate — each result is checked individually.
        token_results = await asyncio.gather(
            _validate_github_token(config.feeds.ghsa_token),
            _validate_socket_token(config.feeds.socket_api_key),
            _validate_x_twitter_token(config.feeds.x_twitter_bearer_token),
            _validate_reddit_credentials(
                config.feeds.reddit_client_id,
                config.feeds.reddit_client_secret,
            ),
            return_exceptions=True,
        )

        # Extract results, handling both normal returns and exceptions
        def _extract(idx: int, default: tuple[str, str]) -> tuple[str, str]:
            r = token_results[idx]
            if isinstance(r, BaseException):
                return default
            assert isinstance(r, tuple) and len(r) == 2
            return r

        gh_status, gh_msg = _extract(0, (TokenStatus.ERROR, "validation failed"))
        socket_status, socket_msg = _extract(1, (TokenStatus.ERROR, "validation failed"))
        xtwitter_status, xtwitter_msg = _extract(2, (TokenStatus.ERROR, "validation failed"))
        reddit_status, reddit_msg = _extract(3, (TokenStatus.ERROR, "validation failed"))

        # GitHub dual-source awareness
        if gh_status == TokenStatus.VALID and not os.environ.get("PKGD_GITHUB_TOKEN"):
            gh_msg += " (set PKGD_GITHUB_TOKEN env var to override config for TimestampResolver)"

        # Libraries.io key: presence-only check, no API call
        libraries_io_key = os.environ.get("PKGD_LIBRARIES_IO_KEY")
        libraries_io_configured = bool(libraries_io_key)
        libraries_io_status = TokenStatus.VALID if libraries_io_configured else TokenStatus.NOT_CONFIGURED
        libraries_io_msg = "key present" if libraries_io_configured else "not configured (optional)"

        token_checks = [
            ("ghsa", "GitHub (GHSA)", gh_status, gh_msg),
            ("socket", "Socket.dev", socket_status, socket_msg),
            ("x_twitter", "X/Twitter", xtwitter_status, xtwitter_msg),
            ("reddit", "Reddit", reddit_status, reddit_msg),
            ("libraries_io", "Libraries.io", libraries_io_status, libraries_io_msg),
        ]
    else:
        token_checks = [
            ("ghsa", "GitHub (GHSA)", TokenStatus.NOT_CONFIGURED, "config not available"),
            ("socket", "Socket.dev", TokenStatus.NOT_CONFIGURED, "config not available"),
            ("x_twitter", "X/Twitter", TokenStatus.NOT_CONFIGURED, "config not available"),
            ("reddit", "Reddit", TokenStatus.NOT_CONFIGURED, "config not available"),
            ("libraries_io", "Libraries.io", TokenStatus.NOT_CONFIGURED, "config not available"),
        ]

    disk_ok, disk_msg, available_bytes = _check_disk_space()

    permission_checks = _check_permissions()

    unconfigured_feeds = [name for name, is_configured, _, _ in feed_checks if not is_configured]
    unconfigured_sources = [name for name, is_configured, _, _ in audit_checks if not is_configured]

    # Suppress health dashboard output in quiet mode (keep JSON)
    if is_quiet_mode() and not json_output:
        if conn is not None:
            conn.close()
        if not all_ok:
            raise SystemExit(_EXIT_GENERAL_ERROR)
        return

    # Re-evaluate all_ok for comprehensive checks (always, regardless of format)
    all_ok = True
    for _name, ok, _detail in checks:
        if not ok:
            all_ok = False

    if not json_output:
        table = create_table(title="[i]System Health[/i]", show_header=True, header_style="italic")
        table.add_column("Check", style="bold")
        table.add_column("Status")
        table.add_column("Details")

        for name, ok, detail in checks:
            icon = "[green]OK[/]" if ok else "[red]FAIL[/]"
            table.add_row(name, icon, detail)

        click.echo()
        stdout_console.print(table)

    if feed_checks:
        if not json_output:
            click.echo()

        feed_table = create_table(
            title=Text("Intelligence Feed Health", justify="center", style="italic"),
            show_header=True,
            header_style="italic",
        )
        feed_table.add_column("Feed", style="bold")
        feed_table.add_column("Configured")
        feed_table.add_column("Last Sync")
        feed_table.add_column("Status")

        for feed_name, is_configured, last_sync, sync_status in feed_checks:
            configured_icon = "[green]yes[/]" if is_configured else "[red]no[/]"

            if sync_status == "idle":
                status_display = "[green]idle[/]"
            elif sync_status == "error":
                status_display = "[red]error[/]"
            elif sync_status == "syncing":
                status_display = "[yellow]syncing[/]"
            else:
                status_display = sync_status

            feed_table.add_row(feed_name, configured_icon, last_sync, status_display)

        if not json_output:
            stdout_console.print(feed_table)

    if audit_checks:
        if not json_output:
            click.echo()

        audit_table = create_table(
            title=Text("Audit Sources", justify="center", style="italic"),
            show_header=True,
            header_style="italic",
        )
        audit_table.add_column("Source", style="bold")
        audit_table.add_column("Configured")
        audit_table.add_column("Last Sync")
        audit_table.add_column("Status")

        for feed_name, is_configured, last_sync, sync_status in audit_checks:
            configured_icon = "[green]yes[/]" if is_configured else "[red]no[/]"

            if sync_status == "idle":
                status_display = "[green]idle[/]"
            elif sync_status == "error":
                status_display = "[red]error[/]"
            elif sync_status == "syncing":
                status_display = "[yellow]syncing[/]"
            else:
                status_display = sync_status

            audit_table.add_row(feed_name, configured_icon, last_sync, status_display)

        if not json_output:
            stdout_console.print(audit_table)

    if token_checks:
        if not json_output:
            click.echo()

        token_table = create_table(
            title=Text("API Token Status", justify="center", style="italic"),
            show_header=True,
            header_style="italic",
        )
        token_table.add_column("Service", style="bold")
        token_table.add_column("Status")
        token_table.add_column("Details")

        for _machine_name, token_name, status, message in token_checks:
            if status == TokenStatus.VALID:
                status_icon = "[green]Valid \u2705[/green]"
            elif status == TokenStatus.EXPIRED:
                status_icon = "[red]Expired \u274c[/red]"
            elif status == TokenStatus.INVALID:
                status_icon = "[red]Invalid \u274c[/red]"
            elif status == TokenStatus.NOT_CONFIGURED:
                status_icon = "[dim]Not configured \u26aa[/dim]"
            else:
                status_icon = f"[yellow]Error \u26a0[/yellow] ({message})"

            token_table.add_row(token_name, status_icon, message)

        if not json_output:
            stdout_console.print(token_table)

    if not json_output:
        click.echo()

    disk_table = create_table(
        title=Text("Disk Space", justify="center", style="italic"),
        show_header=True,
        header_style="italic",
    )
    disk_table.add_column("Check", style="bold")
    disk_table.add_column("Status")
    disk_table.add_column("Details")

    if disk_ok:
        disk_table.add_row("Data directory", "[green]OK[/]", disk_msg)
    else:
        disk_table.add_row(
            "Data directory",
            "[yellow]low space[/]",
            f"{disk_msg} (consider freeing up space)",
        )

    if not json_output:
        stdout_console.print(disk_table)

    if not json_output:
        click.echo()

    perms_table = create_table(
        title=Text("File Permissions", justify="center", style="italic"),
        show_header=True,
        header_style="italic",
    )
    perms_table.add_column("Path", style="bold")
    perms_table.add_column("Status")
    perms_table.add_column("Details")

    for path_name, is_ok, detail in permission_checks:
        status_icon = "[green]OK[/]" if is_ok else "[red]FAIL[/]"
        perms_table.add_row(path_name, status_icon, detail)
        if not is_ok:
            all_ok = False

    if not json_output:
        stdout_console.print(perms_table)

    # -- Verbose output: coverage matrix --
    if verbose and conn is not None:
        _threat_counts = _get_threat_counts(conn)
        _coverage_table = _build_coverage_table(_threat_counts)
        if not json_output:
            click.echo()
            stdout_console.print(_coverage_table)

    # -- Verbose output: feed implementations and timestamp sources --
    if verbose:
        if not json_output:
            click.echo()
            stdout_console.print("[bold]Feed Implementations:[/bold]")
        from pkg_defender.intel import FEED_REGISTRY

        _config_for_feeds = _get_config_from_context(ctx)
        _all_feeds = list(FEED_REGISTRY.keys()) + ["homebrew"]
        _active_count = 0
        _api_key_count = 0
        _disabled_count = 0
        for _feed_name in _all_feeds:
            _feed_cls = FEED_REGISTRY.get(_feed_name)
            _is_implemented = _feed_cls is not None
            _needs_api_key = _feed_name in ("mastodon", "reddit", "x_twitter")
            _is_disabled = (
                not _is_implemented
                or (_feed_name == "socket" and not _config_for_feeds.feeds.socket_enabled)
                or (_feed_name == "ossf_malicious" and not _config_for_feeds.feeds.ossf_malicious_enabled)
            )
            if _is_implemented and not _needs_api_key and not _is_disabled:
                _status_icon = "[green]\u2713[/green]"
                _status_label = "active"
                _active_count += 1
            elif _needs_api_key:
                _status_icon = "[yellow]\u26a0[/yellow]"
                _status_label = "needs API key"
                _api_key_count += 1
            else:
                _status_icon = "[red]\u2717[/red]"
                _status_label = "disabled"
                _disabled_count += 1
            if not json_output:
                stdout_console.print(f"  {_status_icon} {_feed_name} ({_status_label})")

        if not json_output:
            _summary = (
                f"\n  [dim]Active: {_active_count} | "
                f"Needs API Key: {_api_key_count} | Disabled: {_disabled_count}[/dim]"
            )
            stdout_console.print(_summary)

        # Timestamp sources
        if not json_output:
            click.echo()
            stdout_console.print("[bold]Timestamp Sources:[/bold]")
        from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY

        _proxied: list[str] = []
        _verified: list[str] = []
        if "brew" in UNIFIED_MANAGER_REGISTRY:
            _proxied.append("homebrew (GitHub Releases/Tags → Libraries.io)")
        for _eco in ["npm", "pypi", "cargo", "rubygems"]:
            if _eco in UNIFIED_MANAGER_REGISTRY:
                _verified.append(f"{_eco} (registry API)")
        for _eco in _verified:
            if not json_output:
                stdout_console.print(f"  [green]\u2713[/green] {_eco}")
        for _eco in _proxied:
            if not json_output:
                stdout_console.print(f"  [yellow]\u26a0[/yellow] {_eco}")

    if unconfigured_feeds or unconfigured_sources:
        if not json_output:
            click.echo()
        unconfigured_items = unconfigured_feeds + unconfigured_sources
        items_list = ", ".join(f"[bold][yellow]{name}[/yellow][/bold]" for name in unconfigured_items)
        verb = "is" if len(unconfigured_items) == 1 else "are"
        help_tip = Text.from_markup(
            f"\U0001f4a1 [bold]Helpful Tip:[/bold]\nIt looks like {items_list} {verb} not configured yet."
            " Run [cyan]pkgd setup[/cyan] to configure.\n",
            justify="left",
        )
        if not json_output:
            console.print(help_tip)

    if output_format == "json":
        for feed_name, is_configured, last_sync, sync_status in feed_checks:
            health_data["feeds"][feed_name] = {
                "configured": is_configured,
                "last_sync": last_sync if last_sync != "never" else None,
                "status": sync_status,
            }

        for feed_name, is_configured, last_sync, sync_status in audit_checks:
            health_data["feeds"][feed_name] = {
                "configured": is_configured,
                "last_sync": last_sync if last_sync != "not configured" else None,
                "status": sync_status,
            }

        for machine_name, display_name, status, message in token_checks:
            status_str = "unknown"
            if status == TokenStatus.VALID:
                status_str = "valid"
            elif status == TokenStatus.EXPIRED:
                status_str = "expired"
            elif status == TokenStatus.INVALID:
                status_str = "invalid"
            elif status == TokenStatus.NOT_CONFIGURED:
                status_str = "not_configured"
            else:
                status_str = "error"

            health_data["tokens"][machine_name] = {
                "label": display_name,
                "status": status_str,
                "message": message,
            }

        health_data["disk_space"] = {
            "sufficient": disk_ok,
            "message": disk_msg,
            "available_bytes": available_bytes,
        }

        health_data["permissions"] = [
            {"path": name, "ok": is_ok, "detail": detail} for name, is_ok, detail in permission_checks
        ]

        # -- Protection status (config weakening analysis) --
        health_data["protection"] = _get_protection_status(config)

        # -- Daemon status (always, for Docker HEALTHCHECK) --
        health_data["daemon"] = {"status": "unknown"}
        try:
            from pkg_defender.config.settings import get_data_dir
            from pkg_defender.daemon.runner import is_daemon_running

            daemon_running = is_daemon_running(get_data_dir())
            health_data["daemon"] = {"status": "running" if daemon_running else "stopped"}
        except Exception:
            logger.debug("health: daemon status check failed", exc_info=True)

        # -- Active bypass count --
        health_data["active_bypasses"] = {"count": 0}
        if conn is not None:
            try:
                _row = conn.execute(
                    "SELECT COUNT(*) FROM bypasses WHERE expires_at IS NULL OR expires_at >= datetime('now')"
                ).fetchone()
                if _row is not None:
                    health_data["active_bypasses"]["count"] = int(_row[0])
            except Exception:
                logger.debug("health: active bypass count query failed", exc_info=True)
                health_data["active_bypasses"]["count"] = 0

        # -- Ecosystem threat counts (always present, not just verbose) --
        health_data["ecosystem_threats"] = {}
        if conn is not None:
            try:
                health_data["ecosystem_threats"] = _get_threat_counts(conn)
            except Exception:
                logger.debug("health: ecosystem threat count query failed", exc_info=True)
                health_data["ecosystem_threats"] = {}

        if verbose and conn is not None:
            from pkg_defender.registry import UNIFIED_MANAGER_REGISTRY

            _json_threat_counts = _get_threat_counts(conn)
            _json_coverage_data: list[dict[str, Any]] = []
            _json_seen_classes: set[type] = set()
            for _manager_key, _adapter_cls in UNIFIED_MANAGER_REGISTRY.items():
                if _adapter_cls in _json_seen_classes:
                    continue
                _json_seen_classes.add(_adapter_cls)
                _adapter = _adapter_cls()
                _eco = _adapter.ecosystem
                _tier = _adapter.coverage_tier
                _json_coverage_data.append(
                    {
                        "adapter": _adapter.manager_name,
                        "ecosystem": _eco,
                        "coverage_tier": _tier.value,
                        "threat_count": _json_threat_counts.get(_eco, 0),
                        "cooldown_status": "active" if _tier.value != "audit" else "skipped",
                    }
                )
            health_data["coverage"] = _json_coverage_data

        health_data["ready"] = all_ok
        health_data["timestamp"] = datetime.now(UTC).isoformat()

        click.echo(format_json(health_data, pretty_output), nl=False)
        if conn is not None:
            conn.close()
        if not all_ok:
            raise SystemExit(_EXIT_GENERAL_ERROR)
        return

    if conn is not None:
        conn.close()

    if not all_ok:
        raise SystemExit(_EXIT_GENERAL_ERROR)
