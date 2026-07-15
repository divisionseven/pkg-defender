# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Display utilities for CLI output using Rich.

Provides block message rendering for all 5 defender scenarios:
1. Cooldown block — version too new
2. Threat block — known threat match
3. Both block — too new AND has threats
4. Allowed install — passes all checks
5. Stale DB warning — threat database is outdated

Also provides JSON output formatting utilities.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from rich.box import ASCII as _ASCII_BOX
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from pkg_defender.models import PackageAuditResult, ScoredThreat

from pkg_defender.models import CooldownResult

# Module-level console — default for all display functions.
# Respects NO_COLOR env var.
_console: Console | None = None

# Module-level quiet mode flag — suppresses non-error output
_quiet_mode: bool = False

# Module-level ASCII mode flag — forces ASCII-only output
_ascii_mode: bool = False


def create_table(*args: Any, **kwargs: Any) -> Table:
    """Create a Rich Table, using ASCII borders in ASCII mode.

    When ``_ascii_mode`` is enabled and no explicit ``box=`` kwarg was
    passed, injects ``box=ASCII``. Explicit ``box=None`` (no borders) is
    preserved — that's an intentional choice, not a default.

    Args:
        *args: Positional args forwarded to ``rich.table.Table``.
        **kwargs: Keyword args forwarded to ``rich.table.Table``.

    Returns:
        A ``rich.table.Table`` instance.
    """
    if _ascii_mode and "box" not in kwargs:
        kwargs["box"] = _ASCII_BOX
    return Table(*args, **kwargs)


def set_ascii_mode(ascii: bool) -> None:
    """Enable or disable ASCII mode.

    Args:
        ascii: If True, use ASCII text instead of Unicode icons.
    """
    global _ascii_mode
    _ascii_mode = ascii


def is_ascii_mode() -> bool:
    """Check if ASCII mode is enabled.

    Returns:
        True if ASCII mode is enabled, False otherwise.
    """
    return _ascii_mode


def _get_console() -> Console:
    """Return the module-level console, creating it if needed.

    Uses stderr for all output to avoid polluting stdout.
    This allows: pkgd install pkg --json > output.json
    while still showing progress/status messages.
    """
    global _console
    if _console is None:
        no_color = os.environ.get("NO_COLOR") is not None
        _console = Console(stderr=True, no_color=no_color)
    return _console


def set_no_color() -> None:
    """Honor NO_COLOR env var by disabling Rich color output."""
    global _console
    _console = Console(stderr=True, no_color=True)


def set_quiet_mode(quiet: bool) -> None:
    """Enable or disable quiet mode.

    Args:
        quiet: If True, suppress non-error output.
    """
    global _quiet_mode
    _quiet_mode = quiet


def is_quiet_mode() -> bool:
    """Check if quiet mode is enabled.

    Returns:
        True if quiet mode is enabled, False otherwise.
    """
    return _quiet_mode


_verbose_mode: bool = False


def set_verbose_mode(verbose: bool) -> None:
    """Enable or disable verbose mode.

    Args:
        verbose: If True, enable detailed output.
    """
    global _verbose_mode
    _verbose_mode = verbose


def is_verbose_mode() -> bool:
    """Check if verbose mode is enabled.

    Returns:
        True if verbose mode is enabled, False otherwise.
    """
    return _verbose_mode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "UNKNOWN": "dim",
}


def severity_color(severity: str) -> str:
    """Return the Rich style string for a threat severity level.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.

    Returns:
        Rich style string (e.g. "bold red", "yellow", "dim").
    """
    return SEVERITY_COLORS.get(severity, "dim")


_SOURCE_BADGES: dict[str, str] = {
    "osv": "[OSV]",
    "ghsa": "[GHSA]",
    "socket": "[SOCKET]",
    "npm": "[NPM]",
    "pypi": "[PYPI]",
    "rustsec": "[RUSTSEC]",
    "mastodon": "[MASTODON]",
    "reddit": "[REDDIT]",
    "x_twitter": "[X]",
}

_SOURCE_COLORS: dict[str, str] = {
    "osv": "cyan",
    "ghsa": "magenta",
    "socket": "green",
    "npm": "yellow",
    "pypi": "blue",
    "rustsec": "red",
    "mastodon": "bright_black",
    "reddit": "bright_black",
    "x_twitter": "bright_black",
}


def _source_badge(source: str) -> str:
    """Return a bracketed badge string for a threat source.

    Args:
        source: Source identifier (e.g. "osv", "ghsa", "socket").

    Returns:
        Bracketed badge string like ``[OSV]`` or ``[GHSA]``.
    """
    return _SOURCE_BADGES.get(source, f"[{source.upper()}]")


def _source_color(source: str) -> str:
    """Return a Rich-compatible colour name for a threat source.

    Args:
        source: Source identifier (e.g. "osv", "ghsa", "socket").

    Returns:
        Rich colour string.
    """
    return _SOURCE_COLORS.get(source, "white")


def humanize_timedelta(td: timedelta) -> str:
    """Return a human-readable string for a timedelta.

    Args:
        td: The time delta to format.

    Returns:
        Human-readable string like "2 hours", "1 day 3 hours", "45 minutes".
    """
    total_seconds = int(td.total_seconds())
    if total_seconds < 0:
        return "0 seconds"
    if total_seconds == 0:
        return "0 seconds"

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0 and not parts:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return " ".join(parts)


def _severity_icon(severity: str) -> str:
    """Return a text icon for a severity level.

    Args:
        severity: One of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.

    Returns:
        Unicode emoji or ASCII text representation based on mode.
    """
    if _ascii_mode:
        return {
            "CRITICAL": "[!!!!]",
            "HIGH": "[!!!]",
            "MEDIUM": "[!!]",
            "LOW": "[!]",
            "UNKNOWN": "[?]",
        }.get(severity, "[?]")
    return {
        "CRITICAL": "\U0001f6a8",  # 🚨
        "HIGH": "\u26a0",  # ⚠
        "MEDIUM": "\u25cf",  # ●
        "LOW": "\u2139",  # ℹ
    }.get(severity, "\u2753")  # ❓


# ---------------------------------------------------------------------------
# Block message functions
# ---------------------------------------------------------------------------


def display_cooldown_block(
    package: str,
    version: str,
    result: CooldownResult,
    console: Console | None = None,
) -> None:
    """Scenario 1: Cooldown-only block.

    Shows: package@version, age, remaining time, safe version, bypass hint.
    Also shows the date source (verified, proxied, or missing).

    Args:
        package: Package name.
        version: Package version.
        result: CooldownResult from the cooldown engine.
        console: Optional Rich Console for testability.
    """
    con = console or _get_console()

    age_str = humanize_timedelta(result.age) if result.age else "unknown"
    remaining_str = humanize_timedelta(result.remaining) if result.remaining else "unknown"

    body = Text()
    body.append("Package: ", style="bold")
    body.append(f"{package}@{version}\n")

    # Show date source honestly — use SOURCE_TRUST_MAP as single source of truth
    date_source = result.date_source
    from pkg_defender.db.schema import SOURCE_TRUST_MAP  # single source of truth

    trust_level = SOURCE_TRUST_MAP.get(date_source or "", "unknown")
    if trust_level == "verified":
        source_label = "verified timestamp" if _ascii_mode else "\u2713 verified timestamp"
    elif trust_level == "proxied":
        source_label = "PROXIED" if _ascii_mode else "\u26a0 proxied timestamp"
    elif trust_level == "claimed":
        source_label = "claimed timestamp" if _ascii_mode else "\u2717 claimed timestamp"
    else:
        source_label = "no timestamp source" if _ascii_mode else "\u2717 no timestamp source"

    body.append("Cooldown: ", style="bold")
    body.append(f"{result.effective_cooldown_days or 1} day(s) {source_label}\n")

    # Extended penalty messaging for claimed timestamps
    if trust_level == "claimed" and not result.allowed:
        if _ascii_mode:
            body.append("[PKGD] Maintainer-claimed timestamp - +2 day cooldown penalty applied\n", style="yellow")
        else:
            body.append("Maintainer-claimed timestamp \u2014 +2 day cooldown penalty applied\n", style="yellow")

    body.append("Age: ", style="bold")
    body.append(f"{age_str} old\n")
    body.append("Cooldown remaining: ", style="bold")
    body.append(f"{remaining_str}\n")

    if result.publish_time:
        clears_at = result.publish_time + timedelta(days=result.effective_cooldown_days or 1)
        body.append("Clears at: ", style="bold")
        body.append(f"{clears_at.strftime('%Y-%m-%d %H:%M UTC')}\n")

    if result.safe_version:
        body.append("Safe version: ", style="bold green")
        body.append(f"{result.safe_version}\n")

    body.append("\n")
    body.append("Use --bypass to override (not recommended)", style="dim italic")

    con.print(
        Panel(
            body,
            title="\u274c Cooldown Block",
            title_align="left",
            border_style="red",
            expand=False,
        )
    )


def display_threat_block(
    package: str,
    version: str,
    threats: list[ScoredThreat],
    console: Console | None = None,
) -> None:
    """Scenario 2: Threat-only block.

    Shows: threat table with severity, source, summary, detail URL.

    Args:
        package: Package name.
        version: Package version.
        threats: List of scored threats.
        console: Optional Rich Console for testability.
    """
    con = console or _get_console()

    highest = max(threats, key=lambda t: t.final_score) if threats else None
    highest_severity = highest.display_severity if highest else "UNKNOWN"

    body_text = Text()
    body_text.append("Package: ", style="bold")
    body_text.append(f"{package}@{version}\n")
    body_text.append("Highest severity: ", style="bold")
    body_text.append(f"{highest_severity}\n", style=severity_color(highest_severity))

    con.print(
        Panel(
            body_text,
            title="\U0001f6a8 Threat Block",
            title_align="left",
            border_style=severity_color(highest_severity),
            expand=False,
        )
    )

    table = create_table(show_header=True, header_style="italic", box=None, padding=(0, 1))
    table.add_column("Severity", style="bold")
    table.add_column("Source")
    table.add_column("Summary", max_width=40)
    table.add_column("Match")
    table.add_column("Details")

    for scored in threats:
        rec = scored.record
        sev_style = severity_color(scored.display_severity)
        table.add_row(
            Text(
                f"{_severity_icon(scored.display_severity)} {scored.display_severity}",
                style=sev_style,
            ),
            Text(rec.source),
            Text(rec.summary[:40] if rec.summary else "—"),
            Text(scored.version_match_type),
            Text(rec.detail_url or "—"),
        )

    con.print(table)

    bypass_hint = Text("\nUse --bypass to override (not recommended)", style="dim italic")
    con.print(bypass_hint)


def display_both_block(
    package: str,
    version: str,
    cooldown: CooldownResult,
    threats: list[ScoredThreat],
    console: Console | None = None,
) -> None:
    """Scenario 3: Both cooldown and threat blocks.

    Shows: threats first, then cooldown info in a combined panel.

    Args:
        package: Package name.
        version: Package version.
        cooldown: CooldownResult from the cooldown engine.
        threats: List of scored threats.
        console: Optional Rich Console for testability.
    """
    con = console or _get_console()

    highest = max(threats, key=lambda t: t.final_score) if threats else None
    highest_severity = highest.display_severity if highest else "UNKNOWN"

    # Threat section
    body = Text()
    body.append("Package: ", style="bold")
    body.append(f"{package}@{version}\n\n")
    body.append("── Threats ──────────────────────────\n", style="bold red")
    body.append("Highest severity: ", style="bold")
    body.append(f"{highest_severity}\n", style=severity_color(highest_severity))

    for scored in threats:
        rec = scored.record
        sev_style = severity_color(scored.display_severity)
        body.append(f"  {_severity_icon(scored.display_severity)} ", style=sev_style)
        body.append(scored.display_severity, style=sev_style)
        body.append(f" — {rec.summary[:50] if rec.summary else 'No summary'}\n")
        body.append(f"    Source: {rec.source}")
        if rec.detail_url:
            body.append(f"  |  [link={rec.detail_url}]{rec.detail_url}[/link]")
        body.append("\n")

    # Cooldown section
    body.append("\n── Cooldown ─────────────────────────\n", style="bold yellow")
    age_str = humanize_timedelta(cooldown.age) if cooldown.age else "unknown"
    remaining_str = humanize_timedelta(cooldown.remaining) if cooldown.remaining else "unknown"
    body.append("Age: ", style="bold")
    body.append(f"{age_str} old\n")
    body.append("Cooldown remaining: ", style="bold")
    body.append(f"{remaining_str}\n")

    if cooldown.safe_version:
        body.append("Safe version: ", style="bold green")
        body.append(f"{cooldown.safe_version}\n")

    body.append("\n")
    body.append("Use --bypass to override (not recommended)", style="dim italic")

    con.print(
        Panel(
            body,
            title="\u274c\U0001f6a8 Both Cooldown + Threat Block",
            title_align="left",
            border_style="bold red",
            expand=False,
        )
    )


def display_allowed(
    package: str,
    version: str,
    console: Console | None = None,
    force_display: bool = False,
) -> None:
    """Scenario 4: Package passes all checks.

    Shows: green panel confirming the package is safe to install.

    By default, produces no output (Unix convention for successful operations).
    Use force_display=True to always show the success message.

    Args:
        package: Package name.
        version: Package version.
        console: Optional Rich Console for testability.
        force_display: If True, show the success panel even in non-verbose mode.
    """
    # SILENCE ON SUCCESS: Don't print anything by default
    # Only show output if force_display=True or quiet mode is disabled
    if _quiet_mode:
        return
    if not force_display:
        return

    con = console or _get_console()

    body = Text()
    body.append("Package: ", style="bold")
    body.append(f"{package}@{version}\n")
    body.append("Status: ", style="bold")
    body.append("Package passed all checks \u2714\n", style="green")

    con.print(
        Panel(
            body,
            title="\u2705 Allowed",
            title_align="left",
            border_style="green",
            expand=False,
        )
    )


def display_stale_db_warning(
    last_sync: datetime | None,
    console: Console | None = None,
) -> None:
    """Scenario 5: Stale DB warning banner.

    Shows: yellow warning about outdated threat database.

    Args:
        last_sync: Datetime of the last successful sync, or None if never synced.
        console: Optional Rich Console for testability.
    """
    # Suppress in quiet mode — informational warning, not an error
    if _quiet_mode:
        return

    con = console or _get_console()

    if last_sync is None:
        sync_age = "never synced"
    else:
        delta = datetime.now(tz=last_sync.tzinfo) - last_sync
        sync_age = f"{humanize_timedelta(delta)} ago"

    warning = Text()
    warning.append(
        f"\u26a0 Threat database is stale (last sync: {sync_age}). "
        "This may lead to missed threats or inaccurate cooldowns.\n\n",
        style="bold yellow",
    )
    warning.append(
        "Run `pkgd intel sync` to update.",
        style="yellow",
    )

    con.print(
        Panel(
            warning,
            border_style="yellow",
            expand=False,
        )
    )


# ── Resolver warning messages ────────────────────────────────────────

# Maps error codes (from ``TimestampResolver.get_session_errors()``) to
# user-facing Rich markup messages displayed in a yellow Panel.
# Extend this dict when new error codes are added to ``_fetch_json()``.
RESOLVER_ERROR_MESSAGES: dict[str, str] = {
    "rate_limited": (
        "GitHub timestamp lookup is unavailable \u2014 no GitHub token configured.\n"
        "This may cause timestamps to be less accurate for some packages.\n\n"
        "To fix: Configure [bold]ghsa_token[/bold] under [bold][feeds][/bold] in\n"
        "your [bold]pkgd.toml[/bold], or set [bold]PKGD_GITHUB_TOKEN[/bold] in\n"
        "your environment with a GitHub personal access token\n"
        "([bold]public_repo[/bold] scope).\n"
        "Create one at: https://github.com/settings/tokens"
    ),
}


def display_resolver_warning(errors: set[str], console: Console | None = None) -> None:
    """Show a user-facing warning about resolver degradation.

    Builds a Rich Panel on stderr from the collected error codes.
    Each error code in *errors* is looked up in ``RESOLVER_ERROR_MESSAGES``
    and rendered as a paragraph in the panel.

    Called only in interactive mode (the dispatcher routes to plain text
    for CI mode before calling this function).

    Args:
        errors: Set of error codes collected during the session (e.g.,
            ``{"rate_limited"}``).
        console: Optional Rich Console for testability. Defaults to
            the module-level stderr console.
    """
    if _quiet_mode:
        return

    con = console or _get_console()

    messages: list[str] = []
    for error in errors:
        msg = RESOLVER_ERROR_MESSAGES.get(error)
        if msg:
            messages.append(msg)

    if not messages:
        return

    panel = Panel(
        "\n\n".join(messages),
        title="[yellow]Timestamp Resolution Notice[/yellow]",
        border_style="yellow",
    )
    con.print(panel)


def display_audit_results(
    result: PackageAuditResult,
    console: Console | None = None,
    verbose: bool = False,
    passed_packages: list[dict[str, str]] | None = None,
) -> None:
    """Display audit results as a Rich table with summary footer.

    Args:
        result: PackageAuditResult from the auditor.
        console: Optional Rich Console for testability.
        verbose: If True, show all packages line-by-line instead of condensed.
        passed_packages: Optional list of passed package dicts with 'package',
            'version', 'ecosystem' keys. If provided, used for verbose mode.
    """
    con = console or _get_console()

    table = create_table(
        title="[i]Audit Results[/i]",
        show_header=True,
        header_style="italic",
        show_lines=True,
    )
    table.add_column("Package", style="bold")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Details")

    # Threat entries (always shown individually)
    for threat_entry in result.threats:
        highest = max(threat_entry.threats, key=lambda t: t.final_score) if threat_entry.threats else None
        sev = highest.display_severity if highest else "UNKNOWN"
        sev_style = severity_color(sev)

        # Build multiline details text
        details_lines: list[Text | str] = []
        for i, st in enumerate(threat_entry.threats):
            rec = st.record
            if i > 0:
                details_lines.append("")  # blank line between threats

            # Source badge with colour
            source_badge = _source_badge(rec.source)

            # Line 1: [source_badge] SEVERITY — summary (version_match_info)
            version_tag = {
                "exact": f"v{threat_entry.version}",
                "range": "range match",
                "package_wide": "all versions",
            }.get(st.version_match_type, st.version_match_type)
            line1 = Text()
            line1.append(f"{source_badge} ", style=f"bold {_source_color(rec.source)}")
            line1.append(f"{_severity_icon(st.display_severity)} ", style=sev_style)
            line1.append(f"{st.display_severity}", style=sev_style)
            line1.append(f" — {rec.summary or 'No summary'} ({version_tag})")
            details_lines.append(line1)

            # Line 2: Reported: YYYY-MM-DD
            if rec.published_at:
                details_lines.append(f"  Reported: {rec.published_at.strftime('%Y-%m-%d')}")

            # Line 3: detail_url (if available)
            if rec.detail_url:
                details_lines.append(f"  {rec.detail_url}")

        details = Text("\n".join(str(part) for part in details_lines)) if details_lines else Text("—")

        table.add_row(
            Text(threat_entry.package),
            Text(threat_entry.version),
            Text(threat_entry.lock_file, style="dim"),
            Text(f"{_severity_icon(sev)} {sev}", style=sev_style),
            details,
        )

    # Cooldown entries (always shown individually)
    for cd_entry in result.cooldown_pending:
        age_str = humanize_timedelta(cd_entry.age)
        table.add_row(
            Text(cd_entry.package),
            Text(cd_entry.version),
            Text(cd_entry.lock_file, style="dim"),
            Text("\u23f3 Cooldown", style="yellow"),
            f"{age_str} old, clears at {cd_entry.clears_at.strftime('%Y-%m-%d %H:%M')}",
        )

    # Passed entries
    passed_count = result.passed
    if verbose and passed_packages:
        # Show each passed package individually
        for pkg in passed_packages:
            table.add_row(
                Text(pkg["package"]),
                Text(pkg["version"]),
                "",  # Source column (empty for passed)
                Text("\u2705 OK", style="green"),
                "Passed all checks",
            )
    elif passed_count > 0:
        # Condensed view
        table.add_row(
            f"[{passed_count} other packages]",
            "—",
            "",  # Source column (empty for passed)
            Text("\u2705 OK", style="green"),
            "Passed all checks",
        )

    con.print(table)

    # Summary footer
    threat_count = len(result.threats)
    cooldown_count = len(result.cooldown_pending)
    summary = Text()
    summary.append(
        f"{result.total_packages} packages scanned, "
        f"{threat_count} threat{'s' if threat_count != 1 else ''} found, "
        f"{cooldown_count} cooldown pending",
        style="bold",
    )
    con.print(summary)


# ---------------------------------------------------------------------------
# JSON output utilities
# ---------------------------------------------------------------------------


def format_json(data: Any, pretty: bool = False) -> str:
    """Format data as JSON string with trailing newline.

    Args:
        data: The data to serialize to JSON.
        pretty: If True, output indented (indent=2). If False, output compact.

    Returns:
        JSON string representation of data with trailing newline.
    """
    if pretty:
        return json.dumps(data, indent=2) + "\n"
    return json.dumps(data) + "\n"
