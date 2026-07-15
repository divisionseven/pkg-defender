# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Exec handoff for pkgd command wrapper.

These functions handle replacing the current Python process with the
underlying package manager after pkgd has completed its threat/cooldown checks.

Using os.execvp means pkgd vanishes — the manager runs as if pkgd was never
there. stdin/stdout/stderr are inherited. Exit code is the manager's exit code.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import click

from pkg_defender.cli._exit_codes import EXIT_COOLDOWN, EXIT_GENERAL_ERROR, EXIT_THREAT_DETECTED
from pkg_defender.cli.common import _parse_expiry
from pkg_defender.config import get_db_path
from pkg_defender.db.schema import get_connection, insert_bypass
from pkg_defender.display import format_json
from pkg_defender.models import CheckResult
from pkg_defender.models.command import BlockReason, PackageRef, ParsedCommand

if TYPE_CHECKING:
    from pkg_defender.db.schema import ResolutionAttemptRow

# Try to use Rich for pretty output, fall back to plain text
_HAS_RICH = True
_console_cls: Any = None
_custom_theme: Any = None

try:
    from rich.console import Console as _Console_cls
    from rich.theme import Theme as _Theme_cls

    _console_cls = _Console_cls
    _custom_theme = _Theme_cls({"warn": "bold yellow", "error": "bold red"})
except ImportError:
    _HAS_RICH = False


logger = logging.getLogger(__name__)


def _stderr_write(msg: str) -> None:
    """Write to stderr, with Rich formatting if available."""
    if _HAS_RICH and _console_cls is not None:
        _console_cls(theme=_custom_theme, stderr=True, markup=False).print(msg, style="error")
    else:
        sys.stderr.write(msg + "\n")


def _stdout_write(msg: str) -> None:
    """Write to stdout, with Rich formatting if available."""
    if _HAS_RICH and _console_cls is not None:
        _console_cls(theme=_custom_theme, markup=False).print(msg)
    else:
        sys.stdout.write(msg + "\n")


def exec_cleared_command(parsed: ParsedCommand) -> None:
    """
    Replace the current process with the underlying manager command.

    Timeout enforcement happens at the shell hook level, not in exec.py,
    since os.execvp replaces the entire process and any code after the call
    never executes.
    """
    from pkg_defender.registry import get_adapter_class_for_manager

    adapter_class = get_adapter_class_for_manager(parsed.manager)
    if adapter_class is None:
        # Should not happen — dispatcher already validated this
        sys.stderr.write(f"[PKGD] ERROR — Unknown package manager: {parsed.manager}\n")
        sys.exit(EXIT_GENERAL_ERROR)

    adapter = adapter_class()
    exec_args = adapter.build_exec_args(parsed)

    try:
        os.execvp(exec_args[0], exec_args)
    except FileNotFoundError:
        sys.stderr.write(f"[PKGD] ERROR — Command not found: {exec_args[0]}\n")
        sys.exit(EXIT_GENERAL_ERROR)
    except OSError as e:
        sys.stderr.write(f"[PKGD] ERROR — Exec failed: {e}\n")
        sys.exit(EXIT_GENERAL_ERROR)


def handle_cleared_command(parsed: ParsedCommand, passthrough: bool = False) -> None:
    """
    Handle a cleared command — checks dry-run and json flags before exec.

    If --dry-run is set, prints the audit result without executing.
    If --json is set, emits JSON output instead of human-readable text.
    Otherwise, replaces the current process with the manager command.
    """
    if parsed.pkgd_flags.get("dry_run"):
        if parsed.pkgd_flags.get("json"):
            click.echo(format_json(_build_json_result(parsed, "allow")), nl=False)
            return
        _print_dry_run(parsed)
        return

    if parsed.pkgd_flags.get("json"):
        click.echo(format_json(_build_json_result(parsed, "allow")), nl=False, err=True)

    if passthrough:
        _stderr_write(
            f'[PKGD] "{parsed.manager} {" ".join(parsed.raw_args)}" '
            f"not classified as dangerous \u2014 passing through to {parsed.manager}."
        )
    exec_cleared_command(parsed)


def handle_blocked_command(
    parsed: ParsedCommand,
    reason: BlockReason,
    package: PackageRef,
    safe_version: str | None = None,
    clears_at: datetime | None = None,
    checks_performed: str = "bypassed",
    ecosystem: str | None = None,
    window_days: int | None = None,
    release_date: datetime | None = None,
    date_source: str = "",
) -> None:
    """
    Display block UI and optionally prompt for bypass.

    Behavior by reason:
    - THREAT: Display threat block, exit(4) — cannot be bypassed
    - COOLDOWN: Display cooldown block, offer bypass prompt, exit(3) if not bypassed
    - VCS_SOURCE: Display VCS warning, offer confirm prompt, exit(1) if declined
    - LOCAL_PATH: Display local path warning, proceed to exec

    Args:
        parsed: The parsed command.
        reason: Why the command was blocked.
        package: The blocked package reference.
        safe_version: Optional pre-formatted safe version string
            (e.g. ``"requests==2.30.0"``). Only used for COOLDOWN.
        clears_at: Optional datetime when the cooldown expires.
            Only used for COOLDOWN.
        checks_performed: Which checks ran before this block.
            Passed to _log_bypass(). Default 'bypassed'.
        ecosystem: Explicit ecosystem string (e.g., "homebrew").
            Passed through to _log_bypass(). Falls back to package/parsed if None.
        window_days: Cooldown window in days. Only used for COOLDOWN.
            Passed through to _print_cooldown_block(). If None, defaults to 7.
        release_date: Optional release datetime to display in the blocked
            message. Only used for COOLDOWN.
        date_source: Source label for the release date (e.g. "github_tags",
            "pypi", "registry_api"). Only used for COOLDOWN.
    """
    if reason == BlockReason.THREAT:
        # --bypass-threat allows bypassing all threat checks
        if parsed.pkgd_flags.get("bypass_threat"):
            _log_bypass(
                parsed,
                package,
                reason,
                reason_prefix="bypass_threat",
                checks_performed=checks_performed,
                ecosystem=ecosystem,
            )
            if not parsed.pkgd_flags.get("json"):
                pkg_version = package.version or "latest"
                _stderr_write(
                    f"[PKGD] BYPASS — {parsed.manager} {parsed.manager_subcommand}"
                    f" {package.name}@{pkg_version} (--bypass-threat)"
                )
            exec_cleared_command(parsed)
        if parsed.pkgd_flags.get("json"):
            click.echo(
                format_json(
                    _build_json_result(
                        parsed,
                        "block",
                        reason="THREAT",
                        package=package,
                    )
                ),
                nl=False,
            )
            sys.exit(EXIT_THREAT_DETECTED)
        _print_threat_block(package)
        sys.exit(EXIT_THREAT_DETECTED)
    elif reason == BlockReason.COOLDOWN:
        if parsed.pkgd_flags.get("json"):
            click.echo(
                format_json(
                    _build_json_result(
                        parsed,
                        "block",
                        reason="COOLDOWN",
                        package=package,
                        safe_version=safe_version,
                        clears_at=clears_at,
                    )
                ),
                nl=False,
            )
            sys.exit(EXIT_COOLDOWN)
        _print_cooldown_block(
            package,
            parsed,
            safe_version,
            clears_at,
            window_days=window_days or 3,
            release_date=release_date,
            date_source=date_source,
            ecosystem=ecosystem,
        )
        # Cooldown can be bypassed with --bypass-cooldown, --allow-once, --force, or user confirmation
        if parsed.pkgd_flags.get("bypass_cooldown"):
            _log_bypass(
                parsed,
                package,
                reason,
                reason_prefix="bypass_cooldown",
                checks_performed=checks_performed,
                ecosystem=ecosystem,
            )
            if not parsed.pkgd_flags.get("json"):
                pkg_version = package.version or "latest"
                _stderr_write(
                    f"[PKGD] BYPASS — {parsed.manager} {parsed.manager_subcommand}"
                    f" {package.name}@{pkg_version} (--bypass-cooldown)"
                )
            exec_cleared_command(parsed)
        elif parsed.pkgd_flags.get("allow_once"):
            allow_once_val = parsed.pkgd_flags["allow_once"]
            if isinstance(allow_once_val, str):
                expires = _parse_expiry(allow_once_val)
            else:
                expires = datetime.now(UTC) + timedelta(hours=24)
            _log_bypass(
                parsed,
                package,
                reason,
                expires_at=expires,
                reason_prefix="allow_once",
                checks_performed=checks_performed,
                ecosystem=ecosystem,
            )
            exec_cleared_command(parsed)
        elif parsed.pkgd_flags.get("force"):
            click.echo(
                "[PKGD] Tip: Use --allow-once for a single-use bypass (24h expiry) "
                "instead of --force (permanent bypass).",
                err=True,
            )
            _log_bypass(parsed, package, reason, checks_performed=checks_performed, ecosystem=ecosystem)
            exec_cleared_command(parsed)
        elif not parsed.pkgd_flags.get("ci") and not parsed.pkgd_flags.get("dry_run"):
            if _ask_bypass():
                _log_bypass(parsed, package, reason, checks_performed=checks_performed, ecosystem=ecosystem)
                exec_cleared_command(parsed)
        sys.exit(EXIT_COOLDOWN)
    elif reason == BlockReason.VCS_SOURCE:
        if parsed.pkgd_flags.get("json"):
            click.echo(
                format_json(
                    _build_json_result(
                        parsed,
                        "block",
                        reason="VCS_SOURCE",
                        package=package,
                    )
                ),
                nl=False,
                err=True,
            )
            if parsed.pkgd_flags.get("dry_run"):
                sys.exit(EXIT_GENERAL_ERROR)
            exec_cleared_command(parsed)
        _print_vcs_warning(package)
        if parsed.pkgd_flags.get("dry_run"):
            sys.exit(EXIT_GENERAL_ERROR)
        if not parsed.pkgd_flags.get("ci") and not _ask_confirm("Continue with VCS source install?"):
            sys.exit(EXIT_GENERAL_ERROR)
        exec_cleared_command(parsed)
    elif reason == BlockReason.LOCAL_PATH:
        if parsed.pkgd_flags.get("json"):
            click.echo(
                format_json(
                    _build_json_result(
                        parsed,
                        "block",
                        reason="LOCAL_PATH",
                        package=package,
                    )
                ),
                nl=False,
                err=True,
            )
            exec_cleared_command(parsed)
        _print_local_path_warning(package)
        exec_cleared_command(parsed)


# ---------------------------------------------------------------------------
# Source label formatting
# ---------------------------------------------------------------------------


_SOURCE_LABEL_MAP: dict[str, str] = {
    "registry_api": "registry",
    "github_releases": "GitHub Releases",
    "github_tags": "GitHub Tags",
    "libraries_io": "Libraries.io",
    "unresolved": "unresolved",
    "bodhi": "Bodhi",
    "koji": "Koji",
    "repodata": "repodata",
    "pypi": "PyPI",
    "npm": "npm",
    "rubygems": "RubyGems",
    "crates_io": "crates.io",
    "all_sources_failed": "resolution failed",
    "no_github_url": "no repository URL",
    "homebrew_formula_commit": "Homebrew Formula Commit",
    "rate_limited": "rate limited",
    "timeout": "timed out",
    "network_error": "network error",
    "not_found": "not found",
    "server_error": "server error",
    "unknown_error": "unknown error",
}


def _format_source_label(source: str) -> str:
    """Convert an internal source label to a user-friendly display string.

    Source labels that don't have a mapping are returned as-is
    (they're already descriptive enough). An empty string is mapped
    to "unknown".

    Args:
        source: The internal source label (e.g. "github_tags", "registry_api").

    Returns:
        A user-friendly label for display.
    """
    if not source:
        return "unknown"
    return _SOURCE_LABEL_MAP.get(source, source)


_RESOLUTION_STATUS_DISPLAY: dict[str, str] = {
    "resolved": "resolved",
    "all_sources_failed": "resolution failed (all sources exhausted)",
    "no_github_url": "no repository URL available for resolution",
    "rate_limited": "resolution failed (API rate limit exceeded)",
    "timeout": "resolution failed (request timed out)",
    "network_error": "resolution failed (network error)",
    "not_found": "resolution failed (version not found in any source)",
    "server_error": "resolution failed (server error)",
    "unknown_error": "resolution failed (unknown error)",
}


def _format_resolution_status(status: str) -> str:
    """Convert resolution_status to user-friendly display string.

    Args:
        status: The resolution status code from the database.

    Returns:
        A human-readable description of the resolution status.
    """
    return _RESOLUTION_STATUS_DISPLAY.get(status, f"resolution status: {status}")


# Private display functions


def _print_dry_run(parsed: ParsedCommand) -> None:
    """Print dry-run output showing what would be executed.

    After the dispatcher has already reported threat and cooldown check
    results in the modern conversational style, this function appends
    the command-level summary for dry-run mode.
    """
    from pkg_defender.registry import get_adapter_class_for_manager

    adapter_class = get_adapter_class_for_manager(parsed.manager)
    if adapter_class is None:
        return

    adapter = adapter_class()
    exec_args = adapter.build_exec_args(parsed)
    cmd_str = " ".join(exec_args)

    pkg_count = len(parsed.packages)
    pkg_list = ", ".join(pkg.raw for pkg in parsed.packages[:3])
    if pkg_count > 3:
        pkg_list += f", and {pkg_count - 3} more"

    _stdout_write(f"[PKGD] Dry run — would execute: {cmd_str}")
    _stdout_write(f"[PKGD] Packages: {pkg_list}")


def _print_threat_block(package: PackageRef) -> None:
    """Print threat block message."""
    pkg_version = package.version or "latest"
    msg = (
        f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
        f"[PKGD]   Reason: Known security threat detected\n"
        f"[PKGD]   This package has known security vulnerabilities.\n"
        f"[PKGD]   Run 'pkgd intel search {package.name}' for details.\n"
        f"[PKGD]   Use --bypass-threat to bypass (logged to audit trail)."
    )
    _stderr_write(msg)


def _format_remaining_time(clears_at: datetime) -> str:
    """Format the time remaining until clears_at as a human-readable string."""
    delta = clears_at - datetime.now(UTC)
    total_seconds = int(delta.total_seconds())
    if total_seconds <= 0:
        return "now"

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if days == 0 and hours == 0 and minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if days == 0 and hours == 0 and minutes == 0:
        return "less than a minute"

    return "in " + ", ".join(parts)


def _lookup_resolution_info(
    package: PackageRef,
    ecosystem: str | None,
) -> ResolutionAttemptRow | None:
    """Look up resolution attempt info for a package.

    Reads from the ``resolution_attempts`` table to provide diagnostic
    information when the release date is unknown.

    Args:
        package: The package reference.
        ecosystem: The ecosystem string, or ``None``.

    Returns:
        A :class:`ResolutionAttemptRow` if found, ``None`` otherwise.
    """
    from pathlib import Path

    from pkg_defender.config import get_db_path
    from pkg_defender.db.schema import get_connection, get_resolution_attempt

    if ecosystem is None:
        return None
    try:
        db_path = get_db_path()
        if db_path is None or not isinstance(db_path, Path) or not db_path.exists():
            return None
        conn = get_connection(db_path)
        try:
            return get_resolution_attempt(conn, ecosystem, package.name, package.version or "")
        finally:
            conn.close()
    except Exception:
        logger.debug("_lookup_resolution_info: DB lookup failed", exc_info=True)
        return None


def _print_cooldown_block(
    package: PackageRef,
    parsed: ParsedCommand,
    safe_version: str | None = None,
    clears_at: datetime | None = None,
    window_days: int = 3,
    release_date: datetime | None = None,
    date_source: str = "",
    ecosystem: str | None = None,
) -> None:
    """Print cooldown block message.

    Args:
        package: The blocked package reference.
        parsed: The parsed command containing pkgd flags.
        safe_version: Optional pre-formatted safe version string
            (e.g. ``"requests==2.30.0"``).
        clears_at: Optional datetime when the cooldown expires.
        window_days: The cooldown window in days. Defaults to 3.
        release_date: Optional release datetime to display.
        date_source: Source label for the release date.
        ecosystem: Optional ecosystem string for resolution_attempts lookup.
    """
    pkg_version = package.version or "latest"
    if release_date is not None:
        if release_date.tzinfo is None:
            release_date = release_date.replace(tzinfo=UTC)
        # We know the date — block because it's recent
        age_days = (datetime.now(UTC) - release_date).days
        msg = (
            f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
            f"[PKGD]   Reason: Cooldown period active\n"
            f"[PKGD]   Published: {release_date.strftime('%Y-%m-%d @ %H:%M UTC')}"
            f" (source: {_format_source_label(date_source)})\n"
            f"[PKGD]   Age: {age_days}d since release\n"
            f"[PKGD]   Cooldown window: {window_days} day{'s' if window_days != 1 else ''}\n"
        )
    else:
        # We don't know the date — block out of caution
        resolution_info = _lookup_resolution_info(package, ecosystem)
        if resolution_info is not None:
            status_display = _format_resolution_status(resolution_info.resolution_status)
            msg = (
                f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
                f"[PKGD]   Reason: Cooldown period active\n"
                f"[PKGD]   Could not determine release date.\n"
                f"[PKGD]   Resolution status: {status_display}\n"
            )
            if resolution_info.last_error:
                msg += f"[PKGD]   Error detail: {resolution_info.last_error}\n"
            msg += f"[PKGD]   Last attempt: {resolution_info.attempted_at.strftime('%Y-%m-%d %H:%M UTC')}\n"
            msg += "[PKGD]   This is a precautionary block — cannot confirm this version is safe.\n"
        else:
            # No resolution attempt recorded yet
            msg = (
                f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
                f"[PKGD]   Reason: Cooldown period active\n"
                f"[PKGD]   Could not determine release date.\n"
                f"[PKGD]   Resolution has not been attempted for this package.\n"
                f"[PKGD]   This is a precautionary block — cannot confirm this version is safe.\n"
            )
    # Trust penalty messaging
    if date_source:
        from pkg_defender.db.schema import SOURCE_TRUST_MAP

        trust_level = SOURCE_TRUST_MAP.get(date_source, "unknown")
        if trust_level == "claimed":
            msg += "[PKGD]   Trust penalty: maintainer-claimed timestamp (+2 days added to cooldown window)\n"
    if safe_version is not None:
        msg += f"[PKGD]   Safe version: {safe_version}\n"
    if clears_at is not None:
        msg += (
            f"[PKGD]   Clears at: {clears_at.strftime('%Y-%m-%d @ %H:%M UTC')} ({_format_remaining_time(clears_at)})\n"
        )
    msg += (
        "[PKGD]   Use --bypass-cooldown to bypass cooldown (logged to audit trail, threat checks still run).\n"
        "[PKGD]   Use --allow-once for a single-use bypass (logged to audit trail, 24h expiry).\n"
        "[PKGD]   Use --force to bypass permanently (logged to audit trail)."
    )
    _stderr_write(msg)


def _print_vcs_warning(package: PackageRef) -> None:
    """Print VCS/URL install warning."""
    pkg_version = package.version or "latest"
    msg = (
        f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
        f"[PKGD]   Reason: VCS/URL source\n"
        f"[PKGD]   Source: {package.raw or 'unknown'}\n"
        f"[PKGD]   pkg-defender cannot verify VCS packages against the threat database.\n"
        f"[PKGD]   Proceed with caution."
    )
    _stderr_write(msg)


def _print_local_path_warning(package: PackageRef) -> None:
    """Print local path install warning."""
    pkg_version = package.version or "latest"
    msg = (
        f"[PKGD] BLOCKED — {package.name}@{pkg_version}\n"
        f"[PKGD]   Reason: Local path source\n"
        f"[PKGD]   Source: {package.raw or 'unknown'}\n"
        f"[PKGD]   pkg-defender cannot verify local packages against the threat database.\n"
        f"[PKGD]   Proceeding anyway."
    )
    _stderr_write(msg)


def _build_json_result(
    parsed: ParsedCommand,
    decision: str,
    *,
    reason: str | None = None,
    package: PackageRef | None = None,
    safe_version: str | None = None,
    clears_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable result dict for --json output.

    Args:
        parsed: The parsed command with manager, packages, flags.
        decision: The decision string ("allow" or "block").
        reason: Block reason name (e.g., "THREAT", "COOLDOWN").
            Only set when decision is "block".
        package: A single package reference. If provided, emits a
            ``package`` object instead of a ``packages`` list.
        safe_version: Pre-formatted safe version string for cooldown blocks.
        clears_at: Cooldown expiry datetime for cooldown blocks.

    Returns:
        A dict suitable for ``format_json()``.
    """
    result: dict[str, Any] = {
        "decision": decision,
        "manager": parsed.manager,
        "subcommand": parsed.manager_subcommand,
    }

    if package is not None:
        result["package"] = {
            "name": package.name,
            "version": package.version,
            "ecosystem": package.ecosystem,
        }
    elif parsed.packages:
        result["packages"] = [
            {
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
            }
            for p in parsed.packages
        ]

    if reason is not None:
        result["reason"] = reason

    if safe_version is not None:
        result["safe_version"] = safe_version

    if clears_at is not None:
        result["clears_at"] = clears_at.isoformat()

    if parsed.pkgd_flags.get("dry_run"):
        result["dry_run"] = True

    return result


# ---------------------------------------------------------------------------
# Explain (decision trace) output functions
# ---------------------------------------------------------------------------


def _make_separator(title: str) -> str:
    """Create a section separator line like '── Title ──────────────'.

    Args:
        title: The section title text.

    Returns:
        A formatted separator string with the title centered on a dashed line.
    """
    inner = f"── {title} ──"
    padding = 48 - len(inner)
    if padding < 2:
        padding = 2
    return f"[PKGD] {inner}{'─' * padding}"


def _format_age(release_date: datetime | None) -> str:
    """Format a release date as a human-readable age string.

    Args:
        release_date: The release datetime, or None.

    Returns:
        Age string like '2 days 3 hours', or 'Unknown' if date is None.
    """
    if release_date is None:
        return "Unknown"
    now = datetime.now(UTC)
    if release_date.tzinfo is None:
        release_date = release_date.replace(tzinfo=UTC)
    if release_date > now:
        return "0 days 0 hours"
    delta = now - release_date
    days = delta.days
    hours = delta.seconds // 3600
    parts: list[str] = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0 or not parts:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    return " ".join(parts)


def _print_explain_header(package: PackageRef, decision: str, reason: str) -> None:
    """Print the common decision-trace header section.

    Args:
        package: The package reference being checked.
        decision: The decision label (e.g., 'BLOCKED', 'WARNING', 'ERROR').
        reason: A short human-readable reason string.
    """
    pkg_label = f"{package.name}@{package.version}" if package.version else package.name
    lines = [
        _make_separator("Decision Trace"),
        f"[PKGD] Package:     {pkg_label}",
    ]
    if package.ecosystem:
        lines.append(f"[PKGD] Ecosystem:   {package.ecosystem}")
    lines.append(f"[PKGD] Decision:    {decision}")
    lines.append(f"[PKGD] Reason:      {reason}")
    _stderr_write("\n".join(lines))


def _print_explain_section(title: str, items: list[tuple[str, str]]) -> None:
    """Print a labelled section with key-value pairs.

    Args:
        title: The section title.
        items: List of (key, value) tuples to display.
    """
    lines = [_make_separator(title)]
    for key, value in items:
        lines.append(f"[PKGD] {key}: {value}")
    _stderr_write("\n".join(lines))


def _print_explain_actions(actions: list[str]) -> None:
    """Print a 'What you can do' section with actionable bullets.

    Args:
        actions: List of action strings to display as bullet points.
    """
    lines = [_make_separator("What you can do")]
    for action in actions:
        lines.append(f"[PKGD] • {action}")
    _stderr_write("\n".join(lines))


def _print_explain_threat(package: PackageRef, result: CheckResult) -> None:
    """Print explain output for a threat block.

    Args:
        package: The package reference that was blocked.
        result: The full threat check result with scores and threat records.
    """
    _print_explain_header(package, "BLOCKED", "Known security threat detected")

    threat_items: list[tuple[str, str]] = [
        ("Matching threats", str(len(result.threats))),
        ("Highest score", f"{result.highest_score:.2f} ({result.highest_severity})"),
    ]
    _print_explain_section("Threat Details", threat_items)

    for i, threat in enumerate(result.threats, 1):
        detail_lines = [
            "",
            f"[PKGD] Threat #{i}:",
            f"[PKGD]   Source:    {threat.record.source}",
            f"[PKGD]   Severity:  {threat.display_severity}",
            f"[PKGD]   Score:     {threat.final_score:.2f}",
            f"[PKGD]   Summary:   {threat.record.summary}",
        ]
        if threat.record.detail_url:
            detail_lines.append(f"[PKGD]   Reference: {threat.record.detail_url}")
        _stderr_write("\n".join(detail_lines))

    _print_explain_actions(
        [
            "Use --bypass-threat to bypass threat check (logged to audit trail, cooldown still enforced)",
            f"Run 'pkgd intel search {package.name}' for full details",
            "Consider using a known-safe version",
        ]
    )


def _print_explain_cooldown(
    package: PackageRef,
    release_date: datetime | None,
    days_remaining: int,
    ecosystem: str,
    window_days: int,
    safe_version: str | None = None,
    date_source: str = "",
) -> None:
    """Print explain output for a cooldown block.

    Args:
        package: The package reference that was blocked.
        release_date: The package release datetime, or None if unknown.
        days_remaining: Days remaining in the cooldown window.
        ecosystem: The package ecosystem identifier.
        window_days: The cooldown window in days for this ecosystem.
        safe_version: Optional pre-formatted safe version string
            (e.g. ``"requests==2.30.0"``).
        date_source: Source label for the release date.
    """
    _print_explain_header(package, "BLOCKED", "Cooldown period active")

    if release_date is not None:
        release_str = release_date.strftime("%Y-%m-%d @ %H:%M:%S UTC")
        age_str = _format_age(release_date)
        clears_at = release_date + timedelta(days=window_days)
        clears_str = clears_at.strftime("%Y-%m-%d @ %H:%M UTC")
        cooldown_items: list[tuple[str, str]] = [
            ("Release date", f"{release_str} (source: {_format_source_label(date_source)})"),
            ("Age", age_str),
            ("Cooldown window", f"{window_days} days ({ecosystem})"),
            ("Remaining", f"{days_remaining} days"),
            ("Clears at", f"{clears_str} ({_format_remaining_time(clears_at)})"),
        ]
    else:
        cooldown_items = [
            ("Release date", "Unknown"),
            ("Cooldown window", f"{window_days} days ({ecosystem})"),
            ("Remaining", f"{days_remaining} days"),
        ]

    # Trust info — when date_source is available
    from pkg_defender.db.schema import SOURCE_TRUST_MAP

    trust_level = SOURCE_TRUST_MAP.get(date_source, "unknown")
    if trust_level == "claimed":
        cooldown_items.append(("Trust penalty", "maintainer-claimed: +2 days"))
    elif trust_level == "verified":
        cooldown_items.append(("Timestamp source", "verified"))

    _print_explain_section("Cooldown Details", cooldown_items)

    if safe_version is not None:
        _stderr_write(f"[PKGD] Safe version: {safe_version}")

    _print_explain_actions(
        [
            "Use --bypass-cooldown to bypass cooldown (logged to audit trail, threat checks still run)",
            "Use --allow-once for a single-use bypass (24h expiry, logged to audit trail)",
            "Use --force to bypass permanently (logged to audit trail)",
            "Wait until clears_at for automatic clearance",
        ]
    )


def _print_explain_no_db(package: PackageRef, db_path: str) -> None:
    """Print explain output for a missing threat database.

    Args:
        package: The package reference being checked.
        db_path: The expected path to the threat database file.
    """
    _print_explain_header(package, "BLOCKED", "Threat database not found")

    _print_explain_section(
        "System Details",
        [
            ("DB path", db_path),
            ("Status", "File does not exist"),
        ],
    )

    _print_explain_actions(
        [
            "Run 'pkgd setup' to initialize the database",
            "Run 'pkgd intel sync' to download threat data",
        ]
    )


def _print_explain_no_version(package: PackageRef) -> None:
    """Print explain output for a missing version specification.

    Args:
        package: The package reference with no version.
    """
    _print_explain_header(package, "BLOCKED", "No version specified")

    items: list[tuple[str, str]] = [
        ("", "pkgd needs an exact version to check for threats."),
        ("", "Without a version, the threat database cannot be queried."),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            f"Specify a version: pkgd pip install {package.name}==X.Y.Z",
            f"Or use a version constraint: pkgd pip install '{package.name}>=X.0,<Y.0'",
        ]
    )


def _print_explain_stale_db(
    db_path: str,
    last_sync: str | None,
    threshold_hours: int,
    error_msg: str,
) -> None:
    """Print explain output for a stale database with failed refresh.

    Args:
        db_path: The path to the threat database.
        last_sync: The last sync timestamp string, or None.
        threshold_hours: The staleness threshold in hours.
        error_msg: The error message from the failed refresh.
    """
    _print_explain_header(
        PackageRef(name="(all packages)"),
        "BLOCKED",
        "Threat database is stale and refresh failed",
    )

    sync_status = last_sync if last_sync else "Never synced"
    items: list[tuple[str, str]] = [
        ("DB path", db_path),
        ("Last sync", sync_status),
        ("Staleness threshold", f"{threshold_hours} hours"),
        ("Auto-refresh error", error_msg),
    ]
    _print_explain_section("System Details", items)

    _print_explain_actions(
        [
            "Fix network connectivity and run 'pkgd intel sync'",
        ]
    )


def _print_explain_vcs(package: PackageRef) -> None:
    """Print explain output for a VCS/URL source warning.

    Args:
        package: The package reference with VCS source.
    """
    source_url = package.raw if package.raw else "unknown"
    _print_explain_header(
        package,
        "WARNING",
        "VCS source — cannot verify with threat database",
    )

    items: list[tuple[str, str]] = [
        ("Source", source_url),
        ("", "pkgd can only check packages from registries (PyPI, npm, etc.)."),
        ("", "VCS/URL packages bypass threat DB lookups."),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            "Proceed with caution — verify the source manually",
            "Consider pinning to a registry-published version",
        ]
    )


def _print_explain_local_path(package: PackageRef) -> None:
    """Print explain output for a local path install warning.

    Args:
        package: The package reference with local path source.
    """
    source_path = package.raw if package.raw else "unknown"
    _print_explain_header(
        package,
        "WARNING",
        "Local path — cannot verify with threat database",
    )

    items: list[tuple[str, str]] = [
        ("Source", source_path),
        ("", "pkgd can only check packages from registries (PyPI, npm, etc.)."),
        ("", "Local packages bypass threat DB lookups."),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            "Verify the local package contents manually",
        ]
    )


def _print_explain_timeout(timeout_seconds: int) -> None:
    """Print explain output for a timeout error.

    Args:
        timeout_seconds: The configured command timeout in seconds.
    """
    _print_explain_header(
        PackageRef(name="(unknown)"),
        "ERROR",
        "Pre-install check timed out",
    )

    items: list[tuple[str, str]] = [
        ("Timeout", f"{timeout_seconds} seconds"),
        ("", "The check may have encountered a network or database issue."),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            "Retry the command",
            "Increase timeout in config: command_timeout_seconds",
            "Check network connectivity and database health",
        ]
    )


def _print_explain_db_connection(package: PackageRef, error_msg: str) -> None:
    """Print explain output for a database connection error.

    Args:
        package: The package reference being checked.
        error_msg: The database error message.
    """
    _print_explain_header(package, "BLOCKED", "Could not open threat database")

    items: list[tuple[str, str]] = [
        ("Error", error_msg),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            "Run 'pkgd setup' to reinitialize the database",
            "Check database file permissions",
        ]
    )


def _print_explain_no_result(package: PackageRef) -> None:
    """Print explain output for a null batch check result.

    Args:
        package: The package reference that returned no result.
    """
    _print_explain_header(
        package,
        "BLOCKED",
        "No threat check result available",
    )

    items: list[tuple[str, str]] = [
        ("", "The threat check returned no result for this package."),
        ("", "This may indicate database corruption or an interrupted sync."),
    ]
    _print_explain_section("Check Details", items)

    _print_explain_actions(
        [
            "Run 'pkgd intel sync' to refresh the threat database",
        ]
    )


def _ask_bypass() -> bool:
    """Ask user whether to bypass cooldown. Simple yes/no."""
    try:
        response = input("[PKGD] Bypass cooldown and proceed? [y/N] ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _ask_confirm(prompt: str) -> bool:
    """Ask user for confirmation."""
    try:
        response = input(f"[PKGD] {prompt} [y/N] ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _log_bypass(
    parsed: ParsedCommand,
    package: PackageRef,
    reason: BlockReason,
    expires_at: datetime | None = None,
    reason_prefix: str = "bypass",
    checks_performed: str = "bypassed",
    ecosystem: str | None = None,
) -> None:
    """Log a bypass to stderr AND the database audit trail.

    The DB write happens before os.execvp() since the process is replaced
    after this call returns. Connection is opened fresh each time since
    exec.py has no persistent connection handle.

    Args:
        parsed: The parsed command being bypassed.
        package: The package reference that was blocked.
        reason: Why the command was blocked.
        expires_at: Optional expiry timestamp for time-bounded bypasses.
        reason_prefix: Prefix for the reason field (default: "bypass").
        checks_performed: Which security checks ran before bypass.
            Passed through to insert_bypass(). Default 'bypassed'.
        ecosystem: Explicit ecosystem string (e.g., "homebrew").
            Falls back to package.ecosystem or parsed.manager if not provided.
    """
    pkg_version = package.version or "latest"
    msg = (
        f"[PKGD] BYPASS — {parsed.manager} {parsed.manager_subcommand}"
        f" {package.name}@{pkg_version} (reason={reason.name})"
    )
    _stderr_write(msg)

    # Write to the DB audit trail BEFORE execvp replaces the process
    try:
        db_path = get_db_path()
        if db_path and db_path.exists():
            conn = get_connection(db_path)
            try:
                insert_bypass(
                    conn=conn,
                    ecosystem=ecosystem or package.ecosystem or parsed.manager,
                    package=package.name,
                    version=package.version or "",
                    threat_id=None,
                    reason=f"{reason_prefix}:{reason.name}",
                    expires_at=expires_at,
                    commit=True,
                    checks_performed=checks_performed,
                )
            finally:
                conn.close()
        else:
            _stderr_write("[PKGD] ERROR — Could not write bypass to DB (database not found)")
    except Exception:
        logger.warning("Failed to write bypass to database audit log", exc_info=True)
        _stderr_write("[PKGD] ERROR — Failed to write bypass to database audit log")
