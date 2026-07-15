# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""pkgd audit command."""

from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import click

from pkg_defender.cli._exit_codes import EXIT_REGISTRY_UNREACHABLE as _EXIT_REGISTRY_UNREACHABLE
from pkg_defender.cli._exit_codes import EXIT_THREAT_DETECTED as _EXIT_THREAT_DETECTED
from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli._progress import progress_context, should_show_progress
from pkg_defender.cli.common import (
    _get_config_from_context,
    _parse_duration,
    display_audit_results,
    display_stale_db_warning,
    format_json,
    get_db_path,
    get_feed_state,
    get_version_timestamp,
    init_db,
    is_verbose_mode,
)
from pkg_defender.cli.main import cli

logger = logging.getLogger(__name__)


@cli.command(
    name="audit",
    epilog="See also: pkgd status, pkgd intel search",
)
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["rich", "json", "csv"]),
    default="rich",
    help="Output format: 'rich' for formatted output, 'json' for JSON, 'csv' for CSV. "
    "Examples: pkgd audit . -o json > output.json",
)
@click.option(
    "--pretty",
    "-p",
    "pretty_output",
    is_flag=True,
    help="Pretty-print JSON output (only applies with -o json)",
)
@click.option("--json", "json_flag", is_flag=True, help="Output JSON (same as --output json or -o json)")
@click.option("--deep", "-d", is_flag=True, help="Also check cooldown status for each package")
@click.option(
    "--fail-on-threat",
    "-f",
    is_flag=True,
    default=None,
    help="Exit 4 (`EXIT_THREAT_DETECTED`) if CRITICAL or HIGH threats found (default: enabled by config)",
)
@click.option("--since", default=None, help="Only flag threats seen within duration (e.g., 7d, 24h)")
@click.pass_context
def audit(
    ctx: click.Context,
    path: str,
    output_format: str,
    pretty_output: bool,
    json_flag: bool,
    deep: bool,
    fail_on_threat: bool,
    since: str | None = None,
) -> None:
    """Scan a lock file for threats and cooldown-pending packages.

    Analyzes your project's dependency lock file to identify:
    - Known vulnerable packages (CVEs, malicious packages)
    - Packages that are too new (still in cooldown period)
    - Outdated packages with known issues

    Supports: package-lock.json (npm v2/v3), poetry.lock, requirements.txt,
    yarn.lock, pnpm-lock.yaml, uv.lock, Pipfile.lock

    Use --deep to also check the cooldown status for each package (not just
    whether they're blocked). Use --fail-on-threat to make the command exit
    with an error when threats are found, useful in CI/CD pipelines.

    Examples:

    \b
        pkgd audit .
        pkgd audit ./my-project --output json
        pkgd audit . --deep
        pkgd audit . --fail-on-threat
        pkgd audit . --since 7d

    EXIT CODES:
        0    No threats found, all packages safe
        4    Threats found or cooldown-pending packages (or --fail-on-threat triggered)
        2    Invalid arguments, no lock file found
        5    Registry/network unreachable

    ENVIRONMENT:
        PKGD_COOLDOWN_STRICT_MODE    Exit 4 if any threats found (default: false)
        PKGD_COOLDOWN_DEFAULT_DAYS  Override cooldown period
        NO_COLOR                   Disable colored output

    FILES:
        package-lock.json, poetry.lock, requirements.txt, yarn.lock, pnpm-lock.yaml, uv.lock

    \f
    """
    verbose_level = ctx.obj.get("verbose", 0) if ctx.obj else 0
    verbose = verbose_level >= 1 or (verbose_level == 0 and is_verbose_mode())

    if json_flag:
        output_format = "json"
    # CI mode auto-enables JSON output
    output_format = ctx.obj.get("output_format") or output_format

    from pkg_defender.core.auditor import audit_lock_file

    config = _get_config_from_context(ctx)

    if fail_on_threat is None:
        fail_on_threat = config.fail_on_threat_enabled

    db_path = get_db_path()
    conn = init_db(db_path)

    try:
        # Check DB staleness (warn-and-proceed for audit context)
        _state = get_feed_state(conn, "osv")
        if _state:
            _last_sync_str = _state.get("last_sync")
            if _last_sync_str is not None:
                try:
                    _last_sync = datetime.fromisoformat(_last_sync_str)
                    if _last_sync.tzinfo is None:
                        _last_sync = _last_sync.replace(tzinfo=UTC)
                    _age = datetime.now(UTC) - _last_sync
                    if _age > timedelta(hours=config.feeds.staleness_threshold_hours):
                        display_stale_db_warning(_last_sync)
                except (ValueError, TypeError):
                    display_stale_db_warning(None)
            else:
                display_stale_db_warning(None)
        else:
            display_stale_db_warning(None)

        logger.debug(
            "Audit path=%s, deep=%s, fail_on_threat=%s, since=%s",
            path,
            deep,
            fail_on_threat,
            since,
        )

        try:
            if deep and should_show_progress():
                with progress_context("Scanning packages (deep mode)..."):
                    result = audit_lock_file(
                        conn,
                        Path(path),
                        config,
                        deep=deep,
                        timestamp_lookup=get_version_timestamp,
                    )
            else:
                result = audit_lock_file(
                    conn,
                    Path(path),
                    config,
                    deep=deep,
                    timestamp_lookup=get_version_timestamp,
                )
        except FileNotFoundError:
            click.echo(
                f"Error: No recognised lock file found in {path}\n"
                "Supported: package-lock.json, poetry.lock, requirements.txt, "
                "yarn.lock, pnpm-lock.yaml, uv.lock, Pipfile.lock",
                err=True,
            )
            raise SystemExit(_EXIT_USAGE_ERROR) from None
        except Exception as exc:
            click.echo(
                f"Error during audit: {exc}. "
                "This usually occurs when the registry is unreachable. "
                "Check your network connection and try again.",
                err=True,
            )
            raise SystemExit(_EXIT_REGISTRY_UNREACHABLE) from exc

        if since:
            since_td = _parse_duration(since)
            cutoff = datetime.now(UTC) - since_td
            result.threats = [t for t in result.threats if any(st.record.last_seen >= cutoff for st in t.threats)]
            result.cooldown_pending = [c for c in result.cooldown_pending if c.clears_at >= cutoff]

        threat_count = len(result.threats)
        cooldown_count = len(result.cooldown_pending)
        logger.debug(
            "Audit results: %d threats, %d cooldown pending, %d total packages",
            threat_count,
            cooldown_count,
            result.total_packages,
        )

        if output_format == "json":
            output: dict[str, Any] = {
                "lock_file": result.lock_file,
                "total": result.total_packages,
                "threats": [
                    {
                        "package": te.package,
                        "version": te.version,
                        "ecosystem": te.ecosystem,
                        "lock_file": te.lock_file,
                        "severity": te.threats[0].display_severity if te.threats else "UNKNOWN",
                        "threats": [
                            {
                                "severity": t.display_severity,
                                "summary": t.record.summary,
                                "source": t.record.source,
                                "source_id": t.record.source_id,
                                "published_at": t.record.published_at.isoformat() if t.record.published_at else None,
                                "version_match_type": t.version_match_type,
                                "detail_url": t.record.detail_url,
                            }
                            for t in te.threats
                        ],
                    }
                    for te in result.threats
                ],
                "cooldown_pending": [
                    {
                        "package": ce.package,
                        "version": ce.version,
                        "ecosystem": ce.ecosystem,
                        "lock_file": ce.lock_file,
                        "age_seconds": ce.age.total_seconds(),
                        "clears_at": ce.clears_at.isoformat(),
                    }
                    for ce in result.cooldown_pending
                ],
            }
            click.echo(format_json(output, pretty_output), nl=False)
        elif output_format == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                [
                    "package",
                    "version",
                    "ecosystem",
                    "lock_file",
                    "severity",
                    "source",
                    "published_at",
                    "version_match_type",
                    "summary",
                ]
            )
            for te in result.threats:
                for st in te.threats:
                    writer.writerow(
                        [
                            te.package,
                            te.version,
                            te.ecosystem,
                            te.lock_file,
                            st.display_severity,
                            st.record.source,
                            st.record.published_at.isoformat() if st.record.published_at else "",
                            st.version_match_type,
                            st.record.summary[:80],
                        ]
                    )
            for ce in result.cooldown_pending:
                writer.writerow(
                    [
                        ce.package,
                        ce.version,
                        ce.ecosystem,
                        ce.lock_file,
                        "COOLDOWN",
                        "cooldown",
                        "",
                        "",
                        f"clears at {ce.clears_at.isoformat()}",
                    ]
                )
            click.echo(buf.getvalue().strip())
        else:
            click.echo()
            display_audit_results(
                result,
                verbose=verbose,
                passed_packages=result.passed_packages if verbose else None,
            )
    finally:
        conn.close()

    should_exit = False
    if threat_count > 0 and config.cooldown.strict_mode:
        should_exit = True
    if fail_on_threat:
        has_blocking_threat = any(
            te.threats and any(st.display_severity in ("CRITICAL", "HIGH") for st in te.threats)
            for te in result.threats
        )
        if has_blocking_threat:
            should_exit = True
    if cooldown_count > 0:
        should_exit = True
    if should_exit:
        raise SystemExit(_EXIT_THREAT_DETECTED)
