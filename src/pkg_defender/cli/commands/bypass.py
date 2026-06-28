"""pkgd bypass command."""

from __future__ import annotations

import logging
from datetime import datetime

import click

from pkg_defender.cli._exit_codes import EXIT_USAGE_ERROR as _EXIT_USAGE_ERROR
from pkg_defender.cli._manager_constants import MANAGER_NAMES, resolve_ecosystem
from pkg_defender.cli.common import _parse_expiry, console, get_db_path, init_db, insert_bypass
from pkg_defender.cli.main import cli
from pkg_defender.config import load_config

logger = logging.getLogger(__name__)


@cli.command(
    name="bypass",
    epilog=(
        click.style("WARNING: This command bypasses all safety checks!", fg="red", bold=True) + "\n"
        "\n"
        "What is skipped:\n"
        "- Cooldown enforcement\n"
        "- Threat detection\n"
        "- Known-vulnerable package blocks\n"
        "\n"
        "Use ONLY in isolated test/development environments.\n"
        "NEVER use in production systems!\n"
        "\n"
        "See also: pkgd status, pkgd reset"
    ),
)
@click.argument("package_spec")
@click.option("--reason", required=True, help="Reason for bypass")
@click.option(
    "--manager",
    "-m",
    default="npm",
    type=click.Choice(list(MANAGER_NAMES)),
)
@click.option("--expires", default=None, help="Bypass expiry (e.g., '24h', '7d', '30m')")
def bypass(
    package_spec: str,
    reason: str,
    manager: str,
    expires: str | None,
) -> None:
    """Bypass cooldown and threat checks for a specific package version.

    Creates a bypass entry that allows a package to be installed without
    going through normal safety checks. This command is intended ONLY for
    testing/development in isolated environments.

    SECURITY WARNING: Using this command skips all safety checks including
    cooldown enforcement and threat detection. Vulnerable packages will be
    installed. Do NOT use in production systems.

    Examples:

    \b
        pkgd bypass axios@1.6.0 --reason "needed for legacy integration"
        pkgd bypass lodash@4.17.21 --reason "temporary testing" --expires 24h
        pkgd bypass express@4.18.0 --manager npm --expires 7d

    EXIT CODES:
        0    Bypass created successfully
        2    Invalid arguments or missing --reason

    ENVIRONMENT:
        PKGD_CONFIG_PATH    Config file location
        NO_COLOR            Disable colored output

    FILES:
        ~/.local/share/pkg-defender/threats.db    Threat database (bypasses table)

    \f
    """
    ecosystem = resolve_ecosystem(manager)

    # Config gate: bypass command is disabled by default
    _config = load_config()
    if not _config.bypass.command_enabled:
        click.echo(
            "Error: The `pkgd bypass` command is disabled by configuration.\n"
            "To enable: set `[bypass]\ncommand_enabled = true` in your config file\n"
            "or set `PKGD_BYPASS_COMMAND_ENABLED=true` in your environment.",
            err=True,
        )
        raise SystemExit(_EXIT_USAGE_ERROR) from None

    if "@" in package_spec and package_spec.startswith("@"):
        at_idx = package_spec.find("@", 1)
        if at_idx == -1:
            # Scoped package without version (e.g., "@scope/package")
            package = package_spec
            version = ""
        else:
            package = package_spec[:at_idx]
            version = package_spec[at_idx + 1 :]
    elif "@" in package_spec:
        package, version = package_spec.rsplit("@", 1)
    else:
        click.echo(
            "Error: package_spec must include a version (e.g., 'axios@1.14.1')",
            err=True,
        )
        raise SystemExit(_EXIT_USAGE_ERROR) from None

    expires_at: datetime | None = None
    if expires:
        expires_at = _parse_expiry(expires)

    db_path = get_db_path()
    conn = init_db(db_path)

    try:
        insert_bypass(
            conn,
            ecosystem=ecosystem,
            package=package,
            version=version,
            threat_id=None,
            reason=reason,
            expires_at=expires_at,
            checks_performed="none",
        )

        # Audit log the bypass creation
        import getpass

        logger.warning(
            "Bypass record created: user=%s ecosystem=%s package=%s version=%s reason=%s expires=%s",
            getpass.getuser(),
            ecosystem,
            package,
            version,
            reason,
            expires_at,
        )
    finally:
        conn.close()

    click.echo()
    console.print(f"[green]Bypass created[/] for {package}@{version}")
    console.print(f"  Reason:  {reason}")
    console.print(f"  Ecosystem: {ecosystem}")
    if expires_at:
        console.print(f"  Expires: {expires_at.strftime('%Y-%m-%d %H:%M UTC')}")
    else:
        console.print("  Expires: never")
