"""Lock file auditor — scans existing lock files for threats and cooldown violations."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from pkg_defender.audit.cooldown import check_cooldown
from pkg_defender.core.checker import check_package as threat_check_package
from pkg_defender.core.checker import check_packages_batch
from pkg_defender.core.parsers import parse_lock_file
from pkg_defender.db.schema import get_version_timestamps_batch
from pkg_defender.models import (
    AuditCooldownEntry,
    AuditThreatEntry,
    CooldownResult,
    PackageAuditResult,
    VersionInfo,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import sqlite3

    from pkg_defender.config.settings import PKGDConfig


def audit_lock_file(
    conn: sqlite3.Connection,
    project_path: Path,
    config: PKGDConfig,
    *,
    deep: bool = False,
    timestamp_lookup: Callable[[sqlite3.Connection, str, str, str], datetime | None] | None = None,
) -> PackageAuditResult:
    """Audit all lock files found under *project_path*.

    Discovers lock files via :func:`find_lock_files`, audits each one
    via :func:`_audit_lock_file_single`, tags every entry with its source
    lock file, and aggregates all results into a single
    :class:`PackageAuditResult`.

    Args:
        conn: Open SQLite connection with initialised schema.
        project_path: Directory tree to scan for lock files.
        config: Defender configuration.
        deep: If ``True``, also check cooldown status.
        timestamp_lookup: Callable for cooldown checks.

    Returns:
        Aggregated :class:`PackageAuditResult`.

    Raises:
        FileNotFoundError: If no recognised lock file is found anywhere
            under *project_path*.
    """
    from pkg_defender.core.parsers import find_lock_files

    project_path = Path(project_path).resolve()
    lock_files = find_lock_files(project_path)
    if not lock_files:
        raise FileNotFoundError(
            f"No recognised lock file found in {project_path}\n"
            "Supported: package-lock.json, poetry.lock, requirements.txt, "
            "yarn.lock, pnpm-lock.yaml, uv.lock, Pipfile.lock"
        )

    all_threats: list[AuditThreatEntry] = []
    all_cooldown: list[AuditCooldownEntry] = []
    all_passed: list[dict[str, str]] = []
    total_packages = 0

    for lock_path in lock_files:
        result = _audit_lock_file_single(
            conn,
            lock_path,
            config,
            deep=deep,
            timestamp_lookup=timestamp_lookup,
        )
        total_packages += result.total_packages

        # Set lock_file on each entry
        for te in result.threats:
            te.lock_file = str(lock_path.relative_to(project_path))
            all_threats.append(te)
        for ce in result.cooldown_pending:
            ce.lock_file = str(lock_path.relative_to(project_path))
            all_cooldown.append(ce)
        if result.passed_packages:
            all_passed.extend(result.passed_packages)

    return PackageAuditResult(
        project_path=str(project_path),
        lock_file=", ".join(str(lp.relative_to(project_path)) for lp in lock_files),
        total_packages=total_packages,
        threats=all_threats,
        cooldown_pending=all_cooldown,
        passed=len(all_passed),
        passed_packages=all_passed,
        scan_time=datetime.now(UTC),
    )


def _audit_lock_file_single(
    conn: sqlite3.Connection,
    lock_path: Path,
    config: PKGDConfig,
    *,
    deep: bool = False,
    timestamp_lookup: Callable[[sqlite3.Connection, str, str, str], datetime | None] | None = None,
) -> PackageAuditResult:
    """Audit a single lock file for threats and (optionally) cooldown.

    Args:
        conn: Open SQLite connection with initialised schema.
        lock_path: Path to a specific lock file.
        config: Defender configuration.
        deep: If ``True``, also check cooldown status.
        timestamp_lookup: Callable for cooldown checks.

    Returns:
        A :class:`PackageAuditResult` for this single lock file.

    Raises:
        IsADirectoryError: If *lock_path* is a directory (not a file).
    """
    if lock_path.is_dir():
        raise IsADirectoryError(f"Expected a lock file path, got directory: {lock_path}")

    packages = parse_lock_file(lock_path)

    threats: list[AuditThreatEntry] = []
    cooldown_pending: list[AuditCooldownEntry] = []
    passed: list[dict[str, str]] = []

    # Build package list for batch threat check
    pkg_tuples = [(pkg_info["ecosystem"], pkg_info["package"], pkg_info["version"]) for pkg_info in packages]

    # Batch threat check — 2E SQL queries instead of 2N
    batch_results = check_packages_batch(conn, pkg_tuples)

    # In deep mode, batch-fetch version timestamps — 1 query per ecosystem
    # instead of N individual lookups
    ecosystem_timestamps: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    if deep and timestamp_lookup is not None:
        ecosystems = {pkg_info["ecosystem"] for pkg_info in packages}
        for eco in ecosystems:
            eco_pkgs = [(p["package"], p["version"]) for p in packages if p["ecosystem"] == eco]
            ecosystem_timestamps.update(get_version_timestamps_batch(conn, eco, eco_pkgs))

    # Process each package using batch results
    for pkg_info in packages:
        pkg_name = pkg_info["package"]
        pkg_version = pkg_info["version"]
        ecosystem = pkg_info["ecosystem"]

        # --- Threat check (always runs) — use batch result ---
        key = (ecosystem, pkg_name, pkg_version)
        check_result = batch_results.get(key)
        if check_result is None:
            check_result = threat_check_package(conn, ecosystem, pkg_name, pkg_version)

        if check_result.threats:
            threats.append(
                AuditThreatEntry(
                    package=pkg_name,
                    version=pkg_version,
                    ecosystem=ecosystem,
                    threats=check_result.threats,
                    transitive_path=[pkg_name],
                    safe_version=check_result.safe_version,
                )
            )
            continue

        # --- Cooldown check (deep mode only) ---
        if deep and timestamp_lookup is not None:
            ts_key = (ecosystem, pkg_name, pkg_version)
            ts_entry = ecosystem_timestamps.get(ts_key)
            if ts_entry is not None:
                publish_time, source_label = ts_entry
                cd_entry = _check_cooldown_for_audit_with_timestamp(
                    ecosystem,
                    pkg_name,
                    pkg_version,
                    config,
                    publish_time,
                    source_label,
                )
            else:
                # Fallback to original callback if batch didn't find it
                cd_entry = _check_cooldown_for_audit(
                    conn,
                    ecosystem,
                    pkg_name,
                    pkg_version,
                    config,
                    timestamp_lookup,
                )
            if cd_entry is not None:
                cooldown_pending.append(cd_entry)
                continue

        passed.append({"package": pkg_name, "version": pkg_version, "ecosystem": ecosystem})

    return PackageAuditResult(
        project_path=str(lock_path.parent),
        lock_file=lock_path.name,
        total_packages=len(packages),
        threats=threats,
        cooldown_pending=cooldown_pending,
        passed=len(passed),
        passed_packages=passed,
        scan_time=datetime.now(UTC),
    )


def _check_cooldown_for_audit(
    conn: sqlite3.Connection,
    ecosystem: str,
    package: str,
    version: str,
    config: PKGDConfig,
    timestamp_lookup: Callable[[sqlite3.Connection, str, str, str], datetime | None],
) -> AuditCooldownEntry | None:
    """Check cooldown status for a single package version during an audit.

    Looks up the publish_time via the injected timestamp_lookup callable.
    If not found, the entry is skipped (don't block the audit on missing data).

    Args:
        conn: Open SQLite connection.
        ecosystem: Ecosystem identifier (``"npm"``, ``"pypi"``).
        package: Package name.
        version: Exact version string.
        config: Defender configuration.
        timestamp_lookup: Callable ``(conn, ecosystem, package, version) -> datetime | None``.

    Returns:
        An :class:`AuditCooldownEntry` if the package is still within its
        cooldown window, or ``None`` if it passed or data was unavailable.
    """
    publish_time = timestamp_lookup(conn, ecosystem, package, version)
    if publish_time is None:
        logger.warning(
            "Cooldown: publish time not available for %s %s@%s — cooldown check skipped (fail-open)",
            ecosystem,
            package,
            version,
        )
        return None

    version_info = VersionInfo(
        version=version,
        publish_time=publish_time,
        ecosystem=ecosystem,
        package_name=package,
        date_source="cache",
    )

    cd_config = config.cooldown
    from pkg_defender.db.schema import SOURCE_TRUST_MAP

    trust_level = SOURCE_TRUST_MAP.get(version_info.date_source or "", "unknown")
    cd_result: CooldownResult = check_cooldown(version_info, cd_config, trust_level=trust_level)

    if cd_result.allowed:
        return None

    # Compute when the cooldown clears.
    clears_at = publish_time + timedelta(days=cd_result.effective_cooldown_days or 0)
    age = cd_result.age or (datetime.now(UTC) - publish_time)

    return AuditCooldownEntry(
        package=package,
        version=version,
        ecosystem=ecosystem,
        age=age,
        clears_at=clears_at,
    )


def _check_cooldown_for_audit_with_timestamp(
    ecosystem: str,
    package: str,
    version: str,
    config: PKGDConfig,
    publish_time: datetime,
    source_label: str = "",
) -> AuditCooldownEntry | None:
    """Check cooldown status using a pre-fetched publish timestamp.

    This avoids re-querying the database for timestamps that were
    already fetched in batch by get_version_timestamps_batch().

    Args:
        ecosystem: Ecosystem identifier.
        package: Package name.
        version: Exact version string.
        config: Defender configuration.
        publish_time: Pre-fetched publish timestamp.
        source_label: Source label for the publish timestamp (e.g. "registry_api",
            "registry", "github_tags"). Passed into VersionInfo.date_source and
            used to compute trust_level. Defaults to ``""``.

    Returns:
        An AuditCooldownEntry if within cooldown window, or None.
    """
    version_info = VersionInfo(
        version=version,
        publish_time=publish_time,
        ecosystem=ecosystem,
        package_name=package,
        date_source=source_label,
    )

    cd_config = config.cooldown
    from pkg_defender.db.schema import SOURCE_TRUST_MAP

    trust_level = SOURCE_TRUST_MAP.get(source_label, "unknown")
    cd_result: CooldownResult = check_cooldown(version_info, cd_config, trust_level=trust_level)

    if cd_result.allowed:
        return None

    clears_at = publish_time + timedelta(days=cd_result.effective_cooldown_days or 0)
    age = cd_result.age or (datetime.now(UTC) - publish_time)

    return AuditCooldownEntry(
        package=package,
        version=version,
        ecosystem=ecosystem,
        age=age,
        clears_at=clears_at,
    )
