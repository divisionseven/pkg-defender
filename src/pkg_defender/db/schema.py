"""SQLite schema definitions, database connection management, and CRUD operations."""

from __future__ import annotations

import dataclasses
import functools
import getpass
import json
import logging
import os
import random
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkg_defender.config.settings import DatabaseConfig
from pkg_defender.exceptions import DatabaseCorruptionError
from pkg_defender.models import ThreatRecord, VersionInfo

logger = logging.getLogger(__name__)

# Cache: track which database paths have passed PRAGMA quick_check.
# Avoids re-scanning the full database on every get_connection() call
# within the same process (saves 30-84s per pre-install check).
_quick_check_passed: set[str] = set()

# ---------------------------------------------------------------------------

VALID_ECOSYSTEMS: tuple[str, ...] = (
    "npm",
    "pypi",
    "cargo",
    "composer",
    "rubygems",
    "go",
    "maven",
    "nuget",
    "packagist",
    "unknown",
    "homebrew",
    "apt",
    "yum",
    "dnf",
    "conda",
    "gem",
    "pip",
    "pipx",
    "pnpm",
    "pub",
    "swift",
    "uv",
    "yarn",
)

VALID_SOURCES: tuple[str, ...] = (
    "osv",
    "ghsa",
    "socket",
    "npm_advisory",
    "mastodon",
    "reddit",
    "rss",
    "x_twitter",
    "ossf_malicious",
    "homebrew_osv",
)

VALID_MANAGERS: tuple[str, ...] = (
    "pip",
    "pip3",
    "uv",
    "poetry",
    "pipenv",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "cargo",
    "gem",
    "bundler",
    "composer",
    "conda",
    "brew",
    "apt",
    "dnf",
    "yum",
)

VALID_ACTIONS: tuple[str, ...] = (
    "install",
    "update",
    "upgrade",
    "reinstall",
    "execute",
    "fetch",
)

VALID_RISK_LEVELS: tuple[str, ...] = (
    "critical",
    "important",
    "watch",
)

VALID_AUDIT_SOURCES: tuple[str, ...] = (
    "shell_hook",
    "cli",
    "api",
    "cron",
    "test",
)

VALID_VERDICTS: tuple[str, ...] = (
    "PASS",
    "PARTIAL_PASS",
    "FAIL",
    "BLOCKED",
    "WARN",
    "ERROR",
)

VALID_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
VALID_TRUST_LEVELS: tuple[str, ...] = ("verified", "proxied", "claimed", "unknown")
VALID_FEED_STATUSES: tuple[str, ...] = (
    "idle",
    "syncing",
    "error",
    "disabled",
    "not_configured",
    "circuit_open",
)

VALID_RESOLUTION_STATUSES: tuple[str, ...] = (
    "resolved",
    "all_sources_failed",
    "no_github_url",
    "rate_limited",
    "timeout",
    "network_error",
    "not_found",
    "server_error",
    "unknown_error",
)

# Trust level mapping from source_label — replaces fragile if/elif/else chains.
# Maps each known source label to its data reliability tier:
#   "verified" → first-party API, authoritative
#   "proxied"  → mirror/build-system, best-effort
#   "claimed"  → third-party / self-reported, use with caution
#   "unknown"  → no source information
SOURCE_TRUST_MAP: dict[str, str] = {
    "registry_api": "verified",  # PyPI, npm, RubyGems, Cargo, APT native APIs
    "homebrew_formula_commit": "verified",  # Homebrew formula file commit date (Commits API)
    "registry": "claimed",  # Packagist — self-reported metadata
    "bodhi": "verified",  # Fedora Bodhi update system
    "snapshot_debian": "verified",  # Debian snapshot archive
    "koji": "proxied",  # Fedora Koji build system
    "repodata": "proxied",  # YUM/DNF repodata metadata
    "github_releases": "claimed",  # GitHub Releases API (40% coverage)
    "github_tags": "claimed",  # GitHub Tags→Commits API (near-100%)
    "libraries_io": "claimed",  # Libraries.io (third-party, per-version)
    "unresolved": "unknown",  # No authoritative timestamp obtained
    "cache": "unknown",  # Programmatic cache (no source attribution)
    # Resolution-failure source labels — all mapped to "unknown" trust level
    # because no authoritative timestamp was obtained.
    "all_sources_failed": "unknown",
    "no_github_url": "unknown",
    "rate_limited": "unknown",
    "not_found": "unknown",
    "timeout": "unknown",
    "network_error": "unknown",
}

# Cache TTL in days per trust level.
# Entries older than this should be refreshed from the original source.
TRUST_TTL_MAP: dict[str, int] = {
    "verified": 30,
    "proxied": 14,
    "claimed": 7,
    "unknown": 1,
}


def classify_precision(dt: datetime) -> str:
    """Classify a datetime by its precision.

    Uses the microsecond field to determine precision:
    - Microsecond present (≠ 0) → ``"microsecond"``
    - Microsecond absent (== 0) → ``"second"``

    Args:
        dt: Timezone-aware UTC datetime.

    Returns:
        One of ``"microsecond"`` or ``"second"``.
    """
    return "microsecond" if dt.microsecond != 0 else "second"


def _format_utc_z(dt: datetime) -> str:
    """Format an aware UTC datetime as ISO 8601 with Z suffix.

    Handles trailing-zero trimming: ``2024-01-01T00:00:00.000000`` →
    ``2024-01-01T00:00:00Z``.

    Args:
        dt: Timezone-aware datetime (will be treated as UTC — caller
            must have already normalized).

    Returns:
        ISO 8601 string ending with ``Z``.
    """
    dt_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    dt_str = dt_str.rstrip("0").rstrip(".")
    return dt_str + "Z"


def _check_values(values: tuple[str, ...]) -> str:
    """Generate a SQL CHECK IN expression from a Python tuple of allowed values.

    Ensures SQL CHECK constraints stay synchronised with Python-level VALID_*
    tuples. Called during ``SCHEMA_SQL`` evaluation at import time.
    """
    quoted = ", ".join(repr(v) for v in values)
    return f"IN ({quoted})"


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------

# Current schema version — bump when SCHEMA_SQL or migration logic changes.
# Must be incremented for EVERY schema change (new table, new column, new constraint).
CURRENT_SCHEMA_VERSION: int = 1


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Read the database schema version from the schema_version table.

    Args:
        conn: Open database connection.

    Returns:
        The schema version integer. Returns 0 if the table is empty
        or does not exist.
    """
    try:
        row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def set_schema_version(conn: sqlite3.Connection, version: int, *, commit: bool = True) -> None:
    """Set the database schema version by inserting into the schema_version table.

    Args:
        conn: Open database connection.
        version: Schema version to set.
        commit: If True (default), commit after write.
    """
    conn.execute(
        "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
        (version,),
    )
    if commit:
        conn.commit()


def migrate_db(conn: sqlite3.Connection) -> None:
    """Run pending schema migrations to bring the database up to CURRENT_SCHEMA_VERSION.

    Reads the current version from the schema_version table, then stamps
    the database to CURRENT_SCHEMA_VERSION if it is behind.

    For schema version 1, no DDL migration is needed — all tables are
    created by SCHEMA_SQL via CREATE TABLE IF NOT EXISTS. This function
    exists to stamp the version and provide downgrade protection.

    If the project ships to users with existing databases and a schema
    change is needed in the future, migration blocks should be added
    here as sequential steps.

    Args:
        conn: Open database connection with tables already created.

    Raises:
        RuntimeError: If the database version is newer than the code version
            (potential downgrade scenario).
    """
    db_version = get_schema_version(conn)

    if db_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version ({db_version}) is newer than code version "
            f"({CURRENT_SCHEMA_VERSION}). This may indicate a downgrade. "
            "Cannot proceed."
        )

    if db_version == CURRENT_SCHEMA_VERSION:
        return  # Already at current version

    # Initial version stamp — all tables already created by SCHEMA_SQL.
    # No DDL migration is needed because CREATE TABLE IF NOT EXISTS keeps
    # the schema in sync. This stamp exists for downgrade protection and
    # to provide a hook for future migrations if the project ever ships
    # to users with existing databases.
    logger.info("Stamping schema version: v%d → v%d", db_version, CURRENT_SCHEMA_VERSION)
    set_schema_version(conn, CURRENT_SCHEMA_VERSION, commit=True)
    logger.info("Schema migration complete: v%d → v%d", db_version, CURRENT_SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# Schema SQL
# ---------------------------------------------------------------------------

SCHEMA_SQL: str = f"""
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL
        CHECK(ecosystem {_check_values(VALID_ECOSYSTEMS)}),
    package_name TEXT NOT NULL,
    affected_versions TEXT NOT NULL DEFAULT '[]',
    affected_ranges TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL CHECK(severity {_check_values(VALID_SEVERITIES)}),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    source TEXT NOT NULL CHECK(source {_check_values(VALID_SOURCES)}),
    source_id TEXT,
    summary TEXT NOT NULL DEFAULT '',
    detail_url TEXT,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    hit_count INTEGER NOT NULL DEFAULT 1 CHECK(hit_count >= 1),
    cvss_score REAL CHECK(cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)),
    published_at TEXT,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_malicious INTEGER NOT NULL DEFAULT 0 CHECK(is_malicious IN (0, 1)),
    is_unverified INTEGER NOT NULL DEFAULT 0 CHECK(is_unverified IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threats_ecosystem_package
    ON threats(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_threats_first_seen
    ON threats(first_seen);
CREATE INDEX IF NOT EXISTS idx_threats_published
    ON threats(published_at);
CREATE INDEX IF NOT EXISTS idx_threats_ecosystem_null_pkg
    ON threats(ecosystem) WHERE package_name = 'unknown';
CREATE INDEX IF NOT EXISTS idx_threats_source_id
    ON threats(source_id);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen
    ON threats(last_seen);

CREATE TABLE IF NOT EXISTS version_timestamps (
    ecosystem      TEXT NOT NULL CHECK(ecosystem {_check_values(VALID_ECOSYSTEMS)}),
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    publish_time   TEXT NOT NULL
        CHECK(publish_time GLOB '????-??-??T*:*:*Z'),
    trust_level    TEXT NOT NULL DEFAULT 'unknown'
        CHECK(trust_level IN ('verified', 'proxied', 'claimed', 'unknown')),
    source_label   TEXT NOT NULL DEFAULT '',
    precision      TEXT NOT NULL DEFAULT 'second'
        CHECK(precision IN ('microsecond', 'second', 'day', 'unknown')),
    resolved_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    cache_ttl_days INTEGER NOT NULL DEFAULT 7,
    PRIMARY KEY (ecosystem, package_name, version)
);

CREATE TABLE IF NOT EXISTS resolution_attempts (
    ecosystem      TEXT NOT NULL CHECK(ecosystem {_check_values(VALID_ECOSYSTEMS)}),
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    publish_time   TEXT
        CHECK(publish_time IS NULL OR publish_time GLOB '????-??-??T*:*:*Z'),
    resolution_status TEXT NOT NULL DEFAULT 'all_sources_failed'
        CHECK(resolution_status {_check_values(VALID_RESOLUTION_STATUSES)}),
    source_label   TEXT NOT NULL DEFAULT '',
    last_error     TEXT,
    attempted_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    retry_after    TEXT,
    PRIMARY KEY (ecosystem, package_name, version)
);
CREATE INDEX IF NOT EXISTS idx_resolution_attempts_status
    ON resolution_attempts(resolution_status);
CREATE INDEX IF NOT EXISTS idx_resolution_attempts_retry
    ON resolution_attempts(retry_after) WHERE resolution_status != 'resolved';

CREATE TABLE IF NOT EXISTS bypasses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem TEXT NOT NULL CHECK(ecosystem {_check_values(VALID_ECOSYSTEMS)}),
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    threat_id TEXT REFERENCES threats(id) ON DELETE SET NULL,
    reason TEXT NOT NULL DEFAULT '',
    bypassed_at TEXT NOT NULL DEFAULT (datetime('now')),
    user TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    checks_performed TEXT NOT NULL DEFAULT 'bypassed'
);

CREATE INDEX IF NOT EXISTS idx_bypasses_ecosystem_package
    ON bypasses(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_bypasses_threat_id
    ON bypasses(threat_id);
CREATE INDEX IF NOT EXISTS idx_bypasses_expires_at
    ON bypasses(expires_at);

CREATE TABLE IF NOT EXISTS feed_state (
    feed_name TEXT PRIMARY KEY,
    last_sync TEXT,
    cursor TEXT,
    status TEXT NOT NULL DEFAULT 'idle'
        CHECK(status {_check_values(VALID_FEED_STATUSES)}),
    error_message TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS feed_stats (
    feed_name TEXT NOT NULL,
    synced_at TEXT NOT NULL DEFAULT (datetime('now')),
    record_count INTEGER NOT NULL DEFAULT 0,
    avg_confidence REAL,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (feed_name, synced_at)
);
CREATE INDEX IF NOT EXISTS idx_feed_stats_lookup
    ON feed_stats(feed_name, synced_at DESC);

CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    ecosystem TEXT NOT NULL CHECK(ecosystem {_check_values(VALID_ECOSYSTEMS)}),
    package_name TEXT NOT NULL,
    version TEXT,
    action TEXT NOT NULL
        CHECK(action {_check_values(VALID_ACTIONS)}),
    risk_level TEXT NOT NULL
        CHECK(risk_level {_check_values(VALID_RISK_LEVELS)}),
    source TEXT NOT NULL
        CHECK(source {_check_values(VALID_AUDIT_SOURCES)}),
    manager TEXT NOT NULL
        CHECK(manager {_check_values(VALID_MANAGERS)}),
    subcommand TEXT,
    verdict TEXT NOT NULL
        CHECK(verdict {_check_values(VALID_VERDICTS)}),
    exit_code INTEGER NOT NULL CHECK(exit_code >= 0 AND exit_code <= 255),
    error_message TEXT,
    threat_count_general INTEGER NOT NULL DEFAULT 0 CHECK(threat_count_general >= 0),
    threat_count_versioned INTEGER NOT NULL DEFAULT 0 CHECK(threat_count_versioned >= 0),
    cooldown_pass INTEGER NOT NULL DEFAULT 1 CHECK(cooldown_pass IN (0, 1)),
    cooldown_days_remaining INTEGER NOT NULL DEFAULT 0,
    ci_mode INTEGER NOT NULL DEFAULT 0 CHECK(ci_mode IN (0, 1)),
    runtime_ms INTEGER CHECK(runtime_ms IS NULL OR runtime_ms >= 0),
    user TEXT,
    session_id TEXT,
    fail_on_threat_enabled INTEGER NOT NULL DEFAULT 1 CHECK(fail_on_threat_enabled IN (0, 1)),
    cooldown_enabled INTEGER NOT NULL DEFAULT 1 CHECK(cooldown_enabled IN (0, 1)),
    coverage_tier TEXT NOT NULL DEFAULT 'full'
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_ecosystem_package ON audit_events(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_audit_events_verdict ON audit_events(verdict);
CREATE INDEX IF NOT EXISTS idx_audit_events_source ON audit_events(source);
CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id);

"""  # noqa: E501


# ---------------------------------------------------------------------------
# Retry utilities
# ---------------------------------------------------------------------------


def retry_on_busy(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
) -> Callable[..., Any]:
    """Decorator: retry the wrapped function on SQLITE_BUSY with exponential backoff + jitter.

    Retries only on ``sqlite3.OperationalError`` with "database is locked" in the
    message. All other exceptions (including ``IntegrityError`` and non-lock
    ``OperationalError``) propagate immediately without retry.

    This decorator uses blocking ``time.sleep()`` — it must only be applied to
    functions that run in a thread pool (e.g. via ``asyncio.to_thread()``).
    Do NOT apply to async functions or functions that run on the event loop.

    Args:
        max_retries: Maximum total attempts (inclusive of the first call).
            Default 3 means: first attempt + up to 2 retries.
        base_delay: Base delay in seconds for exponential backoff.
            Actual delay = min(base_delay * 2^attempt + random(0, 1), max_delay).
        max_delay: Maximum delay cap in seconds.

    Returns:
        Decorated function with retry behavior.

    Example:
        @retry_on_busy(max_retries=3)
        def _sync_feed_db_ops(...) -> int:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Exception | None = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as exc:
                    if "database is locked" not in str(exc):
                        raise  # Non-busy OperationalError — don't retry
                    last_exc = exc
                    if attempt < max_retries - 1:
                        delay = min(
                            base_delay * (2**attempt) + random.uniform(0, 1),
                            max_delay,
                        )
                        logger.debug(
                            "SQLITE_BUSY on %s attempt %d/%d, retrying in %.1fs",
                            func.__name__,
                            attempt + 1,
                            max_retries,
                            delay,
                        )
                        time.sleep(delay)
            # All retries exhausted — raise the last exception
            assert last_exc is not None
            logger.error(
                "SQLITE_BUSY on %s after %d attempts — giving up",
                func.__name__,
                max_retries,
            )
            raise last_exc

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


def get_connection(
    db_path: Path,
    config: DatabaseConfig | None = None,
    *,
    quick: bool = False,
) -> sqlite3.Connection:
    """Open an SQLite connection with PRAGMAs applied.

    Args:
        db_path: Path to the SQLite database file.
        config: Optional DatabaseConfig. If provided, wal_mode and
            busy_timeout_ms override the hardcoded defaults.
        quick: If True, use a short 1-second busy_timeout for best-effort
            cache writes that should fail fast rather than block.

    Returns:
        A configured sqlite3.Connection.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if config is not None:
        conn.execute(f"PRAGMA journal_mode={'WAL' if config.wal_mode else 'DELETE'}")
        timeout = 1000 if quick else config.busy_timeout_ms
        conn.execute(f"PRAGMA busy_timeout={timeout}")
    else:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={1000 if quick else 5000}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-80000")
    conn.execute("PRAGMA temp_store=MEMORY")

    # Quick integrity check — fail fast on corruption.
    # Cached per resolved path to avoid re-scanning the full database
    # on every connection opened within the same process.
    _resolved = os.path.realpath(str(db_path))
    if _resolved not in _quick_check_passed:
        try:
            _rows = conn.execute("PRAGMA quick_check").fetchall()
            if not (len(_rows) == 1 and _rows[0][0] == "ok"):
                conn.close()
                raise DatabaseCorruptionError(
                    f"Database corruption detected at {db_path}.\n"
                    "Run 'pkgd db verify' for detailed diagnosis.\n"
                    "If the database is unrecoverable, delete it and run 'pkgd intel sync' to rebuild."
                )
            _quick_check_passed.add(_resolved)
        except DatabaseCorruptionError:
            conn.close()
            raise
        except Exception:
            conn.close()
            raise DatabaseCorruptionError(
                f"Database integrity check could not be completed for {db_path}.\n"
                "The database may be corrupted. Run 'pkgd db verify' for diagnosis."
            ) from None

    return conn


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------


def init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize the database: open a connection, create tables, and run migrations.

    Creates tables from SCHEMA_SQL (idempotent CREATE TABLE IF NOT EXISTS),
    then runs any pending schema migrations to bring the database up to
    CURRENT_SCHEMA_VERSION.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        A fully-initialized sqlite3.Connection at the current schema version.
    """
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    migrate_db(conn)
    return conn


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


def get_metadata(conn: sqlite3.Connection, key: str) -> str | None:
    """Read a metadata value by key.

    Args:
        conn: Open database connection.
        key: Metadata key to look up.

    Returns:
        The value if the key exists, or ``None``.
    """
    row = conn.execute(
        "SELECT value FROM db_metadata WHERE key = ?",
        (key,),
    ).fetchone()
    return row[0] if row else None


def set_metadata(
    conn: sqlite3.Connection,
    key: str,
    value: str,
    *,
    commit: bool = True,
) -> None:
    """Upsert a metadata key-value pair.

    Args:
        conn: Open database connection.
        key: Metadata key.
        value: Metadata value.
        commit: If ``True`` (default), commit after write.
    """
    conn.execute(
        "INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)",
        (key, value),
    )
    if commit:
        conn.commit()


# ---------------------------------------------------------------------------
# Threat CRUD
# ---------------------------------------------------------------------------


def _validate_threat(threat: ThreatRecord) -> ThreatRecord | None:
    """Validate and sanitize a ThreatRecord before database insertion.

    Performs all application-level validation that would otherwise be
    duplicated across insert_threat() and insert_threats_bulk().

    Args:
        threat: The ThreatRecord to validate.

    Returns:
        The validated ThreatRecord (potentially mutated, e.g. package_name
        coerced from None to 'unknown'), or None if validation failed.
    """
    # Validate required fields
    if threat.id is None or threat.ecosystem is None:
        logger.warning(
            "Skipping threat with missing required fields: id=%s, ecosystem=%s",
            threat.id,
            threat.ecosystem,
        )
        return None

    # Convert package_name=None to 'unknown' (ecosystem-wide threats)
    if threat.package_name is None:
        threat = dataclasses.replace(threat, package_name="unknown")

    # Validate source against CHECK constraint
    if threat.source not in VALID_SOURCES:
        logger.warning(
            "Invalid source '%s' — not in CHECK constraint. Skipping.",
            threat.source,
        )
        return None

    # Validate ecosystem against CHECK constraint
    if threat.ecosystem not in VALID_ECOSYSTEMS:
        logger.warning(
            "Invalid ecosystem '%s' — not in CHECK constraint. Skipping.",
            threat.ecosystem,
        )
        return None

    # Validate cvss_score range (0-10 per CVSS v3.1 spec)
    if threat.cvss_score is not None and (threat.cvss_score < 0 or threat.cvss_score > 10):
        logger.warning(
            "Skipping threat %s: cvss_score %s out of range [0, 10].",
            threat.id,
            threat.cvss_score,
        )
        return None

    # Validate boolean fields stored as INTEGER CHECK(0,1)
    if threat.is_malicious not in (True, False):
        logger.warning(
            "Skipping threat %s: is_malicious=%s must be boolean.",
            threat.id,
            threat.is_malicious,
        )
        return None

    if threat.is_unverified not in (True, False):
        logger.warning(
            "Skipping threat %s: is_unverified=%s must be boolean.",
            threat.id,
            threat.is_unverified,
        )
        return None

    # Validate detail_url format (if present)
    if (
        threat.detail_url is not None
        and threat.detail_url != ""
        and not threat.detail_url.startswith(("http://", "https://"))
    ):
        logger.warning(
            "Skipping threat %s: detail_url '%s' must start with http:// or https://.",
            threat.id,
            threat.detail_url,
        )
        return None

    return threat


def insert_threat(conn: sqlite3.Connection, threat: ThreatRecord, *, commit: bool = True) -> None:
    """Insert or replace a threat record.

    Serialises list/dict fields as JSON and datetimes as ISO8601.

    Args:
        conn: Open database connection.
        threat: The ThreatRecord to persist.
        commit: If ``True`` (default), commit after insert. Set to ``False``
             when the caller manages the transaction boundary (e.g. batch inserts).
    """
    validated = _validate_threat(threat)
    if validated is None:
        return
    threat = validated

    conn.execute(
        """
        INSERT INTO threats
        (id, ecosystem, package_name, affected_versions, affected_ranges,
        severity, confidence, source, source_id, summary, detail_url,
        first_seen, last_seen, hit_count, cvss_score, published_at,
        ingested_at, is_malicious, is_unverified, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            ecosystem        = excluded.ecosystem,
            package_name     = excluded.package_name,
            affected_versions = excluded.affected_versions,
            affected_ranges  = excluded.affected_ranges,
            severity         = CASE
                                 WHEN excluded.severity IN ('CRITICAL','HIGH')
                                 THEN excluded.severity
                                 ELSE COALESCE(NULLIF(excluded.severity,
                                                       'UNKNOWN'), severity)
                               END,
            confidence       = MAX(threats.confidence, excluded.confidence),
            source_id        = COALESCE(excluded.source_id, threats.source_id),
            summary          = CASE
                                 WHEN LENGTH(excluded.summary)
                                      >= LENGTH(threats.summary)
                                 THEN excluded.summary
                                 ELSE threats.summary
                               END,
            detail_url       = COALESCE(excluded.detail_url,
                                         threats.detail_url),
            first_seen       = MIN(threats.first_seen, excluded.first_seen),
            last_seen        = excluded.last_seen,
            hit_count        = threats.hit_count + 1,
            cvss_score       = COALESCE(excluded.cvss_score,
                                        threats.cvss_score),
            published_at     = COALESCE(excluded.published_at,
                                        threats.published_at),
            ingested_at      = excluded.ingested_at,
        is_malicious = MAX(threats.is_malicious,
        excluded.is_malicious),
        is_unverified = MAX(threats.is_unverified,
        excluded.is_unverified),
        updated_at = datetime('now')
        """,
        (
            threat.id,
            threat.ecosystem,
            threat.package_name,
            json.dumps(threat.affected_versions),
            json.dumps(threat.affected_ranges),
            threat.severity,
            threat.confidence,
            threat.source,
            threat.source_id,
            threat.summary,
            threat.detail_url,
            threat.first_seen.isoformat(),
            threat.last_seen.isoformat(),
            threat.hit_count,
            threat.cvss_score,
            threat.published_at.isoformat() if threat.published_at else None,
            threat.ingested_at.isoformat(),
            1 if threat.is_malicious else 0,
            1 if threat.is_unverified else 0,
        ),
    )
    if commit:
        conn.commit()


def insert_threats_bulk(
    conn: sqlite3.Connection,
    threats: list[ThreatRecord],
    *,
    commit: bool = False,
) -> int:
    """Insert multiple threat records in a single executemany() call.

    Uses the same SQL and validation as :func:`insert_threat` but batches all
    records into a single Python→C crossing, reducing per-record overhead
    by 5–20× for the insert phase.

    Invalid records are logged and silently skipped (same behaviour as
    :func:`insert_threat`).

    Args:
        conn: Open database connection.
        threats: Threat records to insert.
        commit: If ``True``, commit after insert. Set to ``False`` (default)
            when the caller manages the transaction boundary.

    Returns:
        Number of records successfully inserted.
    """
    _insert_threats_bulk_sql = """
        INSERT INTO threats
        (id, ecosystem, package_name, affected_versions, affected_ranges,
        severity, confidence, source, source_id, summary, detail_url,
        first_seen, last_seen, hit_count, cvss_score, published_at,
        ingested_at, is_malicious, is_unverified, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            ecosystem        = excluded.ecosystem,
            package_name     = excluded.package_name,
            affected_versions = excluded.affected_versions,
            affected_ranges  = excluded.affected_ranges,
            severity         = CASE
                                 WHEN excluded.severity IN ('CRITICAL','HIGH')
                                 THEN excluded.severity
                                 ELSE COALESCE(NULLIF(excluded.severity,
                                                       'UNKNOWN'), severity)
                               END,
            confidence       = MAX(threats.confidence, excluded.confidence),
            source_id        = COALESCE(excluded.source_id, threats.source_id),
            summary          = CASE
                                 WHEN LENGTH(excluded.summary)
                                      >= LENGTH(threats.summary)
                                 THEN excluded.summary
                                 ELSE threats.summary
                               END,
            detail_url       = COALESCE(excluded.detail_url,
                                         threats.detail_url),
            first_seen       = MIN(threats.first_seen, excluded.first_seen),
            last_seen        = excluded.last_seen,
            hit_count        = threats.hit_count + 1,
            cvss_score       = COALESCE(excluded.cvss_score,
                                        threats.cvss_score),
            published_at     = COALESCE(excluded.published_at,
                                        threats.published_at),
            ingested_at      = excluded.ingested_at,
        is_malicious = MAX(threats.is_malicious,
        excluded.is_malicious),
        is_unverified = MAX(threats.is_unverified,
        excluded.is_unverified),
        updated_at = datetime('now')
    """

    validated: list[tuple[Any, ...]] = []
    for threat in threats:
        validated_threat = _validate_threat(threat)
        if validated_threat is None:
            continue

        validated.append(
            (
                validated_threat.id,
                validated_threat.ecosystem,
                validated_threat.package_name,
                json.dumps(validated_threat.affected_versions),
                json.dumps(validated_threat.affected_ranges),
                validated_threat.severity,
                validated_threat.confidence,
                validated_threat.source,
                validated_threat.source_id,
                validated_threat.summary,
                validated_threat.detail_url,
                validated_threat.first_seen.isoformat(),
                validated_threat.last_seen.isoformat(),
                validated_threat.hit_count,
                validated_threat.cvss_score,
                validated_threat.published_at.isoformat() if validated_threat.published_at else None,
                validated_threat.ingested_at.isoformat(),
                1 if validated_threat.is_malicious else 0,
                1 if validated_threat.is_unverified else 0,
            )
        )

    if validated:
        conn.executemany(_insert_threats_bulk_sql, validated)

    if commit:
        conn.commit()

    return len(validated)


def get_threat(conn: sqlite3.Connection, threat_id: str) -> ThreatRecord | None:
    """Retrieve a single threat by its primary key.

    Args:
        conn: Open database connection.
        threat_id: The ``{source}:{source_id}`` key.

    Returns:
        A ThreatRecord, or None if not found.
    """
    row = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE id = ?",
        (threat_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_threat(row)


def get_threats_for_package(conn: sqlite3.Connection, ecosystem: str, package: str) -> list[ThreatRecord]:
    """Return all threats matching an ecosystem and package (or ecosystem-wide).

    Args:
        conn: Open database connection.
        ecosystem: Ecosystem identifier (e.g. ``"npm"``).
        package: Package name.

    Returns:
        List of matching ThreatRecord objects.
    """
    # Use UNION ALL to allow index usage (Issue 5 fix)
    rows1 = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE ecosystem = ? AND package_name = ?",
        (ecosystem, package),
    ).fetchall()
    rows2 = conn.execute(
        "SELECT id, ecosystem, package_name, affected_versions, affected_ranges, "
        "severity, confidence, source, source_id, summary, detail_url, "
        "first_seen, last_seen, hit_count, cvss_score, published_at, "
        "ingested_at, is_malicious, is_unverified, updated_at "
        "FROM threats WHERE ecosystem = ? AND package_name = 'unknown'",
        (ecosystem,),
    ).fetchall()
    rows = rows1 + rows2
    return [_row_to_threat(r) for r in rows]


def _row_to_threat(row: sqlite3.Row) -> ThreatRecord:
    """Convert a raw DB row into a ThreatRecord.

    Uses column-name access for resilience against future schema changes.
    """
    try:
        affected_versions = (
            json.loads(row["affected_versions"])
            if row["affected_versions"] and isinstance(row["affected_versions"], str)
            else []
        )
        affected_ranges = (
            json.loads(row["affected_ranges"])
            if row["affected_ranges"] and isinstance(row["affected_ranges"], str)
            else []
        )
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Malformed JSON in threat {row['id']}: {e}")
        raise

    return ThreatRecord(
        id=row["id"],
        ecosystem=row["ecosystem"],
        package_name=row["package_name"],
        affected_versions=affected_versions,
        affected_ranges=affected_ranges,
        severity=row["severity"] or "UNKNOWN",
        confidence=row["confidence"] if row["confidence"] is not None else 0.5,
        source=row["source"] or "",
        source_id=row["source_id"],
        summary=row["summary"] or "",
        detail_url=row["detail_url"],
        first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else datetime.now(UTC),
        last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else datetime.now(UTC),
        hit_count=row["hit_count"] if row["hit_count"] is not None else 1,
        cvss_score=row["cvss_score"],
        published_at=datetime.fromisoformat(row["published_at"]) if row["published_at"] else None,
        ingested_at=datetime.fromisoformat(row["ingested_at"]) if row["ingested_at"] else datetime.now(UTC),
        is_malicious=bool(row["is_malicious"]),
        is_unverified=bool(row["is_unverified"]),
    )


def query_threats_by_source(
    conn: sqlite3.Connection,
    ecosystem: str,
    source: str,
    ingested_since: str | None = None,
) -> list[dict[str, Any]]:
    """Query threats table by ecosystem and source, optionally filtered by ingested_at.

    Args:
        conn: Database connection.
        ecosystem: Ecosystem to filter by (e.g. ``"homebrew"``).
        source: Source to filter by (e.g. ``"homebrew_osv"``).
        ingested_since: ISO 8601 timestamp — only return records ingested at
            or after this time.

    Returns:
        List of dicts with threat record data.
    """
    query = "SELECT * FROM threats WHERE ecosystem = ? AND source = ?"
    params: list[str] = [ecosystem, source]
    if ingested_since is not None:
        query += " AND ingested_at >= ?"
        params.append(ingested_since)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(query, params)
    return [dict(row) for row in cursor.fetchall()]


# ---------------------------------------------------------------------------
# Resolution Attempts CRUD
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ResolutionAttemptRow:
    """A row from the ``resolution_attempts`` table.

    Attributes:
        ecosystem: Package ecosystem (e.g., ``"npm"``, ``"pypi"``).
        package_name: Package name.
        version: Version string.
        publish_time: The resolved publish timestamp, or ``None`` when
            resolution failed.
        resolution_status: One of :data:`VALID_RESOLUTION_STATUSES`.
        source_label: The tier that succeeded (e.g., ``"github_tags"``)
            or failure category.
        last_error: Human-readable error detail from the resolver.
        attempted_at: When this resolution attempt was made.
        retry_after: Computed TTL expiry for retry, or ``None``.
    """

    ecosystem: str
    package_name: str
    version: str
    publish_time: datetime | None
    resolution_status: str
    source_label: str
    last_error: str | None
    attempted_at: datetime
    retry_after: datetime | None


def insert_resolution_attempt(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_name: str,
    version: str,
    publish_time: datetime | None,
    resolution_status: str,
    source_label: str = "",
    last_error: str | None = None,
    retry_after: datetime | None = None,
    *,
    commit: bool = True,
) -> None:
    """Insert or replace a resolution attempt record.

    Uses ``ON CONFLICT DO UPDATE`` so only the latest attempt per
    package-version is kept (one row per PK).

    Args:
        conn: Open database connection.
        ecosystem: Package ecosystem.
        package_name: Package name.
        version: Version string.
        publish_time: Resolved publish timestamp, or ``None`` on failure.
        resolution_status: One of :data:`VALID_RESOLUTION_STATUSES`.
        source_label: The tier that succeeded or failure category.
        last_error: Human-readable error detail.
        retry_after: TTL expiry for retry, or ``None``.
        commit: If ``True`` (default), commit after insert.
    """
    # Validate ecosystem against CHECK constraint
    if ecosystem not in VALID_ECOSYSTEMS:
        logger.warning(
            "Skipping resolution attempt: invalid ecosystem '%s'.",
            ecosystem,
        )
        return

    # Validate resolution_status against CHECK constraint
    if resolution_status not in VALID_RESOLUTION_STATUSES:
        logger.warning(
            "Skipping resolution attempt: invalid resolution_status '%s'.",
            resolution_status,
        )
        return

    # Format publish_time as ISO 8601 with Z suffix (or None)
    pub_time_str: str | None = None
    if publish_time is not None:
        dt = publish_time
        dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
        pub_time_str = _format_utc_z(dt)

    # Format retry_after as ISO 8601 with Z suffix (or None)
    retry_after_str: str | None = None
    if retry_after is not None:
        ra = retry_after
        ra = ra.replace(tzinfo=UTC) if ra.tzinfo is None else ra.astimezone(UTC)
        retry_after_str = _format_utc_z(ra)

    conn.execute(
        """
        INSERT INTO resolution_attempts
            (ecosystem, package_name, version, publish_time, resolution_status,
             source_label, last_error, retry_after)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ecosystem, package_name, version) DO UPDATE SET
            publish_time       = excluded.publish_time,
            resolution_status  = excluded.resolution_status,
            source_label       = excluded.source_label,
            last_error         = excluded.last_error,
            attempted_at       = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
            retry_after        = excluded.retry_after
        """,
        (
            ecosystem,
            package_name,
            version,
            pub_time_str,
            resolution_status,
            source_label,
            last_error,
            retry_after_str,
        ),
    )
    if commit:
        conn.commit()


def get_resolution_attempt(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_name: str,
    version: str,
) -> ResolutionAttemptRow | None:
    """Look up a single resolution attempt by composite primary key.

    Args:
        conn: Open database connection.
        ecosystem: Package ecosystem.
        package_name: Package name.
        version: Version string.

    Returns:
        A :class:`ResolutionAttemptRow`, or ``None`` if not found.
    """
    row = conn.execute(
        """
        SELECT ecosystem, package_name, version, publish_time,
               resolution_status, source_label, last_error,
               attempted_at, retry_after
        FROM resolution_attempts
        WHERE ecosystem = ? AND package_name = ? AND version = ?
        """,
        (ecosystem, package_name, version),
    ).fetchone()
    if row is None:
        return None
    return _row_to_resolution_attempt(row)


def get_resolution_attempts_batch(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_versions: list[tuple[str, str]],
) -> dict[tuple[str, str, str], ResolutionAttemptRow]:
    """Look up resolution attempts for multiple package versions.

    Executes 1 SQL query instead of N queries for the same ecosystem,
    following the :func:`get_version_timestamps_batch` pattern.

    Args:
        conn: Open database connection.
        ecosystem: Package ecosystem.
        package_versions: List of ``(package_name, version)`` tuples.

    Returns:
        Dict mapping ``(ecosystem, package_name, version)`` to
        :class:`ResolutionAttemptRow`. Only entries found are included.
    """
    if not package_versions:
        return {}

    placeholders = " OR ".join(["(package_name = ? AND version = ?)"] * len(package_versions))
    params = [ecosystem] + [v for pkg, ver in package_versions for v in (pkg, ver)]

    rows = conn.execute(
        f"SELECT ecosystem, package_name, version, publish_time,"
        f" resolution_status, source_label, last_error,"
        f" attempted_at, retry_after"
        f" FROM resolution_attempts WHERE ecosystem = ?"
        f" AND ({placeholders})",
        params,
    ).fetchall()

    results: dict[tuple[str, str, str], ResolutionAttemptRow] = {}
    for row in rows:
        key = (row[0], row[1], row[2])
        results[key] = _row_to_resolution_attempt(row)
    return results


def cleanup_expired_resolution_attempts(
    conn: sqlite3.Connection,
    *,
    commit: bool = True,
) -> int:
    """Delete resolution attempts where ``retry_after`` has passed.

    Only removes rows whose ``retry_after`` is in the past and whose
    ``resolution_status`` is not ``'resolved'``.

    Args:
        conn: Open database connection.
        commit: If ``True`` (default), commit after delete.

    Returns:
        Number of rows deleted.
    """
    cursor = conn.execute(
        """
        DELETE FROM resolution_attempts
        WHERE retry_after IS NOT NULL
          AND retry_after < strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
          AND resolution_status != 'resolved'
        """
    )
    deleted = cursor.rowcount
    if commit:
        conn.commit()
    return deleted


def _row_to_resolution_attempt(row: sqlite3.Row) -> ResolutionAttemptRow:
    """Convert a raw DB row into a :class:`ResolutionAttemptRow`.

    Uses column-name access for resilience against future schema changes.
    """
    return ResolutionAttemptRow(
        ecosystem=row["ecosystem"],
        package_name=row["package_name"],
        version=row["version"],
        publish_time=(datetime.fromisoformat(row["publish_time"]) if row["publish_time"] is not None else None),
        resolution_status=row["resolution_status"],
        source_label=row["source_label"],
        last_error=row["last_error"],
        attempted_at=(
            datetime.fromisoformat(row["attempted_at"]) if row["attempted_at"] is not None else datetime.now(UTC)
        ),
        retry_after=(datetime.fromisoformat(row["retry_after"]) if row["retry_after"] is not None else None),
    )


# ---------------------------------------------------------------------------
# Version Timestamp CRUD
# ---------------------------------------------------------------------------


def insert_version_timestamp(conn: sqlite3.Connection, info: VersionInfo, *, commit: bool = True) -> None:
    """Insert or replace a cached version publish timestamp.

    UTC-normalizes the publish_time, classifies its precision,
    maps the date_source to a trust level, and stores cache TTL.

    Args:
        conn: Open database connection.
        info: VersionInfo containing ecosystem, package, version, publish_time,
            and optionally date_source to determine trust_level.
        commit: If ``True`` (default), commit after insert. Set to ``False``
            when the caller manages the transaction boundary (e.g. batch inserts).
    """
    # Validate publish_time is not None (schema says NOT NULL)
    if info.publish_time is None:
        logger.warning(
            f"Skipping version timestamp for {info.ecosystem}/{info.package_name}@{info.version}: publish_time is None."
        )
        return

    # Validate ecosystem against CHECK constraint
    if info.ecosystem not in VALID_ECOSYSTEMS:
        logger.warning(f"Skipping version timestamp: invalid ecosystem '{info.ecosystem}'.")
        return

    # UTC-normalize: coerce naive to UTC, convert aware to UTC
    dt = info.publish_time
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)

    # Format as ISO 8601 with Z suffix
    formatted = _format_utc_z(dt)

    # Determine trust_level from date_source via SOURCE_TRUST_MAP
    date_source = info.date_source or ""
    trust_level = SOURCE_TRUST_MAP.get(date_source, "unknown")

    # Precision classification
    precision = classify_precision(dt)

    # Resolved-at timestamp (when this entry was written)
    resolved_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Cache TTL from trust level
    cache_ttl_days = TRUST_TTL_MAP.get(trust_level, 1)

    conn.execute(
        """
        INSERT INTO version_timestamps
            (ecosystem, package_name, version, publish_time, trust_level, source_label,
             precision, resolved_at, cache_ttl_days)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ecosystem, package_name, version) DO UPDATE SET
            publish_time   = excluded.publish_time,
            trust_level    = excluded.trust_level,
            source_label   = excluded.source_label,
            precision      = excluded.precision,
            resolved_at    = excluded.resolved_at,
            cache_ttl_days = excluded.cache_ttl_days
        """,
        (
            info.ecosystem,
            info.package_name,
            info.version,
            formatted,
            trust_level,
            date_source,
            precision,
            resolved_at,
            cache_ttl_days,
        ),
    )
    if commit:
        conn.commit()


def get_version_timestamp(
    conn: sqlite3.Connection,
    ecosystem: str,
    package: str,
    version: str,
) -> datetime | None:
    """Look up a cached publish timestamp.

    Args:
        conn: Open database connection.
        ecosystem: Ecosystem identifier.
        package: Package name.
        version: Version string.

    Returns:
        The publish_time as a datetime, or None if not cached.
    """
    row = conn.execute(
        """
        SELECT publish_time FROM version_timestamps
        WHERE ecosystem = ? AND package_name = ? AND version = ?
        """,
        (ecosystem, package, version),
    ).fetchone()
    if row is None:
        return None
    return datetime.fromisoformat(row[0])


def get_version_timestamps_batch(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_versions: list[tuple[str, str]],
) -> dict[tuple[str, str, str], tuple[datetime, str]]:
    """Look up cached publish timestamps for multiple package versions.

    Executes 1 SQL query instead of N queries for the same ecosystem.
    This eliminates the N+1 pattern where get_version_timestamp() is
    called per-package in a loop.

    Args:
        conn: Open SQLite connection.
        ecosystem: Ecosystem identifier (e.g., "pypi", "npm").
        package_versions: List of (package_name, version) tuples.

    Returns:
        Dict mapping (ecosystem, package_name, version) -> publish_time.
        Only entries found in the cache are included.
    """
    if not package_versions:
        return {}

    # Build dynamic WHERE clause with parameterized placeholders
    # SQLite doesn't support IN (VALUES ...) with tuples, so we use OR
    placeholders = " OR ".join(["(package_name = ? AND version = ?)"] * len(package_versions))
    params = [ecosystem] + [v for pkg, ver in package_versions for v in (pkg, ver)]

    rows = conn.execute(
        f"SELECT package_name, version, publish_time, source_label"
        f" FROM version_timestamps WHERE ecosystem = ? AND ({placeholders})",
        params,
    ).fetchall()

    results: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    for row in rows:
        pkg_name = row[0]
        ver = row[1]
        pub_time = row[2]
        source_label = row[3]  # source_label column — the original source string
        if isinstance(pub_time, datetime):
            results[(ecosystem, pkg_name, ver)] = (pub_time, source_label)
        else:
            results[(ecosystem, pkg_name, ver)] = (datetime.fromisoformat(pub_time), source_label)

    return results


def get_all_version_timestamps_for_package(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_name: str,
) -> list[tuple[str, str]]:
    """Fetch all cached version timestamps for a given package.

    Returns list of (version, publish_time) tuples ordered by publish_time
    descending. Returns empty list if no data is cached.

    Args:
        conn: Database connection.
        ecosystem: Package ecosystem (e.g., "pypi", "npm").
        package_name: Name of the package.

    Returns:
        Empty list when no cached data.
    """
    rows = conn.execute(
        "SELECT version, publish_time FROM version_timestamps "
        "WHERE ecosystem = ? AND package_name = ? "
        "ORDER BY publish_time DESC",
        (ecosystem, package_name),
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


# ---------------------------------------------------------------------------
# Bypass CRUD
# ---------------------------------------------------------------------------


def insert_bypass(
    conn: sqlite3.Connection,
    ecosystem: str,
    package: str,
    version: str,
    threat_id: str | None,
    reason: str,
    expires_at: datetime | None = None,
    user: str | None = None,
    *,
    commit: bool = True,
    checks_performed: str = "bypassed",
) -> None:
    """Record a bypass audit entry.

    Args:
        conn: Open database connection.
        ecosystem: Ecosystem identifier.
        package: Package name.
        version: Version string.
        threat_id: Optional threat ID that was bypassed.
        reason: Human-readable reason for the bypass.
        expires_at: Optional expiration datetime.
        user: OS username creating the bypass. If None, auto-detected
            via ``getpass.getuser()`` with ``"unknown"`` fallback.
        commit: If ``True`` (default), commit after insert.
        checks_performed: Which checks ran before bypass.
            One of 'none', 'threat_only', 'cooldown_only', 'full', 'bypassed'.
    """
    # Validate ecosystem against CHECK constraint
    if ecosystem not in VALID_ECOSYSTEMS:
        logger.warning(f"Skipping bypass: invalid ecosystem '{ecosystem}'.")
        return

    # Validate checks_performed
    valid_checks = ("none", "threat_only", "cooldown_only", "full", "bypassed")
    if checks_performed not in valid_checks:
        raise ValueError(f"Invalid checks_performed '{checks_performed}'. Must be one of {valid_checks}.")

    # Resolve user attribution
    if user is None:
        try:
            user = getpass.getuser()
        except Exception:
            logger.debug("insert_bypass: getpass.getuser() failed, using 'unknown'", exc_info=True)
            user = "unknown"

    conn.execute(
        """
        INSERT INTO bypasses
            (ecosystem, package_name, version, threat_id, reason, expires_at, checks_performed, user)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ecosystem,
            package,
            version,
            threat_id,
            reason,
            expires_at.isoformat() if expires_at else None,
            checks_performed,
            user,
        ),
    )
    if commit:
        conn.commit()


# ---------------------------------------------------------------------------
# Audit Events CRUD
# ---------------------------------------------------------------------------


def insert_audit_event(
    conn: sqlite3.Connection,
    ecosystem: str,
    package_name: str,
    version: str | None,
    action: str,
    risk_level: str,
    source: str,
    manager: str,
    subcommand: str | None,
    verdict: str,
    exit_code: int,
    error_message: str | None = None,
    threat_count_general: int = 0,
    threat_count_versioned: int = 0,
    cooldown_pass: bool = True,
    cooldown_days_remaining: int = 0,
    ci_mode: bool = False,
    runtime_ms: int | None = None,
    user: str | None = None,
    session_id: str | None = None,
    *,
    commit: bool = True,
    fail_on_threat_enabled: bool = True,
    cooldown_enabled: bool = True,
    coverage_tier: str = "full",
) -> int:
    """Insert an audit event record.

    Args:
        conn: Open database connection.
        ecosystem: Package ecosystem (npm, pypi, etc.)
        package_name: Package name audited.
        version: Version audited (if resolved).
        action: Action type (install, update, etc.)
        risk_level: Risk classification (critical, important, watch).
        source: Invocation source (shell_hook, cli, api, etc.)
        manager: Package manager (npm, pip, brew, etc.)
        subcommand: Subcommand used (install, add, etc.)
        verdict: Final verdict (PASS, FAIL, etc.)
        exit_code: Exit code returned (0=proceed, 1=block, 2=ci-block)
        error_message: Error message if audit failed.
        threat_count_general: Count of threats for any version.
        threat_count_versioned: Count of threats for this version.
        cooldown_pass: Boolean - cooldown check passed.
        cooldown_days_remaining: Days remaining in cooldown window.
        ci_mode: Boolean - CI mode was enabled.
        runtime_ms: Execution time in milliseconds.
        user: OS username (if available).
        session_id: Unique session identifier for grouping.
        commit: If True (default), commit after insert.
        fail_on_threat_enabled: Boolean - whether fail-on-threat was active.
        cooldown_enabled: Boolean - whether cooldown checking was active.
        coverage_tier: Coverage tier string (full|partial|audit).

    Returns:
    The rowid of the inserted event.
    """
    # Validate ecosystem against CHECK constraint
    if ecosystem not in VALID_ECOSYSTEMS:
        logger.warning(f"Skipping audit event: invalid ecosystem '{ecosystem}'.")
        return 0

    # Validate manager against known managers
    if manager not in VALID_MANAGERS:
        logger.warning(f"Skipping audit event: invalid manager '{manager}'.")
        return 0

    # Validate exit_code range (0-255 per POSIX)
    if exit_code < 0 or exit_code > 255:
        logger.warning(f"Skipping audit event: exit_code {exit_code} out of range [0, 255].")
        return 0

    # Validate threat counts are non-negative
    if threat_count_general < 0:
        logger.warning(f"Skipping audit event: threat_count_general {threat_count_general} < 0.")
        return 0

    if threat_count_versioned < 0:
        logger.warning(f"Skipping audit event: threat_count_versioned {threat_count_versioned} < 0.")
        return 0

    # Validate runtime_ms is non-negative if provided
    if runtime_ms is not None and runtime_ms < 0:
        logger.warning(f"Skipping audit event: runtime_ms {runtime_ms} < 0.")
        return 0

    # Validate fail_on_threat_enabled is boolean
    if not isinstance(fail_on_threat_enabled, bool):
        logger.warning("Skipping audit event: fail_on_threat_enabled is not boolean.")
        return 0

    # Validate cooldown_enabled is boolean
    if not isinstance(cooldown_enabled, bool):
        logger.warning("Skipping audit event: cooldown_enabled is not boolean.")
        return 0

    # Validate coverage_tier is an allowed value
    if coverage_tier not in ("full", "partial", "audit"):
        logger.warning(f"Skipping audit event: invalid coverage_tier '{coverage_tier}'.")
        return 0

    cursor = conn.execute(
        """
        INSERT INTO audit_events (
            ecosystem, package_name, version, action, risk_level, source, manager,
            subcommand, verdict, exit_code, error_message, threat_count_general,
            threat_count_versioned, cooldown_pass, cooldown_days_remaining,
            ci_mode, runtime_ms, user, session_id,
            fail_on_threat_enabled, cooldown_enabled, coverage_tier
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ecosystem,
            package_name,
            version,
            action,
            risk_level,
            source,
            manager,
            subcommand,
            verdict,
            exit_code,
            error_message,
            threat_count_general,
            threat_count_versioned,
            1 if cooldown_pass else 0,
            cooldown_days_remaining,
            1 if ci_mode else 0,
            runtime_ms,
            user,
            session_id,
            1 if fail_on_threat_enabled else 0,
            1 if cooldown_enabled else 0,
            coverage_tier,
        ),
    )
    if commit:
        conn.commit()
    # lastrowid can be None if no insert happened - return 0 as fallback
    return cursor.lastrowid if cursor.lastrowid is not None else 0


def get_audit_events(
    conn: sqlite3.Connection,
    ecosystem: str | None = None,
    package_name: str | None = None,
    verdict: str | None = None,
    source: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query audit events with filters.

    Args:
        conn: Open database connection.
        ecosystem: Filter by ecosystem (e.g., 'npm', 'pypi')
        package_name: Filter by package name.
        verdict: Filter by verdict (e.g., 'FAIL', 'BLOCKED')
        source: Filter by source (e.g., 'shell_hook', 'cli')
        since: Filter events after this datetime.
        until: Filter events before this datetime.
        limit: Maximum events to return.

    Returns:
        List of audit event dictionaries.
    """
    query = (
        "SELECT id, timestamp, ecosystem, package_name, version, action, "
        "risk_level, source, manager, subcommand, verdict, exit_code, "
        "error_message, threat_count_general, threat_count_versioned, "
        "cooldown_pass, cooldown_days_remaining, ci_mode, runtime_ms, "
        "user, session_id, "
        "fail_on_threat_enabled, cooldown_enabled, coverage_tier "
        "FROM audit_events WHERE 1=1"
    )
    params: list[Any] = []

    if ecosystem:
        query += " AND ecosystem = ?"
        params.append(ecosystem)
    if package_name:
        query += " AND package_name = ?"
        params.append(package_name)
    if verdict:
        query += " AND verdict = ?"
        params.append(verdict)
    if source:
        query += " AND source = ?"
        params.append(source)
    if since:
        query += " AND timestamp >= ?"
        params.append(since.isoformat())
    if until:
        query += " AND timestamp <= ?"
        params.append(until.isoformat())

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [_row_to_audit_event(row) for row in rows]


def _row_to_audit_event(row: sqlite3.Row) -> dict[str, Any]:
    """Convert an audit_events table row into a dictionary.

    Uses column-name access for resilience against future schema changes.
    """
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "ecosystem": row["ecosystem"],
        "package_name": row["package_name"],
        "version": row["version"],
        "action": row["action"],
        "risk_level": row["risk_level"],
        "source": row["source"],
        "manager": row["manager"],
        "subcommand": row["subcommand"],
        "verdict": row["verdict"],
        "exit_code": row["exit_code"],
        "error_message": row["error_message"],
        "threat_count_general": row["threat_count_general"],
        "threat_count_versioned": row["threat_count_versioned"],
        "cooldown_pass": bool(row["cooldown_pass"]),
        "cooldown_days_remaining": row["cooldown_days_remaining"],
        "ci_mode": bool(row["ci_mode"]),
        "runtime_ms": row["runtime_ms"],
        "user": row["user"],
        "session_id": row["session_id"],
        "fail_on_threat_enabled": bool(row["fail_on_threat_enabled"]),
        "cooldown_enabled": bool(row["cooldown_enabled"]),
        "coverage_tier": row["coverage_tier"],
    }


def get_audit_event_stats(
    conn: sqlite3.Connection,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, Any]:
    """Get aggregate statistics on audit events.

    Args:
        conn: Open database connection.
        since: Filter events after this datetime.
        until: Filter events before this datetime.

    Returns:
        Dict with counts by verdict, ecosystem, source.
    """
    query = "1=1"
    params: list[Any] = []

    if since:
        query += " AND timestamp >= ?"
        params.append(since.isoformat())
    if until:
        query += " AND timestamp <= ?"
        params.append(until.isoformat())

    # Total count
    total = conn.execute(
        f"SELECT COUNT(*) FROM audit_events WHERE {query}",
        params,
    ).fetchone()[0]

    # Count by verdict
    verdict_query = f"""
        SELECT verdict, COUNT(*) as cnt
        FROM audit_events
        WHERE {query}
        GROUP BY verdict
    """
    verdict_rows = conn.execute(verdict_query, params).fetchall()
    by_verdict = {row[0]: row[1] for row in verdict_rows}

    # Count by ecosystem
    eco_query = f"""
        SELECT ecosystem, COUNT(*) as cnt
        FROM audit_events
        WHERE {query}
        GROUP BY ecosystem
    """
    eco_rows = conn.execute(eco_query, params).fetchall()
    by_ecosystem = {row[0]: row[1] for row in eco_rows}

    # Count by source
    source_query = f"""
        SELECT source, COUNT(*) as cnt
        FROM audit_events
        WHERE {query}
        GROUP BY source
    """
    source_rows = conn.execute(source_query, params).fetchall()
    by_source = {row[0]: row[1] for row in source_rows}

    return {
        "total": total,
        "by_verdict": by_verdict,
        "by_ecosystem": by_ecosystem,
        "by_source": by_source,
    }


# ---------------------------------------------------------------------------
# Feed State CRUD
# ---------------------------------------------------------------------------


def update_feed_state(
    conn: sqlite3.Connection,
    feed_name: str,
    cursor: str | None,
    status: str,
    error_message: str | None = None,
    update_last_sync: bool = True,
    commit: bool = True,
) -> None:
    """Insert or replace feed sync state.

    Args:
        conn: Open database connection.
        feed_name: Unique feed identifier.
        cursor: Opaque pagination cursor (or None).
        status: One of ``'idle'``, ``'syncing'``, ``'error'``, ``'disabled'``,
            ``'not_configured'``, ``'circuit_open'``.
        error_message: Optional error detail.
        update_last_sync: If ``True`` (default), update ``last_sync`` to current
            time. If ``False``, preserve the existing ``last_sync`` value.
        commit: If ``True`` (default), commit after write. Set to ``False``
            when the caller manages the transaction boundary.
    """
    if update_last_sync:
        conn.execute(
            """
            INSERT OR REPLACE INTO feed_state
                (feed_name, last_sync, cursor, status, error_message, updated_at)
            VALUES (?, datetime('now'), ?, ?, ?, datetime('now'))
            """,
            (feed_name, cursor, status, error_message),
        )
    else:
        # Preserve existing last_sync
        conn.execute(
            """
            INSERT OR REPLACE INTO feed_state
                (feed_name, last_sync, cursor, status, error_message, updated_at)
            VALUES (
                ?,
                COALESCE((SELECT last_sync FROM feed_state WHERE feed_name = ?), NULL),
                ?, ?, ?, datetime('now')
            )
            """,
            (feed_name, feed_name, cursor, status, error_message),
        )
    if commit:
        conn.commit()


def get_feed_state(conn: sqlite3.Connection, feed_name: str) -> dict[str, str | None] | None:
    """Retrieve feed sync state as a dictionary.

    Args:
        conn: Open database connection.
        feed_name: Unique feed identifier.

    Returns:
        A dict with keys ``feed_name``, ``last_sync``, ``cursor``,
        ``status``, ``error_message``, ``updated_at`` — or None.
    """
    row = conn.execute(
        "SELECT feed_name, last_sync, cursor, status, error_message, updated_at FROM feed_state WHERE feed_name = ?",
        (feed_name,),
    ).fetchone()
    if row is None:
        return None
    return {
        "feed_name": row[0],
        "last_sync": row[1],
        "cursor": row[2],
        "status": row[3],
        "error_message": row[4],
        "updated_at": row[5],
    }


def insert_feed_stats(
    conn: sqlite3.Connection,
    feed_name: str,
    record_count: int,
    avg_confidence: float | None,
    skipped_count: int = 0,
) -> None:
    """Record a feed sync statistics snapshot.

    Args:
        conn: Open database connection.
        feed_name: Unique feed identifier.
        record_count: Number of threat records synced.
        avg_confidence: Average confidence of all records (None if 0 records).
        skipped_count: Number of records skipped by validation (default: 0).
    """
    conn.execute(
        """
        INSERT OR REPLACE INTO feed_stats (feed_name, synced_at, record_count, avg_confidence, skipped_count)
        VALUES (?, datetime('now'), ?, ?, ?)
        """,
        (feed_name, record_count, avg_confidence, skipped_count),
    )
    # Prune old stats: keep only the 30 most recent entries per feed
    conn.execute(
        """
        DELETE FROM feed_stats
        WHERE rowid IN (
            SELECT rowid FROM feed_stats
            WHERE feed_name = ?
            ORDER BY synced_at DESC
            LIMIT -1 OFFSET 30
        )
        """,
        (feed_name,),
    )
    conn.commit()


def insert_feed_stats_thread(
    db_path: Path,
    feed_name: str,
    record_count: int,
    avg_confidence: float | None,
    skipped_count: int = 0,
    config: DatabaseConfig | None = None,
) -> None:
    """Thread-safe wrapper around insert_feed_stats.

    Creates its own connection inside the thread. Use when calling from
    ``asyncio.to_thread()`` to avoid passing sqlite3.Connection across threads.

    Args:
        db_path: Path to the SQLite database file.
        feed_name: Unique feed identifier.
        record_count: Number of threat records synced.
        avg_confidence: Average confidence of all records.
        skipped_count: Number of records skipped by validation (default: 0).
        config: Optional DatabaseConfig for PRAGMA settings.
    """
    conn = get_connection(db_path, config=config)
    try:
        insert_feed_stats(conn, feed_name, record_count, avg_confidence, skipped_count=skipped_count)
    finally:
        conn.close()


def get_feed_stats_history(
    conn: sqlite3.Connection,
    feed_name: str,
    days: int = 7,
) -> list[dict[str, Any]]:
    """Get sync statistics history for a feed.

    Args:
        conn: Open database connection.
        feed_name: Unique feed identifier.
        days: Number of days of history to retrieve (default: 7).

    Returns:
        List of dicts with keys: feed_name, synced_at, record_count,
        avg_confidence, skipped_count. Ordered by synced_at DESC. May be
        empty if no history exists.
    """
    rows = conn.execute(
        """
        SELECT feed_name, synced_at, record_count, avg_confidence, skipped_count
        FROM feed_stats
        WHERE feed_name = ?
          AND synced_at >= datetime('now', ?)
        ORDER BY synced_at DESC
        """,
        (feed_name, f"-{days} days"),
    ).fetchall()
    return [
        {
            "feed_name": row[0],
            "synced_at": row[1],
            "record_count": row[2],
            "avg_confidence": row[3],
            "skipped_count": row[4],
        }
        for row in rows
    ]


def get_feed_stats_history_thread(
    db_path: Path,
    feed_name: str,
    days: int = 7,
    config: DatabaseConfig | None = None,
) -> list[dict[str, Any]]:
    """Thread-safe wrapper around get_feed_stats_history.

    Creates its own connection inside the thread. Use when calling from
    ``asyncio.to_thread()`` to avoid passing sqlite3.Connection across threads.

    Args:
        db_path: Path to the SQLite database file.
        feed_name: Unique feed identifier.
        days: Number of days of history to retrieve.
        config: Optional DatabaseConfig for PRAGMA settings.

    Returns:
        Same as get_feed_stats_history.
    """
    conn = get_connection(db_path, config=config)
    try:
        return get_feed_stats_history(conn, feed_name, days=days)
    finally:
        conn.close()
