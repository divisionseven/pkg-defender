"""Data models for pkg-defender."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class VersionInfo:
    """Cached publish timestamp for a specific package version."""

    version: str
    publish_time: datetime | None
    ecosystem: str
    package_name: str
    date_source: str | None = None


@dataclass
class ThreatRecord:
    """A threat intelligence record from a feed source."""

    id: str
    ecosystem: str
    package_name: str = "unknown"
    affected_versions: list[str] = field(default_factory=list)
    affected_ranges: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    confidence: float = 0.5
    source: str = ""
    source_id: str | None = None
    summary: str = ""
    detail_url: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    hit_count: int = 1
    cvss_score: float | None = None
    published_at: datetime | None = None
    ingested_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_malicious: bool = False
    is_unverified: bool = False


@dataclass
class ScoredThreat:
    """A threat record with computed score and display severity."""

    record: ThreatRecord
    final_score: float
    display_severity: str
    version_match_type: str


@dataclass
class CooldownResult:
    """Result of a cooldown check for a package version."""

    allowed: bool
    age: timedelta | None = None
    remaining: timedelta | None = None
    reason: str | None = None
    publish_time: datetime | None = None
    effective_cooldown_days: int | None = None
    safe_version: str | None = None
    date_source: str | None = None  # One of SOURCE_TRUST_MAP.keys() or None


@dataclass
class CheckResult:
    """Result of a threat check for a package version."""

    blocked: bool
    threats: list[ScoredThreat] = field(default_factory=list)
    highest_score: float = 0.0
    highest_severity: str = "UNKNOWN"
    safe_version: str | None = None


@dataclass
class AuditThreatEntry:
    """A single threat entry in an audit result."""

    package: str
    version: str
    ecosystem: str
    lock_file: str = ""  # Source lock file path (relative to project root)
    threats: list[ScoredThreat] = field(default_factory=list)
    transitive_path: list[str] | None = None
    safe_version: str | None = None


@dataclass
class AuditCooldownEntry:
    """A single cooldown entry in an audit result."""

    package: str
    version: str
    ecosystem: str
    lock_file: str = ""  # Source lock file path (relative to project root)
    age: timedelta = timedelta(0)
    clears_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    transitive_path: list[str] | None = None


@dataclass
class PackageAuditResult:
    """Full result of a lock file audit."""

    project_path: str
    lock_file: str
    total_packages: int
    threats: list[AuditThreatEntry] = field(default_factory=list)
    cooldown_pending: list[AuditCooldownEntry] = field(default_factory=list)
    passed: int = 0
    passed_packages: list[dict[str, str]] = field(default_factory=list)
    scan_time: datetime = field(default_factory=lambda: datetime.now(UTC))
