"""Shared audit types extracted from pipeline for cross-module use."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Verdict(StrEnum):
    """Audit verdict classification.

    Per spec Section 6: Maps to exit codes and user prompts.
    """

    PASS = "PASS"
    PARTIAL_PASS = "PARTIAL_PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"  # Hard block (critical threat, no bypass)
    WARN = "WARN"  # Watch-level risk, proceed with warning
    ERROR = "ERROR"  # Error during audit


@dataclass
class Threat:
    """A threat record for display."""

    severity: str
    summary: str
    source: str
    score: float = 0.0


@dataclass
class AuditResult:
    """Result of the audit pipeline for a single package."""

    package: str
    ecosystem: str
    version: str | None
    release_date: datetime | None
    threats_all: list[Threat] = field(default_factory=list)
    threats_versioned: list[Threat] = field(default_factory=list)
    cooldown_pass: bool = True
    cooldown_days_remaining: int = 0
    cooldown_window_days: int = 3
    overall_verdict: Verdict = Verdict.PASS
    verdict_reason: str = ""
    exit_code: int = 0
