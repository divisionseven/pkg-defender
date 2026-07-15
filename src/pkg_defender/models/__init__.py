# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Data models for pkg-defender command parsing."""

from __future__ import annotations

from typing import TYPE_CHECKING

# Import command models from the command submodule
from pkg_defender.models.command import (
    Action,
    BlockReason,
    CommandIntent,
    InstallSource,
    PackageRef,
    ParsedCommand,
    RiskLevel,
    action_to_intent,
)

# Import root model classes for type checking and runtime
if TYPE_CHECKING:
    from pkg_defender.models.models import (
        AuditCooldownEntry,
        AuditThreatEntry,
        CheckResult,
        CooldownResult,
        PackageAuditResult,
        ScoredThreat,
        ThreatRecord,
        VersionInfo,
    )

# Export for runtime use (these work through lazy loading via __getattr__ below)
# but explicitly re-export to satisfy type checkers
from pkg_defender.models.models import (
    AuditCooldownEntry,
    AuditThreatEntry,
    CheckResult,
    CooldownResult,
    PackageAuditResult,
    ScoredThreat,
    ThreatRecord,
    VersionInfo,
)

__all__ = [
    "Action",
    "BlockReason",
    "CommandIntent",
    "InstallSource",
    "PackageRef",
    "ParsedCommand",
    "RiskLevel",
    "ThreatRecord",
    "action_to_intent",
    "VersionInfo",
    "ScoredThreat",
    "CooldownResult",
    "CheckResult",
    "AuditThreatEntry",
    "AuditCooldownEntry",
    "PackageAuditResult",
]
