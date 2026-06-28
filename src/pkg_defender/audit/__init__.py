"""Audit module for the hooks package.

Exports the audit pipeline and related types for use by the dispatcher.
"""

from __future__ import annotations

from pkg_defender.audit.cooldown import (
    get_cooldown_window,
    step_check_cooldown,
)
from pkg_defender.audit.types import AuditResult, Threat, Verdict

__all__ = [
    "AuditResult",
    "Threat",
    "Verdict",
    "step_check_cooldown",
    "get_cooldown_window",
]
