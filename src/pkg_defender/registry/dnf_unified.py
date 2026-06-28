"""Unified DNF adapter — YUM alias in the unified registry.

DnfUnifiedAdapter inherits from YumUnifiedAdapter — DNF uses the
same command-line interface, the same COMMAND_INTENT_MAP, and the
same registry backend (Bodhi → Koji → repodata cascade). The only
differences are ``manager_name`` and ``ecosystem``.
"""

from __future__ import annotations

from pkg_defender.registry.base import CoverageTier
from pkg_defender.registry.yum_unified import YumUnifiedAdapter


class DnfUnifiedAdapter(YumUnifiedAdapter):
    """Unified adapter for dnf — YUM alias.

    Inherits all registry delegation, command parsing, and exec-args
    building from :class:`YumUnifiedAdapter`. The only differences
    are the ``manager_name`` and ``ecosystem`` identity properties.
    """

    manager_name: str = "dnf"
    ecosystem: str = "dnf"
    coverage_tier: CoverageTier = CoverageTier.AUDIT
