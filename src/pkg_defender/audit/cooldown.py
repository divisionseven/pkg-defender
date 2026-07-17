# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Cooldown checking — enforces minimum age before installing new packages.

Per spec Section 6 (Step 6) and Section 9.2: Checks the release date against
the user's configured cooldown window to reduce exposure to supply-chain
attacks that surface within the first days of a release.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from pkg_defender.models import VersionInfo

if TYPE_CHECKING:
    from pkg_defender.models import CooldownResult


class CooldownConfigLike(Protocol):
    """Protocol for cooldown config objects.

    This Protocol defines the interface that cooldown checking functions
    require, allowing for both dataclass-based configs and lightweight
    adapter objects that only provide the needed fields.

    Note: ``per_ecosystem`` is a read-only property so that concrete types
    with a non-optional ``dict[str, int]`` attribute (e.g. ``CooldownConfig``)
    satisfy the protocol covariant-wise.
    """

    default_days: int
    enabled: bool

    @property
    def per_ecosystem(self) -> dict[str, int] | None: ...


@dataclass
class ThreatCooldownContext:
    """Threat context for signal-based cooldown escalation (§8.3).

    Carries per-package threat intelligence from the threat-check phase
    into the cooldown-check phase, enabling dynamic cooldown window
    escalation based on signal type.

    Attributes:
        has_verified_advisory: True when at least one threat record has
            ``is_unverified=False`` (authoritative source like OSV, GHSA).
        has_tier3_signals: True when at least one threat record has
            ``is_unverified=True`` and the source is social-media-derived
            (Mastodon, Reddit, X/Twitter) or an unrecognized unverified source.
    """

    has_verified_advisory: bool = False
    has_tier3_signals: bool = False


def step_check_cooldown(
    release_date: datetime | None,
    config: CooldownConfigLike,
    ecosystem: str,
    override_hours: int | None = None,
    threat_context: ThreatCooldownContext | None = None,
    trust_level: str | None = None,
) -> tuple[bool, int]:
    """Check if the package release date is past the cooldown window.

        Per spec Section 6, Step 6: Compares release date against the user's
        configured cooldown window.

        Args:
            release_date: The UTC release date of the package version, or None if unknown.
            config: The cooldown configuration from settings.
            ecosystem: The package ecosystem (e.g., "npm", "pypi", "homebrew").
            override_hours: Optional override for the cooldown window in hours.
                When set, replaces the config-based window with ``ceil(override_hours / 24)``
                days (minimum 1 day). ``None`` uses the config-based window.
            threat_context: Optional threat intelligence context for signal-based
                cooldown escalation (§8.3). When present with ``has_verified_advisory``,
                the check returns ``(False, window)`` regardless of age. When present
                with ``has_tier3_signals``, the window is extended to a minimum of
                5 days. ``None`` (default) preserves baseline behavior.
            trust_level: Optional trust level of the date source (e.g. "verified",
                "claimed", "proxied", "unknown"). When ``"claimed"``, adds +2 days
                to the cooldown window per §6.4.2. ``None`` (default) preserves
                baseline behavior.

        Returns:
            Tuple of (passed: bool, days_remaining_in_cooldown: int):
                - passed: True if the package is old enough; False if within cooldown or date unknown
                - days_remaining: Days until cooldown window passes (0 if passed)

        Edge cases:
    - If release_date is None → fail-closed: return (False, <cooldown_window>) — unknown date = cooldown not passed
    - If release_date is in the future → treat as 0 days old
    """
    # Cooldown disabled — skip check entirely
    if not getattr(config, "enabled", True):
        return True, 0

    # Fail-closed: when date is unknown, report as cooldown-not-passed
    if release_date is None:
        window = config.default_days
        if config.per_ecosystem:
            window = config.per_ecosystem.get(ecosystem, config.default_days)
        if override_hours is not None:
            window = max(1, math.ceil(override_hours / 24))
        return False, window

    # Get the cooldown window for this ecosystem
    # First try config.per_ecosystem (TOML), fall back to config.default_days
    window = config.default_days
    if config.per_ecosystem:
        window = config.per_ecosystem.get(ecosystem, config.default_days)

    if override_hours is not None:
        window = max(1, math.ceil(override_hours / 24))

    # Trust-based cooldown penalty (§6.4.2)
    # Applied after override_hours so user overrides are respected first,
    # but before signal escalation so threat context can still override.
    if trust_level == "claimed":
        window += 2

    # Signal-based cooldown escalation (§8.3)
    # Applied after override_hours so user overrides cannot bypass
    # verified-advisory blocks.
    if threat_context is not None:
        if threat_context.has_verified_advisory:
            # Active advisory from an authoritative source → BLOCK
            # regardless of package age. Return the window as
            # days_remaining sentinel.
            return False, window

        if threat_context.has_tier3_signals and window < 5:
            # Tier 3 signal (social media mention) → extend window to
            # at least 5 days. Only raises the floor — existing windows
            # >= 5 days (npm: 7, pypi: 5) are unaffected.
            window = 5

    now = datetime.now(UTC)

    # Ensure release_date is timezone-aware to prevent TypeError
    if release_date.tzinfo is None:
        release_date = release_date.replace(tzinfo=UTC)

    # Handle future dates — treat as 0 days old
    age_days = 0 if release_date > now else (now - release_date).days

    if age_days >= window:
        return True, 0

    return False, window - age_days


def get_cooldown_window(config: CooldownConfigLike, ecosystem: str) -> int:
    """Get the cooldown window days for a given ecosystem.

    Args:
        config: The cooldown configuration from settings.
        ecosystem: The package ecosystem.

    Returns:
        The number of days in the cooldown window for this ecosystem.
    """
    if config.per_ecosystem:
        days = config.per_ecosystem.get(ecosystem, config.default_days)
        return int(days) if days is not None else config.default_days
    return config.default_days


def get_effective_cooldown(package: str, config: CooldownConfigLike) -> int:
    """Return the cooldown days for *package*, checking overrides first.

    Args:
        package: The package name to look up.
        config: Cooldown configuration containing default and per-package
            overrides.

    Returns:
        The number of cooldown days that apply to this package.
    """
    overrides: dict[str, int] = getattr(config, "overrides", {})
    if package in overrides:
        return overrides[package]
    return config.default_days


def _sort_key(version: VersionInfo) -> datetime:
    """Sort key for VersionInfo — None sorts last in descending order."""
    pt: datetime | None = version.publish_time
    if pt is None:
        return datetime.min.replace(tzinfo=UTC)
    if pt.tzinfo is None:
        pt = pt.replace(tzinfo=UTC)
    return pt


def find_safe_version(
    all_versions: list[VersionInfo],
    cooldown_days: int,
    now: datetime | None = None,
) -> str | None:
    """Find the latest version whose publish time is old enough to trust.

    Scans *all_versions* sorted by ``publish_time`` descending and returns the
    first entry whose age (``now - publish_time``) is >= *cooldown_days*.

    Args:
        all_versions: All known versions of a package.
        cooldown_days: Required age in days.
        now: Reference time (defaults to current UTC time).

    Returns:
        The version string of the newest safe version, or ``None`` if every
        version is still within the cooldown window.
    """
    if now is None:
        now = datetime.now(UTC)

    cooldown_td = timedelta(days=cooldown_days)
    sorted_versions = sorted(all_versions, key=_sort_key, reverse=True)

    for vi in sorted_versions:
        pt: datetime | None = vi.publish_time
        if pt is None:
            continue
        if pt.tzinfo is None:
            pt = pt.replace(tzinfo=UTC)
        age: timedelta = now - pt
        if age >= cooldown_td:
            ver: str = vi.version
            return ver

    return None


def check_cooldown(
    version_info: VersionInfo,
    config: CooldownConfigLike,
    all_versions: list[VersionInfo] | None = None,
    now: datetime | None = None,
    trust_level: str | None = None,
) -> CooldownResult:
    """Check whether a package version has aged past the cooldown window.

    This is a **pure function** — no network I/O, no DB access.  It takes
    version metadata, a cooldown config, and optionally the full version list
    (for safe-version suggestions).

    Args:
        version_info: The version being installed (must include publish_time).
        config: Cooldown configuration.
        all_versions: Optional list of every known version of this package.
            Used to suggest a safe alternative when the requested version is
            too new.
        now: Reference time for determinism in tests.
        trust_level: Optional trust level of the date source. When ``"claimed"``,
            adds +2 days to ``effective_cooldown_days`` per §6.4.2. ``None``
            (default) preserves baseline behavior.

    Returns:
        A ``CooldownResult`` indicating whether the install is allowed.
    """
    from pkg_defender.models import CooldownResult  # noqa: PLC0415

    if now is None:
        now = datetime.now(UTC)

    # Guard: publish_time must be present and timezone-aware for cooldown checks
    version_pt = version_info.publish_time
    if version_pt is None:
        raise ValueError("version_info.publish_time must not be None")
    if version_pt.tzinfo is None:
        version_pt = version_pt.replace(tzinfo=UTC)

    # 1. Cooldown disabled entirely
    if not getattr(config, "enabled", True):
        return CooldownResult(
            allowed=True,
            reason="ok",
            age=now - version_pt,
            remaining=None,
            publish_time=version_pt,
            effective_cooldown_days=0,
            safe_version=None,
        )

    # 2. Effective cooldown for this package
    cooldown_days = get_effective_cooldown(version_info.package_name, config)
    # Trust-based cooldown penalty (§6.4.2)
    if trust_level == "claimed":
        cooldown_days += 2
    cooldown_td = timedelta(days=cooldown_days)
    age = now - version_pt

    # 3. Old enough — allowed
    if age >= cooldown_td:
        return CooldownResult(
            allowed=True,
            reason="ok",
            age=age,
            remaining=None,
            publish_time=version_pt,
            effective_cooldown_days=cooldown_days,
            safe_version=None,
        )

    # 4. Too new — blocked
    remaining = cooldown_td - age
    safe_ver: str | None = None
    if all_versions is not None:
        safe_ver = find_safe_version(all_versions, cooldown_days, now)

    return CooldownResult(
        allowed=False,
        reason="too_new",
        age=age,
        remaining=remaining,
        publish_time=version_pt,
        effective_cooldown_days=cooldown_days,
        safe_version=safe_ver,
    )
