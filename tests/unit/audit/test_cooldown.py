"""Tests for the audit cooldown module.

Tests the step_check_cooldown() and related functions.
"""

from datetime import UTC, datetime, timedelta

from pkg_defender.audit.cooldown import (
    CooldownConfigLike,
    ThreatCooldownContext,
    get_cooldown_window,
    step_check_cooldown,
)


class _SimpleMockConfig:
    """Simple mock config that satisfies CooldownConfigLike protocol.

    Used in place of SimpleNamespace because the protocol requires
    ``per_ecosystem`` as a read-only property, which SimpleNamespace
    cannot provide via structural subtyping.
    """

    def __init__(
        self,
        default_days: int,
        per_ecosystem: dict[str, int] | None,
        enabled: bool = True,
    ) -> None:
        self.default_days = default_days
        self._per_ecosystem = per_ecosystem
        self.enabled = enabled

    @property
    def per_ecosystem(self) -> dict[str, int] | None:
        return self._per_ecosystem


class TestCooldownConfigLike:
    """Tests for CooldownConfigLike protocol."""

    def test_protocol_has_required_fields(self) -> None:
        """Protocol exposes ``default_days`` and ``per_ecosystem`` as required fields."""
        # default_days is an annotated instance variable
        assert "default_days" in CooldownConfigLike.__annotations__
        # per_ecosystem is a read-only property (covariant for structural subtyping)
        assert isinstance(CooldownConfigLike.__dict__.get("per_ecosystem"), property)


class TestStepCheckCooldown:
    """Tests for step_check_cooldown()."""

    def test_passed_cooldown(self) -> None:
        """Returns (True, 0) when package is beyond the cooldown window."""
        release_date = datetime.now(UTC) - timedelta(days=10)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(release_date, config, "pypi")

        assert passed is True
        assert days_remaining == 0

    def test_failed_cooldown(self) -> None:
        """Returns (False, 4) when package is within the cooldown window."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(release_date, config, "pypi")

        assert passed is False
        assert days_remaining == 4

    def test_none_release_date(self) -> None:
        """None release date should fail-closed (cooldown not passed)."""
        config = _SimpleMockConfig(default_days=5, per_ecosystem=None, enabled=True)
        passed, days_remaining = step_check_cooldown(None, config, "pypi")
        assert passed is False
        assert days_remaining == 5

    def test_returns_per_ecosystem_window_when_release_date_is_none(self) -> None:
        """None release date should use per_ecosystem window if available."""
        config = _SimpleMockConfig(default_days=5, per_ecosystem={"npm": 7}, enabled=True)
        passed, days_remaining = step_check_cooldown(None, config, "npm")
        assert passed is False
        assert days_remaining == 7

    def test_returns_default_days_window_when_release_date_is_none(self) -> None:
        """None release date should use config.default_days when no per_ecosystem configured."""
        config = _SimpleMockConfig(default_days=99, per_ecosystem=None, enabled=True)
        passed, days_remaining = step_check_cooldown(None, config, "pypi")
        assert passed is False
        assert days_remaining == 99  # config.default_days

    def test_override_hour_conversion_to_days(self) -> None:
        """48-hour override produces a 2-day window."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "pypi",
            override_hours=48,
        )

        assert passed is False
        assert days_remaining == 1  # 2-day window - 1 day age = 1 day remaining

    def test_override_hours_less_than_day(self) -> None:
        """12-hour override produces a 1-day window (ceil)."""
        release_date = datetime.now(UTC)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "pypi",
            override_hours=12,
        )

        assert passed is False
        assert days_remaining == 1  # 1-day window, age 0

    def test_override_none_is_noop(self) -> None:
        """None override produces identical result to not passing the parameter."""
        release_date = datetime.now(UTC) - timedelta(days=2)

        class MockConfig:
            default_days = 2
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        # Use "unknown" ecosystem — not a registered ecosystem, no special handling
        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "unknown",
            override_hours=None,
        )

        assert passed is True
        assert days_remaining == 0

    def test_override_applies_to_none_release_date(self) -> None:
        """When release_date is None, override_hours adjusts the fail-closed window."""
        config = _SimpleMockConfig(default_days=5, per_ecosystem=None, enabled=True)
        passed, days_remaining = step_check_cooldown(
            None,
            config,
            "pypi",
            override_hours=24,
        )
        assert passed is False
        assert days_remaining == 1  # 24h → 1 day, not config.default_days (5)

    # ------------------------------------------------------------------
    # Signal-based cooldown escalation tests (§8.3)
    # ------------------------------------------------------------------

    def test_no_threat_context_preserves_baseline(self) -> None:
        """No threat context → baseline behavior unchanged."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "pypi",
            threat_context=None,
        )

        assert passed is False
        assert days_remaining == 4

    def test_verified_advisory_blocks_regardless_of_age(self) -> None:
        """Verified advisory → BLOCKED even for very old package."""
        release_date = datetime.now(UTC) - timedelta(days=100)
        ctx = ThreatCooldownContext(has_verified_advisory=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "unknown",
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 3  # window = 3 (config.default_days)

    def test_verified_advisory_blocks_fresh_package(self) -> None:
        """Verified advisory → BLOCKED for recently released package."""
        release_date = datetime.now(UTC) - timedelta(hours=1)
        ctx = ThreatCooldownContext(has_verified_advisory=True)

        class MockConfig:
            default_days = 7
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 7  # window = 7

    def test_tier3_signal_extends_window_to_5_days(self) -> None:
        """Tier 3 signal with bundler (window 3) → escalates to 5, age 3 → blocked."""
        release_date = datetime.now(UTC) - timedelta(days=3)
        ctx = ThreatCooldownContext(has_tier3_signals=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "bundler",
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 2  # 5 - 3 = 2

    def test_tier3_signal_blocks_package_between_baseline_and_escalated_window(self) -> None:
        """Tier 3 signal with cargo (window 3) → escalates to 5, age 4 → blocked."""
        release_date = datetime.now(UTC) - timedelta(days=4)
        ctx = ThreatCooldownContext(has_tier3_signals=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "cargo",
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 1  # 5 - 4 = 1

    def test_tier3_signal_cooldown_satisfied_when_old_enough(self) -> None:
        """Tier 3 signal, age 8 ≥ 5 → cooldown satisfied."""
        release_date = datetime.now(UTC) - timedelta(days=8)
        ctx = ThreatCooldownContext(has_tier3_signals=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "bundler",
            threat_context=ctx,
        )

        assert passed is True
        assert days_remaining == 0

    def test_both_signals_advisory_wins(self) -> None:
        """Both signals (advisory + Tier 3) → advisory wins (BLOCK)."""
        release_date = datetime.now(UTC) - timedelta(days=10)
        ctx = ThreatCooldownContext(has_verified_advisory=True, has_tier3_signals=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "unknown",
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 3

    def test_verified_advisory_overrides_override_hours(self) -> None:
        """Verified advisory overrides --cooldown override."""
        release_date = datetime.now(UTC) - timedelta(days=10)
        ctx = ThreatCooldownContext(has_verified_advisory=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "pypi",
            override_hours=48,
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 2  # 48h → 2 day window

    def test_tier3_signal_sets_5_day_floor_with_override(self) -> None:
        """Tier 3 signal: --cooldown 1h override becomes 1d window, then escalated to 5d."""
        release_date = datetime.now(UTC) - timedelta(days=2)
        ctx = ThreatCooldownContext(has_tier3_signals=True)

        class MockConfig:
            default_days = 3
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "bundler",
            override_hours=24,
            threat_context=ctx,
        )

        assert passed is False
        assert days_remaining == 3  # max(1, ceil(24/24)) = 1 → escalated to 5, 5 - 2 = 3

    def test_naive_datetime_treated_as_utc(self) -> None:
        """Naive datetime is treated as UTC, not raising TypeError."""
        release_date = datetime(2026, 3, 1, 12, 0, 0)  # no tzinfo
        config = _SimpleMockConfig(default_days=5, per_ecosystem=None, enabled=True)
        # Should not raise TypeError
        passed, days_remaining = step_check_cooldown(release_date, config, "pypi")
        assert passed is True  # 5 days > age of naive date (well over 5 days ago)
        assert days_remaining == 0


class TestTrustPenalty:
    """Tests for the +2 claimed-timestamp penalty in step_check_cooldown()."""

    def test_claimed_adds_2_days_to_window(self) -> None:
        """trust_level='claimed' with 5-day default → window becomes 7."""
        release_date = datetime.now(UTC) - timedelta(days=3)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="claimed",
        )

        # 5+2 = 7 day window, 3 day old → 4 days remaining
        assert passed is False
        assert days_remaining == 4

    def test_claimed_with_per_ecosystem_window(self) -> None:
        """3-day per_ecosystem window + claimed → 5-day window."""
        release_date = datetime.now(UTC) - timedelta(days=2)

        class MockConfig:
            default_days = 1
            per_ecosystem = {"npm": 3}
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="claimed",
        )

        # 3+2 = 5 day window, 2 day old → 3 days remaining
        assert passed is False
        assert days_remaining == 3

    def test_claimed_with_override_hours(self) -> None:
        """24h override (1d) + claimed → 3d window."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            override_hours=24,
            trust_level="claimed",
        )

        # max(1, ceil(24/24)) = 1 + 2 = 3 day window, 1 day old → 2 days remaining
        assert passed is False
        assert days_remaining == 2

    def test_claimed_with_tier3_signal(self) -> None:
        """claimed +2, then tier3 escalates to max(window, 5)."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 1
            per_ecosystem = None
            enabled = True

        config = MockConfig()
        ctx = ThreatCooldownContext(has_tier3_signals=True)

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            threat_context=ctx,
            trust_level="claimed",
        )

        # Claimed: 1+2=3 → Tier 3: max(3, 5)=5, 1 day old → 4 remaining
        assert passed is False
        assert days_remaining == 4

    def test_claimed_already_passed_cooldown(self) -> None:
        """10-day-old release, 5-day window +2 = 7 → passed."""
        release_date = datetime.now(UTC) - timedelta(days=10)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed, days_remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="claimed",
        )

        # 5+2 = 7 day window, 10 day old → passed
        assert passed is True
        assert days_remaining == 0

    def test_verified_no_penalty(self) -> None:
        """Verified trust → same result as no trust_level."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed_no, _ = step_check_cooldown(release_date, config, "npm")
        passed_yes, remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="verified",
        )

        assert passed_no == passed_yes
        assert remaining == 4

    def test_proxied_no_penalty(self) -> None:
        """Proxied trust → no penalty."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        _, remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="proxied",
        )

        # 5 day window, 1 day old → 4 remaining (no penalty)
        assert remaining == 4

    def test_unknown_no_penalty(self) -> None:
        """Unknown trust → no penalty."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        _, remaining = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level="unknown",
        )

        assert remaining == 4

    def test_none_trust_level_backward_compat(self) -> None:
        """trust_level=None → same as baseline (backward compat)."""
        release_date = datetime.now(UTC) - timedelta(days=1)

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        passed_no, remaining_no = step_check_cooldown(release_date, config, "npm")
        passed_none, remaining_none = step_check_cooldown(
            release_date,
            config,
            "npm",
            trust_level=None,
        )

        assert passed_no == passed_none
        assert remaining_no == remaining_none


class TestThreatCooldownContext:
    """Tests for ThreatCooldownContext dataclass."""

    def test_has_defaults(self) -> None:
        """Default instance has both fields False."""
        ctx = ThreatCooldownContext()
        assert ctx.has_verified_advisory is False
        assert ctx.has_tier3_signals is False

    def test_verified_advisory_true(self) -> None:
        """Constructing with has_verified_advisory=True works."""
        ctx = ThreatCooldownContext(has_verified_advisory=True)
        assert ctx.has_verified_advisory is True
        assert ctx.has_tier3_signals is False

    def test_tier3_signals_true(self) -> None:
        """Constructing with has_tier3_signals=True works."""
        ctx = ThreatCooldownContext(has_tier3_signals=True)
        assert ctx.has_verified_advisory is False
        assert ctx.has_tier3_signals is True

    def test_both_true(self) -> None:
        """Constructing with both True works."""
        ctx = ThreatCooldownContext(has_verified_advisory=True, has_tier3_signals=True)
        assert ctx.has_verified_advisory is True
        assert ctx.has_tier3_signals is True


class TestGetCooldownWindow:
    """Tests for get_cooldown_window()."""

    def test_default_window(self) -> None:
        """Returns config.default_days when no per-ecosystem override exists."""

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        result = get_cooldown_window(config, "pypi")

        assert result == 5

    def test_per_ecosystem_window(self) -> None:
        """Returns per-ecosystem value when ecosystem has an override."""

        class MockConfig:
            default_days = 5
            per_ecosystem = {"npm": 7}
            enabled = True

        config = MockConfig()

        result = get_cooldown_window(config, "npm")

        assert result == 7

    def test_fallback_to_defaults(self) -> None:
        """Falls back to config.default_days for unknown ecosystems."""

        class MockConfig:
            default_days = 5
            per_ecosystem = None
            enabled = True

        config = MockConfig()

        result = get_cooldown_window(config, "unknown")

        assert result == 5


# =========================================================================
# Ported tests from core/cooldown (check_cooldown, find_safe_version,
# get_effective_cooldown)
# =========================================================================


from datetime import UTC, datetime, timedelta  # noqa: E402, F811

from pkg_defender.audit.cooldown import (  # noqa: E402, F811
    check_cooldown,
    find_safe_version,
    get_effective_cooldown,
)
from pkg_defender.config.settings import CooldownConfig  # noqa: E402
from pkg_defender.models import VersionInfo  # noqa: E402

# ---------------------------------------------------------------------------
# Fixed reference time for all tests
# ---------------------------------------------------------------------------

NOW = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)


def _make_version(
    package: str = "lodash",
    version: str = "4.17.21",
    days_ago: int = 0,
    *,
    ecosystem: str = "npm",
) -> VersionInfo:
    """Create a VersionInfo with a publish_time offset from NOW."""
    return VersionInfo(
        version=version,
        publish_time=NOW - timedelta(days=days_ago),
        ecosystem=ecosystem,
        package_name=package,
    )


def _make_config(
    *,
    default_days: int = 1,
    enabled: bool = True,
    overrides: dict[str, int] | None = None,
) -> CooldownConfig:
    """Create a CooldownConfig with sensible test defaults."""
    return CooldownConfig(
        default_days=default_days,
        enabled=enabled,
        overrides=overrides or {},
    )


# ===================================================================
# check_cooldown
# ===================================================================


class TestCheckCooldown:
    """Tests for check_cooldown()."""

    def test_version_passes_when_old_enough(self) -> None:
        """A version published 5 days ago passes the default 1-day cooldown."""
        vi = _make_version(days_ago=5)
        result = check_cooldown(vi, _make_config(), now=NOW)
        assert result.allowed is True
        assert result.reason == "ok"
        assert result.remaining is None
        assert result.age == timedelta(days=5)
        assert result.effective_cooldown_days == 1

    def test_version_blocked_when_too_new(self) -> None:
        """A version published 6 hours ago is blocked by the 1-day cooldown."""
        vi = _make_version(version="4.17.22", days_ago=0)
        # publish_time = NOW, so age = 0
        # Use a publish time 6 hours ago
        vi = VersionInfo(
            version="4.17.22",
            publish_time=NOW - timedelta(hours=6),
            ecosystem="npm",
            package_name="lodash",
        )
        result = check_cooldown(vi, _make_config(), now=NOW)
        assert result.allowed is False
        assert result.reason == "too_new"
        assert result.remaining is not None
        assert result.remaining == timedelta(hours=18)
        assert result.age == timedelta(hours=6)
        assert result.effective_cooldown_days == 1

    def test_package_specific_override_is_applied(self) -> None:
        """A package override (2 days) extends the cooldown window."""
        vi = _make_version(package="axios", version="1.7.0", days_ago=1)
        config = _make_config(default_days=1, overrides={"axios": 2})
        result = check_cooldown(vi, config, now=NOW)
        # age = 1 day, cooldown = 2 days → blocked
        assert result.allowed is False
        assert result.reason == "too_new"
        assert result.effective_cooldown_days == 2
        assert result.remaining == timedelta(days=1)

    def test_disabled_cooldown_allows_everything(self) -> None:
        """When enabled=False, even a brand-new version is allowed."""
        vi = _make_version(version="0.0.1", days_ago=0)
        config = _make_config(enabled=False)
        result = check_cooldown(vi, config, now=NOW)
        assert result.allowed is True
        assert result.reason == "ok"
        assert result.effective_cooldown_days == 0

    def test_safe_version_suggestion_is_returned(self) -> None:
        """When blocked, find_safe_version returns the best alternative."""
        versions = [
            _make_version(package="axios", version="1.7.0", days_ago=0),
            _make_version(package="axios", version="1.6.9", days_ago=3),
            _make_version(package="axios", version="1.6.8", days_ago=10),
        ]
        vi = versions[0]  # 0 days old → blocked
        config = _make_config(default_days=1)
        result = check_cooldown(vi, config, all_versions=versions, now=NOW)
        assert result.allowed is False
        assert result.safe_version == "1.6.9"  # newest version >= 1 day old

    def test_no_safe_version_when_all_too_new(self) -> None:
        """If every version is within cooldown, safe_version is None."""
        versions = [
            _make_version(version="3.0.0", days_ago=0),
            _make_version(version="3.0.0-beta", days_ago=0),
        ]
        vi = versions[0]
        result = check_cooldown(vi, _make_config(), all_versions=versions, now=NOW)
        assert result.allowed is False
        assert result.safe_version is None

    def test_exactly_at_cooldown_boundary_is_allowed(self) -> None:
        """A version published exactly 1 day ago is allowed (age >= cooldown)."""
        vi = _make_version(days_ago=1)
        result = check_cooldown(vi, _make_config(default_days=1), now=NOW)
        assert result.allowed is True
        assert result.reason == "ok"
        assert result.age == timedelta(days=1)

    def test_one_second_before_boundary_is_blocked(self) -> None:
        """A version published 1 day minus 1 second ago is blocked."""
        vi = VersionInfo(
            version="1.0.0",
            publish_time=NOW - timedelta(days=1, seconds=-1),
            ecosystem="npm",
            package_name="test-pkg",
        )
        result = check_cooldown(vi, _make_config(default_days=1), now=NOW)
        assert result.allowed is False
        assert result.reason == "too_new"

    def test_publish_time_is_preserved_in_result(self) -> None:
        """The result always carries the original publish_time."""
        vi = _make_version(days_ago=5)
        result = check_cooldown(vi, _make_config(), now=NOW)
        assert result.publish_time == vi.publish_time

    def test_default_now_is_utc(self) -> None:
        """When now=None, the engine uses UTC time (no tz-naive comparison)."""
        vi = _make_version(days_ago=10)
        result = check_cooldown(vi, _make_config())
        # Should not raise and should be allowed (10 days > 1 day)
        assert result.allowed is True

    def test_naive_publish_time_treated_as_utc(self) -> None:
        """Naive publish_time is normalized to UTC, not raising TypeError."""
        vi = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2026, 3, 1, 12, 0, 0),  # naive
            ecosystem="npm",
            package_name="test-pkg",
        )
        result = check_cooldown(vi, _make_config(), now=NOW)
        assert result.allowed is True  # naive date is old enough


class TestCheckCooldownTrustPenalty:
    """Tests for the +2 claimed-timestamp penalty in check_cooldown()."""

    def test_claimed_increases_effective_cooldown_days(self) -> None:
        """check_cooldown with claimed trust_level → effective_cooldown_days = base + 2."""
        vi = _make_version(days_ago=1)
        config = _make_config(default_days=1)
        result = check_cooldown(vi, config, trust_level="claimed", now=NOW)
        # age=1d, base window=1d, +2 claimed=3d → blocked, effective=3
        assert result.allowed is False
        assert result.effective_cooldown_days == 3
        assert result.remaining == timedelta(days=2)

    def test_claimed_blocks_older_version(self) -> None:
        """A version that would pass base window now blocked with +2."""
        vi = _make_version(days_ago=2)
        config = _make_config(default_days=2)
        # Without trust_level: 2d <= 2d → would pass
        result_base = check_cooldown(vi, config, now=NOW)
        assert result_base.allowed is True

        # With claimed: 2d base + 2d penalty = 4d → blocked
        result_penalty = check_cooldown(vi, config, trust_level="claimed", now=NOW)
        assert result_penalty.allowed is False
        assert result_penalty.effective_cooldown_days == 4


# ===================================================================
# find_safe_version
# ===================================================================


class TestFindSafeVersion:
    """Tests for find_safe_version()."""

    def test_returns_newest_passing_version(self) -> None:
        """Among versions 1, 3, 10 days old (cooldown=1), returns 1-day-old."""
        versions = [
            _make_version(version="2.0.0", days_ago=0),
            _make_version(version="1.2.0", days_ago=1),
            _make_version(version="1.1.0", days_ago=3),
            _make_version(version="1.0.0", days_ago=10),
        ]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result == "1.2.0"

    def test_empty_list_returns_none(self) -> None:
        """No versions → no safe version."""
        result = find_safe_version([], cooldown_days=1, now=NOW)
        assert result is None

    def test_all_within_cooldown_returns_none(self) -> None:
        """If every version is younger than cooldown, returns None."""
        versions = [
            _make_version(version="5.0.0", days_ago=0),
            _make_version(version="4.9.9", days_ago=0),
        ]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result is None

    def test_exact_boundary_is_safe(self) -> None:
        """A version published exactly at the cooldown boundary is safe."""
        versions = [
            _make_version(version="2.0.0", days_ago=0),
            _make_version(version="1.0.0", days_ago=3),  # exactly safe
        ]
        # Use 3-day cooldown so version at 3 days is exactly at boundary
        versions[1] = VersionInfo(
            version="1.0.0",
            publish_time=NOW - timedelta(days=3),
            ecosystem="npm",
            package_name="test",
        )
        result = find_safe_version(versions, cooldown_days=3, now=NOW)
        assert result == "1.0.0"

    def test_prefers_newest_among_passing_versions(self) -> None:
        """When multiple versions pass cooldown, returns the newest one."""
        versions = [
            _make_version(version="3.0.0", days_ago=0),  # too new
            _make_version(version="2.5.0", days_ago=2),  # passes
            _make_version(version="2.0.0", days_ago=5),  # passes
            _make_version(version="1.0.0", days_ago=30),  # passes
        ]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result == "2.5.0"

    def test_single_version_passes(self) -> None:
        """A single old enough version is returned."""
        versions = [_make_version(version="1.0.0", days_ago=100)]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result == "1.0.0"

    def test_single_version_too_new(self) -> None:
        """A single too-new version returns None."""
        versions = [_make_version(version="1.0.0", days_ago=0)]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result is None

    def test_naive_publish_time_treated_as_utc(self) -> None:
        """VersionInfo with naive publish_time does not crash find_safe_version."""
        vi = VersionInfo(
            version="1.0.0",
            publish_time=datetime(2026, 3, 1, 12, 0, 0),  # naive
            ecosystem="npm",
            package_name="test-pkg",
        )
        versions = [
            VersionInfo(version="2.0.0", publish_time=datetime.now(UTC), ecosystem="npm", package_name="test-pkg"),
            vi,
        ]
        result = find_safe_version(versions, cooldown_days=1, now=NOW)
        assert result is not None


# ===================================================================
# Regression tests for P0.1: datetime.min sort-key was timezone-naive
# ===================================================================


class TestSortKeyTimezone:
    """Regression: P0.1 — datetime.min sort-key was timezone-naive."""

    async def test_sort_key_none_publish_time(self) -> None:
        """_sort_key returns timezone-aware datetime for None publish_time."""
        from pkg_defender.audit.cooldown import _sort_key
        from pkg_defender.models.models import VersionInfo

        v = VersionInfo(ecosystem="test", package_name="pkg", version="1.0.0", publish_time=None)
        key = _sort_key(v)
        assert key.tzinfo is not None, f"Expected timezone-aware datetime, got naive: {key}"

    async def test_sort_key_sorting_with_none(self) -> None:
        """Sorting mixed None/aware publish_times doesn't TypeError."""
        from pkg_defender.audit.cooldown import _sort_key
        from pkg_defender.models.models import VersionInfo

        versions = [
            VersionInfo(ecosystem="npm", package_name="test", version="3.0.0", publish_time=None),
            VersionInfo(ecosystem="npm", package_name="test", version="2.0.0", publish_time=None),
            VersionInfo(
                ecosystem="npm",
                package_name="test",
                version="1.0.0",
                publish_time=datetime.now(UTC),
            ),
        ]
        # This would TypeError before the fix.
        sorted(versions, key=_sort_key)


# ===================================================================
# get_effective_cooldown
# ===================================================================


class TestGetEffectiveCooldown:
    """Tests for get_effective_cooldown()."""

    def test_returns_default_without_override(self) -> None:
        """Package not in overrides → returns default_days."""
        config = _make_config(default_days=1, overrides={"axios": 3})
        result = get_effective_cooldown("lodash", config)
        assert result == 1

    def test_returns_override_when_set(self) -> None:
        """Package in overrides → returns override value."""
        config = _make_config(default_days=1, overrides={"axios": 3})
        result = get_effective_cooldown("axios", config)
        assert result == 3

    def test_override_zero_is_valid(self) -> None:
        """Override of 0 means no cooldown for that package."""
        config = _make_config(default_days=5, overrides={"internal-pkg": 0})
        result = get_effective_cooldown("internal-pkg", config)
        assert result == 0

    def test_empty_overrides_dict(self) -> None:
        """Empty overrides dict → always returns default."""
        config = _make_config(default_days=2)
        result = get_effective_cooldown("anything", config)
        assert result == 2

    def test_multiple_overrides_independent(self) -> None:
        """Multiple overrides don't interfere with each other."""
        config = _make_config(
            default_days=1,
            overrides={"axios": 3, "react": 5},
        )
        assert get_effective_cooldown("axios", config) == 3
        assert get_effective_cooldown("react", config) == 5
        assert get_effective_cooldown("vue", config) == 1


# ===================================================================
# Integration-style tests combining all functions
# ===================================================================


class TestCooldownIntegration:
    """End-to-end scenarios combining check, find, and effective cooldown."""

    def test_override_zero_allows_immediately(self) -> None:
        """A package with override=0 is always allowed, even if just published."""
        vi = _make_version(package="internal-tools", version="1.0.0", days_ago=0)
        config = _make_config(default_days=3, overrides={"internal-tools": 0})
        result = check_cooldown(vi, config, now=NOW)
        assert result.allowed is True
        assert result.reason == "ok"

    def test_blocked_install_suggests_older_safe_version(self) -> None:
        """Full flow: blocked version + available versions → safe suggestion."""
        versions = [
            _make_version(package="express", version="5.0.0", days_ago=0),
            _make_version(package="express", version="4.19.0", days_ago=2),
            _make_version(package="express", version="4.18.2", days_ago=90),
        ]
        config = _make_config(default_days=3)
        result = check_cooldown(versions[0], config, all_versions=versions, now=NOW)
        assert result.allowed is False
        assert result.safe_version == "4.18.2"  # only 90-day-old version passes 3-day cooldown

    def test_returns_blocked_when_override_cooldown_exceeds_version_age(self) -> None:
        """Package with 7-day override: version 5 days old is blocked."""
        vi = _make_version(package="critical-lib", version="2.0.0", days_ago=5)
        config = _make_config(default_days=1, overrides={"critical-lib": 7})
        result = check_cooldown(vi, config, now=NOW)
        assert result.allowed is False
        assert result.effective_cooldown_days == 7
        assert result.remaining == timedelta(days=2)
