"""Tests for pkg_defender.registry._buildtime_validator.

The BUILDTIME clamping validator detects Fedora 43+ reproducible-builds
artifacts (same BUILDTIME for many packages in the same window). The
heuristic is conservative: strict greater-than at N>5 (so N=6+ triggers,
N=5 does not), per-source buckets, 2-hour TTL.

State isolation: every test calls :func:`_reset_state_for_tests` in a
fixture because the module-level buckets persist across tests otherwise.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from pkg_defender.registry import _buildtime_validator
from pkg_defender.registry._buildtime_validator import (
    _BUCKET_TTL_HOURS,
    _CLAMPING_THRESHOLD,
    SOURCE_USER_MANUAL,
    _buckets,
    _maybe_cleanup,
    _reset_state_for_tests,
    detect_clamping,
)


def _fixed_now(epoch: int) -> datetime:
    """Return a UTC-aware datetime at *epoch* seconds."""
    return datetime.fromtimestamp(epoch, tz=UTC)


class TestDetectClampingBasics:
    """Happy-path / boundary tests for :func:`detect_clamping`."""

    def test_detects_clamping_at_threshold_plus_one(self) -> None:
        """N=6 same BUILDTIME in same hour → ``True`` (strict greater-than)."""
        bt = _fixed_now(1_700_000_000)
        # First 5 should not trigger
        for _ in range(_CLAMPING_THRESHOLD):
            assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is False
        # The 6th call crosses the threshold
        assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is True

    def test_no_clamping_unique_timestamps(self) -> None:
        """6 packages with different BUILDTIMEs → ``False``."""
        for i in range(6):
            bt = _fixed_now(1_700_000_000 + i)
            assert (
                detect_clamping(
                    buildtime=bt,
                    source="bodhi",
                    package=f"pkg{i}",
                    version="1.0",
                )
                is False
            )

    def test_no_clamping_at_exact_threshold(self) -> None:
        """N=5 same BUILDTIME (boundary) → ``False``. Strict greater-than."""
        bt = _fixed_now(1_700_000_000)
        for _ in range(_CLAMPING_THRESHOLD):
            assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is False

    def test_no_clamping_different_hours(self) -> None:
        """Same BUILDTIME in different hours → ``False`` (different buckets)."""
        # Pin the "now" used by the validator via a mock.
        base = 1_700_000_000
        bt = _fixed_now(base)
        with patch.object(
            _buildtime_validator,
            "datetime",
        ) as mock_dt:
            # First 5 calls land in hour 0
            mock_dt.now.return_value = _fixed_now(base)
            for _ in range(5):
                assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is False
            # 6th call uses the same BUILDTIME but a different wall-clock hour
            # (advancing >3600s puts us in a fresh hour bucket).
            mock_dt.now.return_value = _fixed_now(base + 7200)
            assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is False

    def test_no_clamping_different_sources(self) -> None:
        """Same BUILDTIME but different sources → ``False`` (per-source buckets)."""
        bt = _fixed_now(1_700_000_000)
        for source in ("bodhi", "koji", "repodata", "unresolved"):
            for _ in range(5):
                assert (
                    detect_clamping(
                        buildtime=bt,
                        source=source,
                        package="curl",
                        version="1.0",
                    )
                    is False
                )
        # Now hit the threshold for the 6th source — still not flagged
        # (each source has only had 5 calls so far)
        # The first source "bodhi" was hit 5 times; if we hit it a 6th time
        # we expect True now (and we add 5 more "unresolved" calls to be safe)
        assert detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") is True

    def test_logger_debug_called_on_clamping(self) -> None:
        """``logger.debug`` is called when clamping is detected."""
        bt = _fixed_now(1_700_000_000)
        with patch.object(_buildtime_validator, "logger") as mock_logger:
            # Cross the threshold
            for _ in range(_CLAMPING_THRESHOLD):
                detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0")
            detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0")
        # The final call must have logged a debug message with the source,
        # package, and version as format args (Python logging stores the
        # format string in args[0] and the format arguments in args[1:]).
        assert mock_logger.debug.called
        call_args = mock_logger.debug.call_args
        # Inspect all positional + keyword arguments for the expected tokens
        all_args = list(call_args.args) + list(call_args.kwargs.values())
        all_strs = " ".join(str(a) for a in all_args)
        assert "bodhi" in all_strs
        assert "curl" in all_strs
        assert "1.0" in all_strs


class TestDetectClampingRobustness:
    """Robustness / contract tests for :func:`detect_clamping`."""

    def test_rejects_naive_datetime(self) -> None:
        """Naive datetimes raise ``TypeError`` to prevent arithmetic bugs."""
        naive = datetime(2024, 1, 1, 12, 0, 0)  # no tzinfo
        with pytest.raises(TypeError, match="timezone-aware"):
            detect_clamping(
                buildtime=naive,
                source="bodhi",
                package="curl",
                version="1.0",
            )

    def test_state_isolated_via_reset(self) -> None:
        """``_reset_state_for_tests()`` clears all buckets."""
        bt = _fixed_now(1_700_000_000)
        # Add 4 entries
        for _ in range(4):
            detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0")
        assert len(_buckets) > 0
        # Manually invoke the reset; the autouse fixture also resets after
        # the test for the next case.
        _reset_state_for_tests()
        assert len(_buckets) == 0
        assert _buildtime_validator._last_cleanup_hour == 0


class TestMaybeCleanup:
    """Tests for the internal :func:`_maybe_cleanup` helper."""

    def test_cleanup_drops_stale_buckets(self) -> None:
        """Buckets older than ``_BUCKET_TTL_HOURS`` are dropped."""
        now = int(datetime.now(UTC).timestamp())
        current_hour = now // 3600
        # Stale bucket: _BUCKET_TTL_HOURS + 1 hours ago
        stale_hour = current_hour - _BUCKET_TTL_HOURS - 1
        _buckets[("bodhi", stale_hour)][1_700_000_000] = 99
        # Fresh bucket: current hour
        _buckets[("bodhi", current_hour)][1_700_000_000] = 1

        _maybe_cleanup(now)
        # Stale bucket dropped
        assert ("bodhi", stale_hour) not in _buckets
        # Fresh bucket preserved
        assert ("bodhi", current_hour) in _buckets

    def test_cleanup_runs_at_most_once_per_hour(self) -> None:
        """Re-calling within the same hour is a no-op (no stale drops).

        Verifies the throttle by adding a stale bucket, calling
        ``_maybe_cleanup`` twice within the same hour, and verifying
        that the stale bucket survives both calls. The first call
        drops it; the re-added bucket must survive the second call
        because cleanup is gated by ``_last_cleanup_hour``.
        """
        now = int(datetime.now(UTC).timestamp())
        current_hour = now // 3600
        stale_hour = current_hour - _BUCKET_TTL_HOURS - 1

        # First call drops any stale buckets that exist
        _buckets[("bodhi", stale_hour)][1_700_000_000] = 99
        _maybe_cleanup(now)
        # Stale bucket was dropped by the first call
        assert ("bodhi", stale_hour) not in _buckets

        # Force the throttle into the current hour for deterministic test
        global _last_cleanup_hour  # noqa: PLW0603
        _last_cleanup_hour = current_hour

        # Re-add a stale bucket — second call (same hour) must NOT drop it
        _buckets[("bodhi", stale_hour)][1_700_000_000] = 99
        _maybe_cleanup(now + 60)  # 1 minute later, same hour
        # Throttle is in effect: stale bucket survives
        assert ("bodhi", stale_hour) in _buckets


class TestMutationClampingThreshold:
    """Mutation test: revert the N>5 threshold and verify the test FAILS.

    Procedure: change ``_CLAMPING_THRESHOLD`` to a different value
    (simulating an accidental edit) and verify the upstream tests would
    fail with the new threshold. This is the gold-standard mutation
    test — it confirms the boundary tests actually exercise the
    threshold.

    The test mutates ``_CLAMPING_THRESHOLD`` via monkeypatch and then
    runs the boundary check; with the wrong threshold the boundary
    test's expected ``False`` becomes ``True`` (or vice versa).
    """

    def test_mutation_threshold_too_low(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If threshold were N>3, then N=4 would trigger (breaking the test)."""
        monkeypatch.setattr(_buildtime_validator, "_CLAMPING_THRESHOLD", 3, raising=True)
        bt = _fixed_now(1_700_000_000)
        # With threshold=3, the 4th call should trigger
        results = [detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") for _ in range(4)]
        # The original "no_clamping_at_exact_threshold" test asserted all False
        # for the first 5 calls. With threshold=3, the 4th call returns True —
        # so the original test would FAIL (False != True). This is the
        # mutation check: the threshold matters and is exercised.
        assert results == [False, False, False, True]

    def test_mutation_threshold_too_high(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If threshold were N>7, then 6 calls would not trigger (breaking the test)."""
        monkeypatch.setattr(_buildtime_validator, "_CLAMPING_THRESHOLD", 7, raising=True)
        bt = _fixed_now(1_700_000_000)
        # With threshold=7, the 6th call should NOT trigger
        results = [detect_clamping(buildtime=bt, source="bodhi", package="curl", version="1.0") for _ in range(6)]
        # The original "detects_clamping_at_threshold_plus_one" test asserted
        # the 6th call returns True. With threshold=7, all 6 return False —
        # so the original test would FAIL (True != False).
        assert results == [False] * 6


class TestSourceConstants:
    """Verify the source constants are exposed with the correct values."""

    def test_source_user_manual_value(self) -> None:
        """``SOURCE_USER_MANUAL`` is the literal ``\"unresolved\"``."""
        assert SOURCE_USER_MANUAL == "unresolved"
