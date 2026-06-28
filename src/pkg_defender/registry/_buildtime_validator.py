"""BUILDTIME clamping validator for Fedora 43+ reproducible-builds detection.

This module detects when a package's BUILDTIME (or any source's publish-time
proxy) is clamped to a single second across many packages in the same build
window. This is a known artifact of Fedora's ``SOURCE_DATE_EPOCH`` reproducible
builds policy: the build system pins a single timestamp to the entire build
batch so that the resulting RPMs are byte-identical regardless of when they
were actually built.

When this artifact is detected, downstream code should demote the source from
``proxied`` to ``none`` in the public ``date_source`` field — a clamped
BUILDTIME is not a meaningful "publish time" for cooldown checks.

Algorithm (per Constraint C2, plan §Phase 0):
    Strict greater-than threshold: a single BUILDTIME value appearing
    **more than 5 times** (i.e. 6+) in the same build window from the same
    source is flagged as clamped. N=5 is the boundary and is **not** flagged.
    Buckets are time-bounded (TTL=2h) and per-source — a single frozen
    snapshot repo (e.g. openEuler 22.03 LTS) legitimately shows the same
    BUILDTIME for many packages, but each source is evaluated independently.

Module-level state is intentional. The validator is a heuristic that needs
to accumulate counts across calls within a process — class-based state would
require wiring a singleton instance through the cascade, which is harder to
test and easier to break. The state is guarded by a ``threading.Lock`` and
exposed via :func:`_reset_state_for_tests` for test isolation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime
from threading import Lock

logger = logging.getLogger(__name__)

# Source string used by the cascade when no upstream source produced a
# timestamp. Public value — keep in sync with the cascade's "no source" code.
SOURCE_USER_MANUAL: str = "unresolved"

# Strict greater-than threshold: N>5 means N=6+ triggers clamping detection.
# N=5 is the boundary and is intentionally NOT flagged (see plan §Phase 0
# test contract: "boundary (exactly N=5 — NOT flagged)").
_CLAMPING_THRESHOLD: int = 5

# How long to keep a bucket (in hours). Buckets older than this are dropped
# to bound memory and prevent stale counts from affecting current decisions.
_BUCKET_TTL_HOURS: int = 2

# --- Module-level state (intentional, see module docstring) -------------
#
# ``_buckets`` maps ``(source, hour_bucket)`` to a counter of BUILDTIME
# epochs. ``hour_bucket`` is ``now_epoch // 3600`` (the current wall-clock
# hour, in epoch-seconds). A second-level inner dict keys by BUILDTIME epoch
# (seconds) and counts occurrences.
_buckets: dict[tuple[str, int], dict[int, int]] = defaultdict(lambda: defaultdict(int))

# Tracks the last hour in which cleanup was performed. Cleanup runs at most
# once per hour to avoid scanning the full bucket dict on every call.
_last_cleanup_hour: int = 0

# Guards concurrent mutation of ``_buckets`` and ``_last_cleanup_hour``. The
# lock is module-level (not per-bucket) because the bucket dict is small
# (max ~a few hundred entries over a 2-hour window).
_state_lock = Lock()


def _maybe_cleanup(now_epoch: int) -> None:
    """Drop buckets older than :data:`_BUCKET_TTL_HOURS`.

    Runs at most once per hour (``_last_cleanup_hour`` gates re-execution).
    Buckets are keyed by ``(source, hour_bucket)``; buckets whose hour is
    older than ``current_hour - _BUCKET_TTL_HOURS`` are dropped.

    Args:
        now_epoch: Current wall-clock time as epoch seconds (UTC).
    """
    global _last_cleanup_hour

    current_hour = now_epoch // 3600
    if _last_cleanup_hour == current_hour:
        return

    cutoff_hour = current_hour - _BUCKET_TTL_HOURS
    with _state_lock:
        # Drop stale buckets. ``list()`` snapshot prevents dict-mutation
        # during iteration.
        stale_keys = [key for key, _ in _buckets.items() if key[1] < cutoff_hour]
        for key in stale_keys:
            del _buckets[key]
        _last_cleanup_hour = current_hour


def detect_clamping(
    *,
    buildtime: datetime,
    source: str,
    package: str,
    version: str,
) -> bool:
    """Return ``True`` if ``(source, buildtime)`` appears clamped.

    A BUILDTIME is considered "clamped" (a reproducible-builds artifact)
    when the same epoch-second value appears **more than**
    :data:`_CLAMPING_THRESHOLD` times from the same ``source`` within the
    current build window. See module docstring for the full rationale.

    Args:
        buildtime: The candidate BUILDTIME / publish-time proxy. Must be
            timezone-aware (UTC) — naive datetimes raise ``TypeError`` from
            ``datetime.now(UTC) - buildtime`` arithmetic in callers.
        source: The source identifier (e.g. ``"bodhi"``, ``"koji"``,
            ``"repodata"``, a repodata URL, or :data:`SOURCE_USER_MANUAL`).
        package: Package name — included in the debug log for triage.
        version: Package version string — included in the debug log for
            triage.

    Returns:
        ``True`` if this call crosses the clamping threshold (i.e. the
        same BUILDTIME has now been seen >5 times from this source in the
        current hour). ``False`` otherwise.

    Raises:
        TypeError: If ``buildtime`` is naive (no ``tzinfo``). The validator
            refuses to record a naive timestamp because it would corrupt
            downstream arithmetic in the cascade.
    """
    if buildtime.tzinfo is None:
        raise TypeError(
            "detect_clamping requires a timezone-aware buildtime "
            "(got naive datetime; use datetime.now(UTC) or .replace(tzinfo=UTC))"
        )

    now_epoch = int(datetime.now(UTC).timestamp())
    _maybe_cleanup(now_epoch)

    hour_bucket = now_epoch // 3600
    bt_epoch = int(buildtime.timestamp())

    with _state_lock:
        bucket = _buckets[(source, hour_bucket)]
        bucket[bt_epoch] += 1
        count = bucket[bt_epoch]

    if count > _CLAMPING_THRESHOLD:
        logger.debug(
            "BUILDTIME clamping detected: source=%s package=%s version=%s "
            "buildtime=%s count=%d threshold=%d (strict >)",
            source,
            package,
            version,
            buildtime.isoformat(),
            count,
            _CLAMPING_THRESHOLD,
        )
        return True

    return False


def _reset_state_for_tests() -> None:
    """Clear all module-level bucket state. **Test-only API.**

    Production code MUST NOT call this. Tests should call it in a fixture
    to ensure no state leaks between test cases. Clears ``_buckets`` and
    resets ``_last_cleanup_hour`` so the next call re-runs cleanup (which
    is a no-op on an empty dict).
    """
    global _last_cleanup_hour
    with _state_lock:
        _buckets.clear()
        _last_cleanup_hour = 0
