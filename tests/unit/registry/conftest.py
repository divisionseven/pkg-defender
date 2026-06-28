"""Registry test configuration — resets module-level state between tests.

The buildtime validator and timestamp resolver maintain module-level mutable
state (buckets, caches) that persists across tests in the same process.
Without isolation at the conftest level, test ordering matters and state
from one test leaks into another.

This follows the same pattern as tests/conftest.py (``_reset_quiet_mode``,
``_cleanup_logging_handlers``).
"""

from collections.abc import Generator

import pytest

from pkg_defender.registry._buildtime_validator import _reset_state_for_tests
from pkg_defender.registry._timestamp import _reset_timestamp_caches


@pytest.fixture(autouse=True)
def _reset_buildtime_validator() -> Generator[None, None, None]:
    """Clear the buildtime validator's module-level bucket state between tests.

    The validator accumulates BUILDTIME counts in ``_buckets`` across calls.
    Without reset, tests that check exact threshold counts (N=5 boundary, N=6
    detection) would be contaminated by earlier tests' state.
    """
    _reset_state_for_tests()
    yield
    _reset_state_for_tests()


@pytest.fixture(autouse=True)
def _reset_timestamp_caches_fixture() -> Generator[None, None, None]:
    """Clear timestamp resolver TTL and rate-limit caches between tests.

    The resolver caches ``(package, version) -> ResolutionResult`` and
    ``domain -> expiry`` entries. Without reset, tests that mock API calls
    may get stale cached results from earlier tests.
    """
    _reset_timestamp_caches()
    yield
    _reset_timestamp_caches()
