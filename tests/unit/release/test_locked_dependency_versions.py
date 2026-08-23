"""Regression guards: locked dependency versions must meet vulnerability-fix floors.

Each floor corresponds to a published advisory fix. A downgrade below a floor
re-introduces a known vulnerability and must fail CI.

Coverage:
    1. uv.lock: aiohttp >= 3.14.3  (CVE-2026-69244, CVE-2026-69243, CVE-2026-59881)
    2. package-lock.json: undici >= 6.28.0  (CVE-2026-16728, CVE-2026-15157, CVE-2026-16729)
       + package.json overrides.undici must not fall below 6.28.0
    3. package-lock.json root brace-expansion >= 2.1.4  (GHSA-rgw5-rvv9-x895 / CVE-2026-69152)
    4. package-lock.json test-exclude-nested brace-expansion >= 1.1.18
       (GHSA-rgw5-rvv9-x895 / CVE-2026-69152)
    5. package-lock.json js-yaml >= 3.15.1  (GHSA-5p4m-2wfm-xmqj)

Floors are compared with ``>=`` semantics so future upgrades keep passing;
only a *downgrade* below a known-vulnerable threshold fails.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest
from packaging.version import Version

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
UV_LOCK_PATH = REPO_ROOT / "uv.lock"
ACTION_PACKAGE_JSON_PATH = REPO_ROOT / "github-action" / "package.json"
ACTION_PACKAGE_LOCK_PATH = REPO_ROOT / "github-action" / "package-lock.json"

assert UV_LOCK_PATH.is_file(), f"uv.lock not found at {UV_LOCK_PATH}"
assert ACTION_PACKAGE_JSON_PATH.is_file(), f"github-action/package.json not found at {ACTION_PACKAGE_JSON_PATH}"
assert ACTION_PACKAGE_LOCK_PATH.is_file(), f"github-action/package-lock.json not found at {ACTION_PACKAGE_LOCK_PATH}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uv_lock_package_version(name: str) -> Version:
    """Return the locked version of ``name`` parsed from ``uv.lock``."""
    with UV_LOCK_PATH.open("rb") as f:
        data: dict[str, Any] = tomllib.load(f)

    packages = data.get("package")
    assert isinstance(packages, list), "uv.lock is missing the [[package]] array"

    for entry in packages:
        if isinstance(entry, dict) and entry.get("name") == name:
            version = entry.get("version")
            assert isinstance(version, str), f"{name!r} entry in uv.lock has a missing/non-string version"
            return Version(version)

    pytest.fail(f"Package {name!r} not found in {UV_LOCK_PATH}")


def _action_lock_version(package_key: str) -> Version:
    """Return the locked version for a ``packages`` key in the npm lock file."""
    with ACTION_PACKAGE_LOCK_PATH.open(encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    packages = data.get("packages")
    assert isinstance(packages, dict), "package-lock.json is missing the 'packages' map"

    entry = packages.get(package_key)
    assert isinstance(entry, dict), (
        f"Key {package_key!r} not found in package-lock.json 'packages' — the "
        "dependency tree was reshaped. Update this guard's keys to match."
    )
    version = entry.get("version")
    assert isinstance(version, str), f"{package_key!r} has a missing/non-string version"
    return Version(version)


def _action_override_version(name: str) -> Version:
    """Return the npm ``overrides`` value for ``name`` from package.json."""
    with ACTION_PACKAGE_JSON_PATH.open(encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    overrides = data.get("overrides")
    assert isinstance(overrides, dict), "package.json is missing the 'overrides' map"
    value = overrides.get(name)
    assert isinstance(value, str), f"overrides.{name} is missing or not a string"
    return Version(value)


# ===================================================================
# Test 1: uv.lock floors (Python ecosystem)
# ===================================================================


class TestUvLockFloors:
    """``uv.lock`` must pin runtime dependencies at or above fix floors."""

    @pytest.mark.parametrize(
        ("package_name", "floor", "advisories"),
        [
            pytest.param(
                "aiohttp",
                "3.14.3",
                "CVE-2026-69244, CVE-2026-69243, CVE-2026-59881",
                id="aiohttp",
            ),
        ],
    )
    def test_locked_version_meets_floor(self, package_name: str, floor: str, advisories: str) -> None:
        """The locked version must be >= the advisory fix floor."""
        locked = _uv_lock_package_version(package_name)
        floor_version = Version(floor)
        assert locked >= floor_version, (
            f"uv.lock pins {package_name} {locked}, below the vulnerability-fix "
            f"floor {floor}. Known affected advisories: {advisories}. Re-run "
            f"'uv lock --upgrade-package {package_name}' and commit the relock."
        )


# ===================================================================
# Test 2: package-lock.json floors (npm ecosystem)
# ===================================================================


class TestActionLockFloors:
    """``github-action/package-lock.json`` must pin packages at or above fix floors."""

    @pytest.mark.parametrize(
        ("package_key", "floor", "advisories"),
        [
            pytest.param(
                "node_modules/undici",
                "6.28.0",
                "CVE-2026-16728, CVE-2026-15157, CVE-2026-16729",
                id="undici",
            ),
            pytest.param(
                "node_modules/brace-expansion",
                "2.1.4",
                "GHSA-rgw5-rvv9-x895 / CVE-2026-69152",
                id="brace-expansion-root",
            ),
            pytest.param(
                "node_modules/test-exclude/node_modules/brace-expansion",
                "1.1.18",
                "GHSA-rgw5-rvv9-x895 / CVE-2026-69152",
                id="brace-expansion-nested",
            ),
            pytest.param(
                "node_modules/js-yaml",
                "3.15.1",
                "GHSA-5p4m-2wfm-xmqj",
                id="js-yaml",
            ),
        ],
    )
    def test_locked_version_meets_floor(self, package_key: str, floor: str, advisories: str) -> None:
        """The locked version must be >= the advisory fix floor."""
        locked = _action_lock_version(package_key)
        floor_version = Version(floor)
        assert locked >= floor_version, (
            f"package-lock.json pins {package_key} {locked}, below the "
            f"vulnerability-fix floor {floor}. Known affected advisories: "
            f"{advisories}. Refresh the lock with npm inside github-action/."
        )


# ===================================================================
# Test 3: undici override must not fall below the fix floor
# ===================================================================


class TestUndiciOverrideFloor:
    """The npm override for undici must not name a sub-floor version.

    Root cause lesson: an override naming a vulnerable exact version silently
    re-pins that version during any ``npm install``, defeating lock-file
    hygiene. The override must move in lockstep with the floor.
    """

    def test_override_not_below_fix_floor(self) -> None:
        """overrides.undici must be >= the advisory fix floor."""
        pinned = _action_override_version("undici")
        floor_version = Version("6.28.0")
        assert pinned >= floor_version, (
            f"github-action/package.json overrides.undici pins {pinned}, below "
            f"the vulnerability-fix floor {floor_version} "
            "(CVE-2026-16728, CVE-2026-15157, CVE-2026-16729). Bump the override "
            "value in lockstep with the dependency."
        )
