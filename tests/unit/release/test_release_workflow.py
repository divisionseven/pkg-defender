"""Regression tests for release pipeline fixes.

These tests validate the structural and logical correctness of the CI/CD
workflow files and build configuration — they do NOT run the actual release
pipeline. They are fast unit-level assertions that catch regressions in the
workflow definitions.

Coverage:
    1. release.yml is valid YAML with the expected job structure
    2. Binary build job uses ``uv run pyinstaller`` (not ``uv tool run``)
    3. PyPI publish job uses ``uv publish dist/*`` (not twine)
    4. pyproject.toml declares pyinstaller in the dev dependency group
    5. uv.lock is consistent with pyproject.toml (via ``uv lock --check``)
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
RELEASE_YML = WORKFLOW_DIR / "release.yml"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"

assert RELEASE_YML.is_file(), f"release.yml not found at {RELEASE_YML}"
assert PYPROJECT_TOML.is_file(), f"pyproject.toml not found at {PYPROJECT_TOML}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_release_yaml() -> dict[str, Any]:
    """Parse and return release.yml as a Python dict.

    Note: PyYAML interprets the bare ``on:`` key as the boolean ``True``
    (a known YAML 1.1 quirk).  Use ``_get_on_key()`` to retrieve the triggers.
    """
    with open(RELEASE_YML) as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return data


def _get_on_key(data: dict[str, Any]) -> dict[str, Any] | None:
    """Return the triggers dict (the YAML ``on:`` block).

    PyYAML parses ``on:`` as the boolean ``True`` rather than the string
    ``"on"`` because ``on``/``off`` are boolean literals in YAML 1.1.
    GitHub Actions' parser handles this correctly, but PyYAML does not.
    """
    triggers = data.get("on")
    if isinstance(triggers, dict):
        return triggers
    triggers = data.get(True)  # type: ignore[call-overload]
    if isinstance(triggers, dict):
        return triggers
    return None


def get_job_steps(job_name: str) -> list[dict[str, Any]]:
    """Return the steps list for a named job in release.yml."""
    data = load_release_yaml()
    job = data.get("jobs", {}).get(job_name)
    if job is None:
        pytest.fail(f"Job {job_name!r} not found in release.yml")
    steps = job.get("steps")
    if not isinstance(steps, list):
        pytest.fail(f"Job {job_name!r} has no 'steps' key")
    return steps


# ===================================================================
# Test 1: release.yml is valid YAML with expected structure
# ===================================================================


class TestReleaseYamlValidity:
    """release.yml must be valid YAML with the correct top-level keys and job
    dependency graph.  This catches syntax errors and structural regressions."""

    def test_parses_as_valid_yaml(self) -> None:
        """Smoke test: the YAML file loads without error."""
        data = load_release_yaml()
        assert isinstance(data, dict)

    def test_top_level_keys(self) -> None:
        """Must have name, on, permissions, concurrency, env, jobs.

        Note: PyYAML stores the ``on:`` key as boolean ``True`` due to a
        YAML 1.1 quirk.  We check via ``_get_on_key()``.
        """
        data = load_release_yaml()
        assert "name" in data, "Missing top-level key: name"
        assert _get_on_key(data) is not None, "Missing 'on:' trigger key (stored as True by PyYAML)"
        assert "permissions" in data, "Missing top-level key: permissions"
        assert "concurrency" in data, "Missing top-level key: concurrency"
        assert "env" in data, "Missing top-level key: env"
        assert "jobs" in data, "Missing top-level key: jobs"

    def test_trigger_is_tag_push(self) -> None:
        """Must trigger on push of version tags only."""
        data = load_release_yaml()
        triggers = _get_on_key(data)
        assert triggers is not None, "Missing 'on:' triggers block"
        push = triggers.get("push")
        assert push is not None, "Missing 'on.push' trigger"
        tags = push.get("tags")
        assert tags is not None, "Missing 'on.push.tags'"

        patterns = [t for t in tags if isinstance(t, str)]
        stable_patterns = [p for p in patterns if "v[0-9]" in p]
        assert len(stable_patterns) >= 1, "Expected stable tag pattern like 'v[0-9]+.[0-9]+.[0-9]+'"

    def test_required_jobs_present(self) -> None:
        """All 9 pipeline jobs must be defined."""
        data = load_release_yaml()
        jobs = data.get("jobs", {})
        expected_jobs = [
            "validate",
            "ci",
            "build",
            "provenance",
            "build-docker",
            "build-binaries",
            "github-release",
            "publish",
            "update-homebrew-tap",
        ]
        for name in expected_jobs:
            assert name in jobs, f"Missing job: {name!r}"

    def test_concurrency_cancel_in_progress_is_false(self) -> None:
        """Never cancel a release in progress."""
        data = load_release_yaml()
        concurrency = data.get("concurrency", {})
        assert concurrency.get("cancel-in-progress") is False, "cancel-in-progress must be false for releases"


# ===================================================================
# Test 2: Binary build uses ``uv run pyinstaller`` (not uv tool run)
# ===================================================================


class TestBinaryBuildCommand:
    """Regression test for the binary build fix.

    Root cause: release.yml:339 (before fix)
    ``uv tool run pyinstaller`` runs in an isolated tool environment that
    cannot see project dependencies (click, etc.).  The resulting binary
    crashes with ``ModuleNotFoundError: No module named 'click'``.

    Fix: changed ``uv tool run pyinstaller`` → ``uv run pyinstaller`` so
    that PyInstaller runs inside the project venv where all dependencies
    are available.
    """

    def test_uv_run_pyinstaller_present(self) -> None:
        """The binary build step must use ``uv run pyinstaller`` (project venv)."""
        steps = get_job_steps("build-binaries")
        run_commands = [s["run"] for s in steps if "run" in s]

        matches = [c for c in run_commands if "uv run pyinstaller" in c]
        assert len(matches) >= 1, (
            f"Expected a step with 'uv run pyinstaller' in build-binaries job. Run commands found: {run_commands}"
        )

    def test_no_uv_tool_run_pyinstaller(self) -> None:
        """Must NOT use ``uv tool run pyinstaller`` (isolated tool env)."""
        steps = get_job_steps("build-binaries")
        run_commands = [s["run"] for s in steps if "run" in s]

        forbidden = [c for c in run_commands if "uv tool run pyinstaller" in c]
        assert len(forbidden) == 0, (
            "Found forbidden 'uv tool run pyinstaller' in build-binaries job. "
            "This runs PyInstaller in an isolated tool env that can't see "
            "project dependencies. Use 'uv run pyinstaller' instead. "
            f"Offending commands: {forbidden}"
        )

    def test_no_uv_tool_install_pyinstaller(self) -> None:
        """Must NOT have a separate ``uv tool install pyinstaller`` step."""
        steps = get_job_steps("build-binaries")
        run_commands = [s["run"] for s in steps if "run" in s]

        forbidden = [c for c in run_commands if "uv tool install" in c and "pyinstaller" in c]
        assert len(forbidden) == 0, (
            "Found 'uv tool install pyinstaller' in build-binaries job — "
            "this is no longer needed since PyInstaller is a project dev "
            "dependency installed via 'uv sync'. "
            f"Offending commands: {forbidden}"
        )

    def test_uv_sync_present_after_fix(self) -> None:
        """The build-binaries job must still run ``uv sync`` (install deps)."""
        steps = get_job_steps("build-binaries")
        run_commands = [s["run"] for s in steps if "run" in s]

        matches = [c for c in run_commands if "uv sync" in c]
        assert len(matches) >= 1, (
            "Expected a step with 'uv sync' in build-binaries job. "
            "Project dependencies must be installed before building. "
            f"Run commands found: {run_commands}"
        )


# ===================================================================
# Test 3: PyPI publish uses ``uv publish dist/*`` (not twine)
# ===================================================================


class TestPublishCommand:
    """Regression test for the PyPI publish fix.

    Root cause: release.yml:528 (before fix)
    The publish job had no ``astral-sh/setup-uv`` step, so ``uv tool install twine``
    failed with ``uv: command not found``.  Additionally, the old pattern used
    ``gh-action-pypi-publish`` with ``twine check`` which required both Python and
    twine.

    Fix: Replaced the entire job with ``astral-sh/setup-uv`` + ``uv publish dist/*``,
    removing Python setup, twine, and the PyPI action entirely.
    """

    def test_uv_publish_present(self) -> None:
        """The publish step must use ``uv publish dist/*``."""
        steps = get_job_steps("publish")
        run_commands = [s["run"] for s in steps if "run" in s]

        matches = [c for c in run_commands if "uv publish" in c and "dist" in c]
        assert len(matches) >= 1, (
            f"Expected a step with 'uv publish dist/*' in publish job. Run commands found: {run_commands}"
        )

    def test_no_twine_reference(self) -> None:
        """Must NOT reference twine anywhere in the publish job."""
        steps = get_job_steps("publish")
        run_commands = [s["run"] for s in steps if "run" in s]

        forbidden = [c for c in run_commands if "twine" in c.lower()]
        assert len(forbidden) == 0, (
            "Found twine references in publish job: twine is no longer needed; "
            "use 'uv publish dist/*' instead. "
            f"Offending commands: {forbidden}"
        )

    def test_setup_uv_present(self) -> None:
        """The publish job must have an astral-sh/setup-uv step."""
        steps = get_job_steps("publish")
        uses_values = [s["uses"] for s in steps if "uses" in s]

        matches = [u for u in uses_values if "astral-sh/setup-uv" in u]
        assert len(matches) >= 1, (
            f"Expected a step using 'astral-sh/setup-uv' in publish job. Action uses found: {uses_values}"
        )

    def test_no_setup_python(self) -> None:
        """The publish job must NOT have an actions/setup-python step."""
        steps = get_job_steps("publish")
        uses_values = [s["uses"] for s in steps if "uses" in s]

        forbidden = [u for u in uses_values if "actions/setup-python" in u]
        assert len(forbidden) == 0, (
            "Found actions/setup-python in publish job — Python is not needed; "
            "uv publish does not require it. "
            f"Offending actions: {forbidden}"
        )

    def test_no_gh_action_pypi_publish(self) -> None:
        """The publish job must NOT use the deprecated gh-action-pypi-publish."""
        steps = get_job_steps("publish")
        uses_values = [s["uses"] for s in steps if "uses" in s]

        forbidden = [u for u in uses_values if "pypa/gh-action-pypi-publish" in u]
        assert len(forbidden) == 0, (
            "Found gh-action-pypi-publish in publish job — this has been replaced "
            "by 'uv publish dist/*'. "
            f"Offending actions: {forbidden}"
        )

    def test_environment_pypi_is_set(self) -> None:
        """The publish job must declare environment: pypi."""
        data = load_release_yaml()
        job = data.get("jobs", {}).get("publish", {})
        assert job.get("environment") == "pypi", "publish job must specify 'environment: pypi' for trusted publishing"

    def test_id_token_write_permission(self) -> None:
        """The publish job must have id-token: write (for OIDC)."""
        data = load_release_yaml()
        job = data.get("jobs", {}).get("publish", {})
        perms = job.get("permissions", {})
        assert perms.get("id-token") == "write", (
            "publish job must have 'permissions.id-token: write' for OIDC publishing"
        )


# ===================================================================
# Test 4: pyproject.toml declares pyinstaller in dev dependency group
# ===================================================================


class TestPyinstallerDevDependency:
    """pyproject.toml must declare pyinstaller in the dev dependency group so
    that ``uv sync --dev`` installs it and ``uv run pyinstaller`` works.
    """

    @staticmethod
    def _load_pyproject() -> dict[str, Any]:
        import tomllib

        with open(PYPROJECT_TOML, "rb") as f:
            return tomllib.load(f)

    def test_pyinstaller_in_dev_group(self) -> None:
        """pyinstaller must be listed under [dependency-groups] dev."""
        pyproject = self._load_pyproject()
        dev_deps = pyproject.get("dependency-groups", {}).get("dev", [])
        assert len(dev_deps) > 0, "[dependency-groups] dev is empty or missing"

        matches = [d for d in dev_deps if "pyinstaller" in d]
        assert len(matches) >= 1, f"pyinstaller not found in [dependency-groups] dev. Current dev deps: {dev_deps}"

    def test_pyinstaller_version_constraint(self) -> None:
        """pyinstaller must have version constraint >=6.21.0,<7.0."""
        pyproject = self._load_pyproject()
        dev_deps = pyproject.get("dependency-groups", {}).get("dev", [])

        pyinstaller_dep = next((d for d in dev_deps if "pyinstaller" in d), None)
        assert pyinstaller_dep is not None, "pyinstaller dep not found"

        assert ">=6.21.0" in pyinstaller_dep, (
            f"pyinstaller version constraint missing lower bound in: {pyinstaller_dep}"
        )
        assert "<7.0" in pyinstaller_dep, f"pyinstaller version constraint missing upper bound in: {pyinstaller_dep}"

    def test_dev_group_has_test_and_lint_deps(self) -> None:
        """Adding pyinstaller must not have removed existing dev dependencies."""
        pyproject = self._load_pyproject()
        dev_deps = pyproject.get("dependency-groups", {}).get("dev", [])

        expected_markers = [
            "pytest>=",
            "pytest-asyncio>=",
            "ruff>=",
            "mypy>=",
            "pre-commit>=",
        ]
        for marker in expected_markers:
            assert any(marker in d for d in dev_deps), (
                f"Expected a dev dep matching {marker!r} but none found. Current dev deps: {dev_deps}"
            )


# ===================================================================
# Test 5: uv.lock consistency
# ===================================================================


class TestUvLockConsistency:
    """``uv.lock`` must be consistent with pyproject.toml — catching the case
    where a new dependency was added to pyproject.toml but the lock file was
    not regenerated."""

    @staticmethod
    def _uv_binary() -> str:
        """Return the path to the uv binary."""
        # Try common locations
        for candidate in ("uv", os.fsdecode(Path.home() / ".local" / "bin" / "uv")):
            try:
                subprocess.run(
                    [candidate, "--version"],
                    capture_output=True,
                    check=False,
                )
                return candidate
            except FileNotFoundError:
                continue
        pytest.skip("uv binary not found — cannot check lock file consistency")

    def test_uv_lock_check_passes(self) -> None:
        """``uv lock --check`` must exit successfully.

        This validates that uv.lock is consistent with the dependency
        declarations in pyproject.toml.  If pyproject.toml was modified
        without running ``uv lock`` afterward, this test fails.
        """
        uv = self._uv_binary()
        result = subprocess.run(
            [uv, "lock", "--check"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, (
            f"uv lock --check failed (exit code {result.returncode})\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_lock_file_exists(self) -> None:
        """uv.lock must exist in the repo root."""
        lock_file = REPO_ROOT / "uv.lock"
        assert lock_file.is_file(), f"uv.lock not found at {lock_file}"


# ===================================================================
# Test 6: Build job has SBOM generation
# ===================================================================


class TestBuildJobSections:
    """The build job must generate an SBOM.  This was not part of the release
    pipeline failures, but is a related structural check."""

    def test_build_job_has_sbom_steps(self) -> None:
        """Build job must generate and verify an SBOM."""
        steps = get_job_steps("build")
        run_commands = [s["run"] for s in steps if "run" in s]

        sbom_related = [c for c in run_commands if "sbom" in c.lower()]
        assert len(sbom_related) >= 1, f"Expected SBOM-related commands in build job. Run commands: {run_commands}"

    def test_build_job_has_uv_sync(self) -> None:
        """Build job must use uv sync to install deps."""
        steps = get_job_steps("build")
        run_commands = [s["run"] for s in steps if "run" in s]

        assert any("uv sync" in c for c in run_commands), (
            f"Expected 'uv sync' in build job. Run commands: {run_commands}"
        )
