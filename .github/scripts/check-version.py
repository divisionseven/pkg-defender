#!/usr/bin/env python3
"""
Verifies that the version declared in your project files matches the tag being
released. Catches "I forgot to bump the version" before a release goes out.

Scans for any of these files (only checks the ones that exist):
  pyproject.toml    [project] version or [tool.poetry] version
  package.json      .version
  Cargo.toml        [package] version
  setup.cfg         [metadata] version
  setup.py          version= (regex)
  VERSION           raw file content
  src/*/__init__.py or <package>/__init__.py   __version__ = "..."

Usage:
    python3 .github/scripts/check-version.py <tag>

    <tag> may include a leading 'v' (e.g. v1.2.3 or 1.2.3).

Exit codes:
    0   All found version files match the tag
    1   Usage error
    2   One or more files have a mismatched or unreadable version
"""

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[import]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


# ── Colour helpers (no deps) ─────────────────────────────────────────────────
def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def ok(text: str) -> str:
    return _c("32", text)


def err(text: str) -> str:
    return _c("31", text)


def warn(text: str) -> str:
    return _c("33", text)


def bold(text: str) -> str:
    return _c("1", text)


# ── Result dataclass ─────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    path: str
    found: str | None  # version found in file, or None if unreadable
    matches: bool


# ── Individual file checkers ─────────────────────────────────────────────────


def check_pyproject_toml(expected: str) -> CheckResult | None:
    path = Path("pyproject.toml")
    if not path.exists():
        return None

    if tomllib is None:
        # Fall back to regex if tomllib isn't available
        content = path.read_text(encoding="utf-8")
        m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        version = m.group(1) if m else None
    else:
        with path.open("rb") as f:
            data = tomllib.load(f)
        version = data.get("project", {}).get("version") or data.get("tool", {}).get("poetry", {}).get("version")

    return CheckResult(str(path), version, version == expected)


def check_package_json(expected: str) -> CheckResult | None:
    path = Path("package.json")
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        version = data.get("version")
    except (json.JSONDecodeError, OSError):
        version = None
    return CheckResult(str(path), version, version == expected)


def check_cargo_toml(expected: str) -> CheckResult | None:
    path = Path("Cargo.toml")
    if not path.exists():
        return None

    if tomllib is None:
        content = path.read_text(encoding="utf-8")
        m = re.search(
            r'^\[package\].*?^version\s*=\s*["\']([^"\']+)["\']',
            content,
            re.MULTILINE | re.DOTALL,
        )
        version = m.group(1) if m else None
    else:
        with path.open("rb") as f:
            data = tomllib.load(f)
        version = data.get("package", {}).get("version")

    return CheckResult(str(path), version, version == expected)


def check_setup_cfg(expected: str) -> CheckResult | None:
    path = Path("setup.cfg")
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    m = re.search(r"^\s*version\s*=\s*(.+)$", content, re.MULTILINE)
    version = m.group(1).strip() if m else None
    return CheckResult(str(path), version, version == expected)


def check_setup_py(expected: str) -> CheckResult | None:
    path = Path("setup.py")
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
    version = m.group(1) if m else None
    return CheckResult(str(path), version, version == expected)


def check_version_file(expected: str) -> CheckResult | None:
    path = Path("VERSION")
    if not path.exists():
        return None
    version = path.read_text(encoding="utf-8").strip()
    return CheckResult(str(path), version, version == expected)


def check_init_files(expected: str) -> list[CheckResult]:
    """Check __version__ in __init__.py files under src/ or top-level packages."""
    results = []
    candidates = list(Path("src").rglob("__init__.py")) if Path("src").exists() else []
    # Also check top-level packages (directories with __init__.py, not src/)
    candidates += [
        p
        for p in Path(".").glob("*/__init__.py")
        if not str(p).startswith("src/")
        and not str(p).startswith(".")
        and "test" not in str(p)
        and "build" not in str(p)
    ]
    for path in candidates:
        content = path.read_text(encoding="utf-8")
        m = re.search(r'^\s*__version__\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if m:
            version = m.group(1)
            results.append(CheckResult(str(path), version, version == expected))
    return results


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1

    tag = sys.argv[1]
    version = tag.lstrip("v")  # normalise: v1.2.3 → 1.2.3

    print(bold(f"\nVersion consistency check — expecting: {version}"))
    print("─" * 52)

    # Collect all results
    results: list[CheckResult] = []
    for checker in (
        check_pyproject_toml,
        check_package_json,
        check_cargo_toml,
        check_setup_cfg,
        check_setup_py,
        check_version_file,
    ):
        result = checker(version)
        if result is not None:
            results.append(result)

    results.extend(check_init_files(version))

    if not results:
        print(warn("  No version files found. Nothing to check."))
        print(warn("  If your project has a version file, add support for it above."))
        return 0

    # Print results
    failures = 0
    for r in results:
        if r.found is None:
            status = warn("  WARN")
            detail = "could not parse version"
        elif r.matches:
            status = ok("  PASS")
            detail = r.found
        else:
            status = err("  FAIL")
            detail = f"found '{r.found}', expected '{version}'"
            failures += 1

        print(f"{status}  {r.path:<40}  {detail}")

    print("─" * 52)

    if failures > 0:
        print(err(f"\n✗ {failures} file(s) have a version mismatch."))
        print(err("  Update them to match the tag before releasing.\n"))
        return 2
    else:
        print(ok(f"\n✓ All {len(results)} file(s) match version {version}.\n"))
        return 0


if __name__ == "__main__":
    sys.exit(main())
