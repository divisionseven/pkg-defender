"""Package name extraction from unstructured social feed text."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Pre-compiled regex patterns (compiled once, reused)
_INSTALL_PATTERN = re.compile(
    r"\b(?:npm\s+(?:i|install)|pip3?\s+install|yarn\s+add|pnpm\s+(?:add|install))\s+([\w@/.-]+)",
    re.IGNORECASE,
)
_BACKTICK_PATTERN = re.compile(r"`([\w@/.-]+)`")
_NPM_SCOPED = re.compile(r"^@[\w-]+/[\w-]+$")
_PYTHON_PKG = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")

# Common English words that match package patterns but are NOT packages
_FALSE_POSITIVES: set[str] = {
    "the",
    "a",
    "an",
    "is",
    "it",
    "in",
    "to",
    "for",
    "of",
    "and",
    "or",
    "not",
    "this",
    "that",
    "with",
    "from",
    "by",
    "as",
    "at",
    "on",
    "be",
}


@dataclass
class ExtractedPackage:
    """A package name extracted from unstructured text."""

    package: str
    ecosystem: str  # "npm", "pypi", or "unknown"
    source_hint: str  # Which regex matched: "install_cmd" or "backtick"


def extract_packages(text: str) -> list[ExtractedPackage]:
    """Extract package names from unstructured text.

    Uses two strategies:
    1. Install command pattern: 'npm install foo', 'pip install bar'
    2. Backtick-quoted names: '`axios`', '`requests`'

    Args:
        text: Unstructured text from a social feed entry.

    Returns:
        List of ExtractedPackage objects. Empty if none found.
    """
    results: list[ExtractedPackage] = []
    seen: set[str] = set()

    # Strategy 1: install commands (ecosystem is known from command)
    for match in _INSTALL_PATTERN.finditer(text):
        pkg = match.group(1).strip()
        cmd = match.group(0).lower()
        if pkg.lower() in _FALSE_POSITIVES or pkg in seen:
            continue
        ecosystem = "npm" if "npm" in cmd or "yarn" in cmd or "pnpm" in cmd else "pypi"
        results.append(ExtractedPackage(package=pkg, ecosystem=ecosystem, source_hint="install_cmd"))
        seen.add(pkg)

    # Strategy 2: backtick-quoted names (ecosystem unknown unless determinable)
    for match in _BACKTICK_PATTERN.finditer(text):
        pkg = match.group(1).strip()
        if pkg.lower() in _FALSE_POSITIVES or pkg in seen:
            continue
        if not _is_plausible_package_name(pkg):
            continue
        ecosystem = _guess_ecosystem(pkg)
        results.append(ExtractedPackage(package=pkg, ecosystem=ecosystem, source_hint="backtick"))
        seen.add(pkg)

    return results


def _is_plausible_package_name(name: str) -> bool:
    """Check if a string looks like a real package name, not a file path or code reference.

    Args:
        name: Candidate package name extracted from backtick-quoted text.

    Returns:
        True if the name plausibly represents a package, False otherwise.
    """
    if len(name) < 2:
        return False
    if name.startswith("."):
        return False
    if name[0].isdigit():
        return False
    if "." in name and not name.startswith("@"):
        return False
    return not ("/" in name and not name.startswith("@"))


def _guess_ecosystem(pkg_name: str) -> str:
    """Guess ecosystem from package name heuristics.

    Args:
        pkg_name: Package name string.

    Returns:
        "npm", "pypi", or "unknown".
    """
    if _NPM_SCOPED.match(pkg_name):
        return "npm"
    if pkg_name.endswith((".js", ".ts")):
        return "npm"
    if _PYTHON_PKG.match(pkg_name) and "-" in pkg_name:
        return "pypi"  # Python packages commonly use hyphens
    return "unknown"
