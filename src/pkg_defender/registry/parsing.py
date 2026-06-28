"""Version and package reference parsing functions for each ecosystem.

These functions parse package references from raw command-line strings
into structured PackageRef objects.

Per spec Section 9:
- Python (pip/uv): PEP 508 package name + version specifier
- Node.js (npm/yarn/pnpm): scoped packages (@scope/name@version)
- Homebrew: simple name@version
"""

from __future__ import annotations

import re

from pkg_defender.models.command import InstallSource, PackageRef

# PEP 508 compliant package name regex
# Matches: requests, requests==2.31.0, requests>=2.0,<3.0, requests[security,socks]==2.31.0
PY_PKG_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?) # Package name (PEP 508)
    (?:\[(?P<extras>[^\]]+)\])? # Optional extras
    (?P<constraint> # Optional version constraint
        (?:==|!=|>=|<=|~=|>|<)
        [^\s,]+
        (?:,(?:==|!=|>=|<=|~=|>|<)[^\s,]+)*
    )?
    $
    """,
    re.VERBOSE,
)


def parse_python_package(raw: str, ecosystem: str = "") -> PackageRef:
    """
    Parse a Python package reference from pip/uv install arguments.

    Handles:
    - Package names: requests
    - Pinned versions: requests==2.31.0
    - Version constraints: requests>=2.0,<3.0
    - Extras: requests[security,socks]
    - VCS sources: git+https://...
    - URL sources: https://...
    - Local paths: ./, ../, ~/
    """
    if raw.startswith(("git+", "hg+", "svn+", "bzr+")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.VCS,
            raw=raw,
            ecosystem=ecosystem,
        )

    if raw.startswith(("http://", "https://", "ftp://")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.URL,
            raw=raw,
            ecosystem=ecosystem,
        )

    if raw.startswith((".", "/", "~")) or raw == ".":
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.LOCAL_PATH,
            raw=raw,
            ecosystem=ecosystem,
        )

    m = PY_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )

    name = m.group("name")
    extras_str = m.group("extras")
    constraint = m.group("constraint")

    extras = [e.strip() for e in extras_str.split(",")] if extras_str else []

    # Extract pinned version if constraint is exact (==X.Y.Z with no comma)
    pinned_version = None
    if constraint and constraint.startswith("==") and "," not in constraint:
        pinned_version = constraint[2:]

    return PackageRef(
        name=name,
        version=pinned_version,
        version_constraint=constraint,
        extras=extras,
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


# npm package regex
# Matches: express, @scope/express, express@4.18.0, @scope/express@17.0.0
NPM_PKG_RE = re.compile(
    r"""
    ^
    (?P<scope>@[A-Za-z0-9_-]+/)? # Optional @scope/
    (?P<name>[A-Za-z0-9._-]+) # Package name
    (?:@(?P<version>[^\s]+))? # Optional @version or @range
    $
    """,
    re.VERBOSE,
)


def parse_npm_package(raw: str, ecosystem: str = "") -> PackageRef:
    """
    Parse a Node.js package reference from npm/yarn/pnpm install arguments.

    Handles:
    - Package names: express
    - Scoped packages: @angular/core
    - Pinned versions: express@4.18.0
    - Version ranges: express@^4.0.0
    - Keywords: @latest, @next, @beta
    - VCS: github:, gitlab:, bitbucket:
    - URLs: https://...
    """
    if raw.startswith(("github:", "gitlab:", "bitbucket:", "gist:")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.VCS,
            raw=raw,
            ecosystem=ecosystem,
        )

    if raw.startswith(("http://", "https://")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.URL,
            raw=raw,
            ecosystem=ecosystem,
        )

    if raw.startswith((".", "/")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.LOCAL_PATH,
            raw=raw,
            ecosystem=ecosystem,
        )

    m = NPM_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )

    scope = m.group("scope") or ""
    name = scope + m.group("name")
    version_str = m.group("version")

    # Determine if version is pinned (exact) or a range
    pinned_version = None
    constraint = None
    if version_str:
        if version_str in ("latest", "next", "beta", "alpha"):
            constraint = version_str
        elif version_str and version_str[0].isdigit():
            pinned_version = version_str  # "4.18.0" — exact
        else:
            constraint = version_str  # "^4.0.0", "~4.18", ">=4.0.0"

    return PackageRef(
        name=name,
        version=pinned_version,
        version_constraint=constraint,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


# brew package regex
# Matches: tree, git, node, tree@3.1.0
BREW_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9._-]+)(?:@(?P<version>[^\s]+))?$")


def parse_brew_package(raw: str, ecosystem: str = "") -> PackageRef:
    """
    Parse a Homebrew formula reference.

    Handles:
    - Formula names: tree, git, node
    - Versioned formulae: tree@3.1.0
    """
    m = BREW_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )

    return PackageRef(
        name=m.group("name"),
        version=m.group("version"),
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


# gem package regex
GEM_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9._-]+)(?:@(?P<version>[^\s]+))?$")


def parse_gem_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse a RubyGems gem reference."""
    m = GEM_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    return PackageRef(
        name=m.group("name"),
        version=m.group("version"),
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


# composer package regex - vendor/pkg format
COMPOSER_PKG_RE = re.compile(r"^(?P<vendor>[a-zA-Z0-9_-]+/)?(?P<name>[a-zA-Z0-9._-]+)(?:@(?P<version>[^\s]+))?$")


def parse_composer_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse a Composer package reference (vendor/pkg@v1.0.0)."""
    m = COMPOSER_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    vendor = m.group("vendor") or ""
    name = vendor + m.group("name")
    version = m.group("version")
    return PackageRef(
        name=name,
        version=version,
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


# cargo package regex - supports ^,~,>= version constraints
CARGO_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9_-]+)(?:(?:\^|~|>=|<=|=)(?P<version>[^\s]+))?$")


def parse_cargo_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse a Cargo crate reference."""
    if raw.startswith(("git+", "git://", "http://", "https://")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.VCS,
            raw=raw,
            ecosystem=ecosystem,
        )
    if raw.startswith((".", "/")):
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.LOCAL_PATH,
            raw=raw,
            ecosystem=ecosystem,
        )
    m = CARGO_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    name = m.group("name")
    version = m.group("version")
    return PackageRef(
        name=name,
        version=version,
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


APT_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9._+-]+)(?:=(?P<version>[^\s]+))?$")


def parse_apt_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse an APT package reference."""
    m = APT_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    return PackageRef(
        name=m.group("name"),
        version=m.group("version"),
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


DNF_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9._+]+)(?:-(?P<version>[^\s]+))?$")


def parse_dnf_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse a DNF package reference."""
    m = DNF_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    return PackageRef(
        name=m.group("name"),
        version=m.group("version"),
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )


CONDA_PKG_RE = re.compile(r"^(?P<name>[a-zA-Z0-9._-]+)(?:=(?P<version>[^\s]+))?(?:=(?P<build>[^\s]+))?$")


def parse_conda_package(raw: str, ecosystem: str = "") -> PackageRef:
    """Parse a Conda package reference."""
    m = CONDA_PKG_RE.match(raw)
    if not m:
        return PackageRef(
            name=raw,
            version=None,
            version_constraint=None,
            extras=[],
            source=InstallSource.UNKNOWN,
            raw=raw,
            ecosystem=ecosystem,
        )
    return PackageRef(
        name=m.group("name"),
        version=m.group("version"),
        version_constraint=None,
        extras=[],
        source=InstallSource.REGISTRY,
        raw=raw,
        ecosystem=ecosystem,
    )
