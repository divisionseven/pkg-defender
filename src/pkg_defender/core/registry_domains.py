# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Registry domain allowlist for SSRF attack prevention.

This module provides a hardcoded allowlist of trusted registry domains
for each package manager. All domain checks are performed against this
allowlist to prevent SSRF attacks through malicious redirects.

SECURITY NOTE: All URLs in the allowlist are hardcoded - no user input
is accepted for domain verification. This is a defense-in-depth measure
to prevent attacks where an attacker controls the redirect target.
"""

from __future__ import annotations

import urllib.parse
from typing import Final

# Hardcoded allowlist mapping package manager names to their allowed domains.
# Using frozenset for immutability - no runtime modifications allowed.
#
# Domains included:
# - Primary registry domains for each package manager
# - Known mirrors (e.g., npmmirror for npm in China)
# - Git hosting domains where dependency definitions live
# - CDN domains for package distributions
REGISTRY_ALLOWLIST: Final[dict[str, frozenset[str]]] = {
    # npm ecosystem
    "npm": frozenset({"registry.npmjs.org", "registry.npmmirror.com", "api.github.com", "libraries.io"}),
    # PyPI ecosystem (multiple aliases as they use the same backend)
    "pypi": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "pip": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "uv": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "pipx": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "pip3": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "pipenv": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    "poetry": frozenset({"pypi.org", "files.pythonhosted.org", "api.github.com", "libraries.io"}),
    # RubyGems
    "rubygems": frozenset({"rubygems.org", "api.github.com", "libraries.io"}),
    "gem": frozenset({"rubygems.org", "api.github.com", "libraries.io"}),
    "bundler": frozenset({"rubygems.org", "api.github.com", "libraries.io"}),
    # Cargo/Rust
    "cargo": frozenset({"crates.io", "github.com", "api.github.com", "libraries.io"}),
    # Composer/Packagist
    "composer": frozenset({"packagist.org", "api.github.com"}),
    # Homebrew
    "homebrew": frozenset(
        {
            "formulae.brew.sh",
            "github.com",
            "raw.githubusercontent.com",
            "api.github.com",
            "libraries.io",
        }
    ),
    "brew": frozenset(
        {
            "formulae.brew.sh",
            "github.com",
            "raw.githubusercontent.com",
            "api.github.com",
            "libraries.io",
        }
    ),
    # APT (Debian/Ubuntu) -- includes snapshot.debian.org for publish-time lookups
    "apt": frozenset(
        {
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "ports.ubuntu.com",
            "snapshot.debian.org",
            "api.github.com",
        }
    ),
    # YUM/DNF (RHEL/CentOS/Fedora) -- includes all 11 verified RPM repo
    # domains (YUM-001 section 6.1), plus Koji and Bodhi for the yum/dnf cascade.
    "yum": frozenset(
        {
            # Existing
            "repo.centos.org",
            "mirrorlist.centos.org",
            "download.fedoraproject.org",
            # Koji (RPM build lookup) and Bodhi (update status)
            "koji.fedoraproject.org",
            "bodhi.fedoraproject.org",
            # 11 verified RPM repo domains (YUM-001 section 6.1)
            "dl.fedoraproject.org",  # Fedora rawhide + EPEL
            "mirror.stream.centos.org",  # CentOS Stream 9
            "download.rockylinux.org",  # Rocky Linux 9
            "repo.almalinux.org",  # AlmaLinux 9
            "yum.oracle.com",  # Oracle Linux 9
            "repo.openeuler.org",  # openEuler 22.03 LTS
            "mirrors.kernel.org",  # Mageia 9
            "download.opensuse.org",  # openSUSE Tumbleweed
            "download1.rpmfusion.org",  # RPM Fusion free (EL9)
            "cdn.amazonlinux.com",  # Amazon Linux 2
            "api.github.com",
        }
    ),
    "dnf": frozenset(
        {
            # Same as yum -- RPM ecosystem shared domain set
            "repo.centos.org",
            "mirrorlist.centos.org",
            "download.fedoraproject.org",
            "koji.fedoraproject.org",
            "bodhi.fedoraproject.org",
            "dl.fedoraproject.org",
            "mirror.stream.centos.org",
            "download.rockylinux.org",
            "repo.almalinux.org",
            "yum.oracle.com",
            "repo.openeuler.org",
            "mirrors.kernel.org",
            "download.opensuse.org",
            "download1.rpmfusion.org",
            "cdn.amazonlinux.com",
            "api.github.com",
        }
    ),
    # Conda
    "conda": frozenset(
        {
            "repo.anaconda.com",
            "conda-forge.org",
            "repo.continuum.io",
            "api.anaconda.org",
            "api.github.com",
            "libraries.io",
        }
    ),
    # Yarn/PNPM/Bun (use npm registry -- including npmmirror for China)
    "pnpm": frozenset({"registry.npmjs.org", "registry.npmmirror.com", "api.github.com", "libraries.io"}),
    "yarn": frozenset({"registry.npmjs.org", "registry.npmmirror.com", "api.github.com", "libraries.io"}),
    "bun": frozenset({"registry.npmjs.org", "registry.npmmirror.com", "api.github.com", "libraries.io"}),
    # Packagist (Composer/PHP)
    "packagist": frozenset({"packagist.org", "api.github.com"}),
}

# Mapping from manager to their primary registry URL (for get_registry_url)
_REGISTRY_PRIMARY_URL: Final[dict[str, str]] = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "pip": "https://pypi.org",
    "uv": "https://pypi.org",
    "pipx": "https://pypi.org",
    "pip3": "https://pypi.org",
    "pipenv": "https://pypi.org",
    "poetry": "https://pypi.org",
    "rubygems": "https://rubygems.org",
    "gem": "https://rubygems.org",
    "cargo": "https://crates.io",
    "homebrew": "https://formulae.brew.sh",
    "brew": "https://formulae.brew.sh",
    "apt": "https://archive.ubuntu.com",
    "yum": "https://repo.centos.org",
    "dnf": "https://download.fedoraproject.org",
    "conda": "https://repo.anaconda.com",
    "yarn": "https://registry.npmjs.org",
    "pnpm": "https://registry.npmjs.org",
    "bun": "https://registry.npmjs.org",
    "bundler": "https://rubygems.org",
    "composer": "https://packagist.org",
    "packagist": "https://packagist.org",
}


def _extract_domain(url: str) -> str | None:
    """Extract the domain from a URL string.

    Handles various URL formats:
    - Full URLs: https://registry.npmjs.org/foo
    - Protocol-relative: //registry.npmjs.org/foo
    - Just domain: registry.npmjs.org

    Args:
        url: URL string to parse.

    Returns:
        The lowercase domain, or None if parsing fails.
    """
    if not url:
        return None

    url = url.strip()

    # Handle protocol-relative URLs (starts with //)
    if url.startswith("//"):
        url = f"https:{url}"

    # Handle bare domain (no scheme)
    if not url.startswith(("http://", "https://")):
        # Check if it's a bare domain (contains no path separator)
        url = f"https://{url}" if "/" not in url else f"https://{url}"

    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower() if parsed.netloc else None
    except Exception:
        return None


def is_domain_allowed(manager: str, url: str) -> bool:
    """Check if a URL's domain is in the allowlist for a package manager.

    This function verifies that the domain of the given URL is one of the
    trusted domains for the specified package manager. It handles URL
    redirects implicitly by checking the final destination URL.

    SECURITY: This is a defense-in-depth check. The actual HTTP request
    handling code should follow redirects and verify the final URL matches
    the allowlist before returning data to callers.

    Args:
        manager: Package manager name (e.g., "npm", "pypi", "cargo").
        url: Full URL to verify (e.g., "https://registry.npmjs.org/foo").

    Returns:
        True if the domain is in the allowlist for the manager,
        False otherwise. Also returns False if the manager is unknown
        or URL is invalid.

    Examples:
        >>> is_domain_allowed("npm", "https://registry.npmjs.org/lodash")
        True
        >>> is_domain_allowed("npm", "https://evil.com/malicious")
        False
        >>> is_domain_allowed("unknown", "https://example.com")
        False
    """
    # Normalize manager name
    manager = manager.lower().strip()

    # Check if manager is in allowlist
    allowed_domains = REGISTRY_ALLOWLIST.get(manager)
    if allowed_domains is None:
        return False

    # Extract domain from URL
    domain = _extract_domain(url)
    if domain is None:
        return False

    # Check if domain is in allowlist
    return domain in allowed_domains


def get_registry_url(manager: str) -> str:
    """Return the primary registry URL for a package manager.

    Args:
        manager: Package manager name (e.g., "npm", "pypi", "cargo").

    Returns:
        The primary registry URL with scheme (e.g., "https://registry.npmjs.org").

    Raises:
        ValueError: If the manager is not in the allowlist.

    Examples:
        >>> get_registry_url("npm")
        'https://registry.npmjs.org'
        >>> get_registry_url("pypi")
        'https://pypi.org'
    """
    manager = manager.lower().strip()

    url = _REGISTRY_PRIMARY_URL.get(manager)
    if url is None:
        raise ValueError(
            f"Unknown package manager: {manager!r}. Available managers: {', '.join(sorted(REGISTRY_ALLOWLIST.keys()))}"
        )

    return url


def get_allowed_domains(manager: str) -> frozenset[str]:
    """Return the set of allowed domains for a package manager.

    Args:
        manager: Package manager name (e.g., "npm", "pypi").

    Returns:
        Frozenset of allowed domains, or empty frozenset if unknown.

    Examples:
        >>> get_allowed_domains("npm")
        frozenset({'registry.npmjs.org', 'registry.npmmirror.com'})
    """
    manager = manager.lower().strip()
    return REGISTRY_ALLOWLIST.get(manager, frozenset())
