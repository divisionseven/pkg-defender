"""Value flags for all supported package managers.

VALUE_FLAGS are flags that consume the NEXT argument as their value.
Without these, "--index-url https://..." would parse "https://..." as a package name.

Each frozenset is passed to the tokenize_args() helper method.
"""

from __future__ import annotations

# pip / uv value flags (uv is largely pip-compatible)
PIP_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        # File-based install flags
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-t",
        "--target",
        "-d",
        "--download-dir",
        # Index / registry flags
        "-i",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--trusted-host",
        "--no-index",
        # Auth / cert flags
        "--cert",
        "--client-cert",
        # Cache / build flags
        "--cache-dir",
        "--build",
        "--build-dir",
        "--pre",
        "--no-build-isolation",
        "--build-option",
        "--config-settings",
        "-C",
        # Source flags
        "--src",
        "--root",
        "--prefix",
        "--upgrade-strategy",
        # Python / interpreter flags
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--python",
        # Logging / retries
        "--log",
        "--proxy",
        "--retries",
        "--timeout",
        # Other value-consuming flags
        "--exists-action",
        "--install-option",
        "--global-option",
        "--no-binary",
        "--only-binary",
        "--prefer-binary",
        "--progress-bar",
        "--root-user-action",
    }
)


# uv-specific value flags (supplement pip flags)
UV_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "--index",
        "--python",
        "-p",
        "--exclude-newer",
        "--constraint",
        "-c",
        "--override",
        "--upgrade-package",
        "-P",
        "--resolution",
        "--prerelease",
        "--link-mode",
        "--cache-dir",
        "--directory",
        "--project",
        "--package",
        "--script",
        "--env-file",
        "--target",
        "--prefix",
        "--no-project",
        "--no-scripts",
        "--script-expand",
        "-r",
        "--requirement",
    }
)


# npm value flags
NPM_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--workspace",
        "-w",
        "--wall",
        "--tag",
        "--registry",
        "--prefix",
        "--userconfig",
        "--globalconfig",
        "--access",
        "--otp",
        "--script-shell",
        "--before",
        "--install-strategy",
        "--cache",
        "--maxsockets",
        "--fetch-retry-mintimeout",
        "--fetch-retry-maxtimeout",
        "--fetch-retries",
        "--proxy",
        "--https-proxy",
        "--noproxy",
        "--package-lock-only",  # Boolean but listed for safety
    }
)


# yarn value flags
YARN_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--cwd",
        "--registry",
        "--tag",
        "--prefix",
        "--modules-folder",
        "--cache-folder",
        "--preferred-cache-folder",
        "--network-timeout",
        "--network-concurrency",
        "--proxy",
        "--https-proxy",
        "--version",  # yarn add pkg --version X
        "--pattern",
        "--json",
        "--flat",
        "--har",
    }
)


# pnpm value flags
PNPM_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--dir",
        "--prefix",
        "--registry",
        "--network-proxy",
        "--script-shell",
        "--shamefully-flatten",
        "--force",
        "--workspace",
        "--filter",
    }
)


# brew value flags
BREW_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--formula",
        "--cask",
        "--HEAD",
        "--fetch-HEAD",
        "--env",
        "--ignore-dependencies",
        "--only-dependencies",
        "--build-from-source",
        "--cc",
        "--git",
        "--debug",
        "--verbose",
    }
)

# poetry value flags
POETRY_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--lock",
        "--group",
        "--extras",
        "-E",
        "--verbose",
        "--ansi",
        "--no-ansi",
        "--dry-run",
    }
)

# pipenv value flags
PIPENV_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--ignore-pipfile",
        "--skip-lock",
        "--sequence",
        "--clear",
        "--code",
        "--deploy",
        "--keep-outdated",
        "--prune",
        "--selective-upgrade",
        "--exit-code",
    }
)

# bun value flags
BUN_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--cwd",
        "--env",
        "--no-save",
        "--platform",
        "--arch",
        "--global",
        "--bun",
    }
)

# gem value flags
GEM_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--version",
        "--no-doc",
        "--no-ri",
        "--no-exec",
        "--local",
        "--remote",
        "--source",
        "--platform",
        "--install-dir",
        "--bindir",
    }
)

# bundler value flags
BUNDLER_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--gemfile",
        "--path",
        "--jobs",
        "--retry",
        "--without",
        "--with",
        "--local",
        "--deployment",
        "--frozen",
    }
)

# composer value flags
COMPOSER_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--dev",
        "--no-dev",
        "--prefer-source",
        "--prefer-dist",
        "--no-interaction",
        "--no-progress",
        "--no-audit",
        "--no-autoloader",
        "--optimize-autoloader",
        "--ignore-platform-req",
        "--ignore-platform-reqs",
        "--prefer-stable",
        "--prefer-lowest",
        "--sort-packages",
    }
)

# cargo value flags
CARGO_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--git",
        "--path",
        "--locked",
        "--frozen",
        "--no-default-features",
        "--all-features",
        "--features",
        "--package",
        "--manifest-path",
        "--target",
        "--release",
        "--debug",
        "--example",
        "--bin",
        "--bench",
        "--test",
        "--doc",
        "--jobs",
    }
)

# apt value flags
APT_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--yes",
        "-y",
        "--no-install-recommends",
        "--upgrade",
        "--fix-broken",
        "--allow-downgrades",
        "--allow-remove-essential",
        "--allow-change-held-packages",
        "--force-yes",
        "--dry-run",
        "-s",
        "--simulate",
        "--install-suggests",
        "--no-install-suggests",
        "--purge",
        "-o",
        "--option",
    }
)

# dnf value flags
DNF_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--assumeyes",
        "-y",
        "--enablerepo",
        "--disablerepo",
        "--exclude",
        "--namespace",
        "--setopt",
        "--skip-broken",
        "--bugfix",
        "--enhancement",
        "--security",
        "--advisory",
        "--cve",
        "--latest",
        "--update",
        "--installed",
        "--available",
        "--forcearch",
        "--color",
    }
)

# conda value flags
CONDA_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--name",
        "-n",
        "--channel",
        "-c",
        "--yes",
        "-y",
        "--no-channel-priority",
        "--override-channels",
        "--use-local",
        "--offline",
        "--copy",
        "--link",
        "--force-conda-link",
        "--insecure",
        "--update-dependencies",
        "--update-all",
        "--file",
        "--prune",
    }
)
