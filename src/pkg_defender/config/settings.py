"""Configuration system — TOML loader, dataclass schema, env var overrides.

Configuration:
    Defaults are set in each dataclass field definition. Override via:
    - Environment variables:  PKGD_<SECTION>_<FIELD>  (e.g., PKGD_COOLDOWN_DEFAULT_DAYS)
    - TOML config file:       [cooldown] / default_days = 7  in  pkgd.toml  or  pyproject.toml
    - Per-package:          config.cooldown.overrides["package_name"] = 7
    - Disable:             config.cooldown.enabled = False
"""

from __future__ import annotations

import functools
import io
import json
import logging as _log
import os
import tomllib
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union, get_args, get_origin

import platformdirs

_logger = _log.getLogger(__name__)

# =============================================================================
# NOTE: Default config values are now generated dynamically from the dataclass
# definitions in this file. No manual updates are required when adding options.
# =============================================================================


@dataclass
class CooldownConfig:
    """Cooldown gate configuration — enforces a minimum age before installing new packages.

    The cooldown gate delays installation of newly-released package versions,
    reducing exposure to supply-chain attacks that surface within the first days
    of a release.  The default is 7 days as recommended by the PKG-Defender team.
    The PKG-Defender team uses a 7-day cooldown on its own systems.
    (set PKGD_COOLDOWN_DEFAULT_DAYS=3 for a shorter window.)

    Configuration options:
        default_days:
            Minimum age in days before a new version is allowed (default: 7).
            Override via:
              - Env var:     PKGD_COOLDOWN_DEFAULT_DAYS=<days>
              - TOML file:   [cooldown] / default_days = <days>
        overrides["package_name"]:
            Per-package days override (package name -> days).  Example in TOML:
              [cooldown.overrides]
              "react" = 14
        enabled:
            Set to False to disable cooldown checking entirely.
            Example in TOML:  [cooldown] / enabled = false
        strict_mode:
            If True, audit exits non-zero when threats are found during cooldown enforcement.
        bypass_require_reason:
            If True, a reason must be provided when bypassing the cooldown.
        bypass_log_retention_days:
            Number of days to retain bypass audit log entries (default: 90).

    Attributes:
        default_days: Number of days a new version must age before install is allowed.
        enabled: Whether cooldown checking is active.
        strict_mode: If True, audit exits non-zero when threats are found during
            cooldown enforcement. If False, audit exits zero even with threats
            (weakened security posture).
        overrides: Per-package cooldown days overrides (package name -> days).
        bypass_require_reason: Whether bypass requires a reason to be provided.
        bypass_log_retention_days: Number of days to retain bypass log entries.
    """

    default_days: int = field(
        default=7,
        metadata={
            "description": "Minimum age in days before a new package version is allowed (default: 7).",
        },
    )
    enabled: bool = field(
        default=True,
        metadata={
            "description": "Whether cooldown checking is active. Set false to disable entirely.",
        },
    )
    strict_mode: bool = field(
        default=True,
        metadata={
            "description": (
                "If True, audit exits non-zero when threats are found during "
                "cooldown enforcement. If False, audit exits zero even with "
                "threats (weakened security posture)."
            ),
        },
    )
    overrides: dict[str, int] = field(
        default_factory=dict,
        metadata={
            "description": "Per-package cooldown days override (package name → days).",
        },
    )
    per_ecosystem: dict[str, int] = field(
        default_factory=dict,
        metadata={
            "description": "Per-ecosystem cooldown window overrides (ecosystem → days).",
        },
    )
    bypass_require_reason: bool = field(
        default=True,
        metadata={
            "description": "If True, a reason must be provided when bypassing the cooldown.",
        },
    )
    bypass_log_retention_days: int = field(
        default=90,
        metadata={
            "description": "Number of days to retain bypass audit log entries.",
        },
    )


@dataclass
class FeedConfig:
    """Intelligence feed configuration.

    Attributes:
        osv_enabled: Whether the OSV.dev feed is active.
        ghsa_enabled: Whether the GitHub Security Advisory feed is active.
        ghsa_token: Bearer token for GitHub GraphQL API (from PKGD_FEEDS_GHSA_TOKEN).
        mastodon_enabled: Whether the Mastodon social feed is active.
        mastodon_instance: Mastodon instance hostname to query.
        mastodon_hashtags: Hashtags to monitor for supply chain signals.
        mastodon_max_age_hours: Max age in hours for Mastodon posts.
        reddit_enabled: Whether the Reddit social feed is active.
        reddit_subreddits: Subreddits to monitor.
        reddit_keywords: Keywords to search for in subreddit posts.
        reddit_max_age_hours: Max age in hours for Reddit posts.
        reddit_client_id: Reddit OAuth client_id (required for official API).
        reddit_client_secret: Reddit OAuth client_secret (required for official API).
        rss_enabled: Whether the RSS feed is active.
        rss_urls: RSS feed URLs to monitor.
        rss_keywords: Keywords to filter RSS entries.
        rss_max_age_hours: Max age in hours for RSS entries.
        x_twitter_enabled: Whether the X/Twitter feed is active (BYOK).
        x_twitter_bearer_token: Bearer token for X/Twitter API.
        x_twitter_trusted_accounts: Trusted X/Twitter account IDs.
        x_twitter_keywords: Keywords to search for in tweets.
        x_twitter_max_age_hours: Max age in hours for tweets.
        staleness_threshold_hours: Hours before a feed is considered stale.
        socket_api_key: API key for Socket.dev feed.
        socket_enabled: Whether the Socket.dev feed is active.
        npm_advisory_enabled: Whether to enable the npm advisory feed.
        ossf_malicious_enabled: Whether to enable the OSSF malicious packages feed.
        http_timeout: HTTP timeout in seconds for feed requests.
    """

    osv_enabled: bool = field(
        default=True,
        metadata={"description": "Whether the OSV.dev feed is active."},
    )
    ghsa_enabled: bool = field(
        default=True,
        metadata={"description": "Whether the GitHub Security Advisory feed is active."},
    )
    ghsa_token: str = field(
        default="",
        metadata={
            "description": "Bearer token for GitHub GraphQL API (rate limit 60→5,000/hr).",
            "secret": True,
        },
    )

    # Social feeds — informational only (never block)
    mastodon_enabled: bool = field(
        default=False,
        metadata={"description": "Whether the Mastodon social feed is active (disabled until OAuth exists)."},
    )
    mastodon_instance: str = field(
        default="infosec.exchange",
        metadata={"description": "Mastodon instance hostname to query."},
    )
    mastodon_hashtags: list[str] = field(
        default_factory=lambda: [
            "supplychain",
            "npmjs",
            "pypi",
            "infosec",
            "malware",
        ],
        metadata={"description": "Hashtags to monitor for supply chain signals."},
    )
    mastodon_max_age_hours: int = field(
        default=72,
        metadata={"description": "Max age in hours for Mastodon posts to consider."},
    )

    reddit_enabled: bool = field(
        default=False,
        metadata={"description": "Whether the Reddit social feed is active (bring your own keys)."},
    )
    reddit_subreddits: list[str] = field(
        default_factory=lambda: [
            "netsec",
            "javascript",
            "Python",
            "programming",
        ],
        metadata={"description": "Subreddits to monitor for threat signals."},
    )
    reddit_keywords: list[str] = field(
        default_factory=lambda: [
            "supply chain",
            "compromised",
            "malicious",
            "backdoor",
            "typosquat",
        ],
        metadata={"description": "Keywords to search for in subreddit posts."},
    )
    reddit_max_age_hours: int = field(
        default=72,
        metadata={"description": "Max age in hours for Reddit posts to consider."},
    )
    reddit_client_id: str = field(
        default="",
        metadata={
            "description": "Reddit OAuth client ID (required for official API).",
            "secret": True,
        },
    )
    reddit_client_secret: str = field(
        default="",
        metadata={
            "description": "Reddit OAuth client secret (required for official API).",
            "secret": True,
        },
    )

    rss_enabled: bool = field(
        default=True,
        metadata={"description": "Whether the RSS feed is active."},
    )
    rss_urls: list[str] = field(
        default_factory=lambda: [
            "https://socket.dev/api/blog/feed.atom",
            "https://snyk.io/blog/feed/",
            "https://openssf.org/feed/",
            "https://github.blog/security/feed/",
            "https://blog.gitguardian.com/feed/",
            "https://blog.sonatype.com/rss.xml",
        ],
        metadata={"description": "RSS feed URLs to monitor for advisory data."},
    )
    rss_keywords: list[str] = field(
        default_factory=lambda: [
            # Core security terms
            "vulnerability",
            "vulnerabilities",
            "CVE",
            # Attack types
            "supply chain",
            "supply-chain",
            "compromised",
            "malicious",
            "backdoor",
            "typosquat",
            "malware",
            "virus",
            "ransomware",
            "exploit",
            "breach",
            "leak",
            # Ecosystem specific
            "npm",
            "pypi",
            "pip",
            "rubygems",
            "cargo",
            "go.mod",
            "maven",
            "gradle",
            # General security
            "security",
            "hack",
            "attack",
            "patch",
            "update",
            # Incident response
            "incident",
            "alert",
            "warning",
            "advisory",
        ],
        metadata={"description": "Keywords to filter RSS entries."},
    )
    rss_max_age_hours: int = field(
        default=336,
        metadata={"description": "Max age in hours for RSS entries to consider (default 14 days)."},
    )

    x_twitter_enabled: bool = field(
        default=False,
        metadata={"description": "Whether the X/Twitter feed is active (bring your own key)."},
    )
    x_twitter_bearer_token: str = field(
        default="",
        metadata={
            "description": "Bearer token for X/Twitter API v2.",
            "secret": True,
        },
    )
    x_twitter_trusted_accounts: list[str] = field(
        default_factory=list,
        metadata={"description": "Trusted X/Twitter account IDs to monitor specifically."},
    )
    x_twitter_keywords: list[str] = field(
        default_factory=lambda: [
            "supply chain",
            "npm compromised",
            "pypi malicious",
            "malware",
        ],
        metadata={"description": "Keywords to search for in tweets."},
    )
    x_twitter_max_age_hours: int = field(
        default=48,
        metadata={"description": "Max age in hours for tweets to consider."},
    )

    staleness_threshold_hours: int = field(
        default=8,
        metadata={"description": "Hours before a feed is considered stale (triggers re-sync)."},
    )
    socket_api_key: str = field(
        default="",
        metadata={
            "description": "API key for Socket.dev threat feed.",
            "secret": True,
        },
    )
    socket_enabled: bool = field(
        default=False,
        metadata={"description": "Whether the Socket.dev feed is active."},
    )
    npm_advisory_enabled: bool = field(
        default=False,
        metadata={"description": "Whether the npm advisory feed is active."},
    )
    ossf_malicious_enabled: bool = field(
        default=True,
        metadata={"description": "Whether the OSSF malicious packages feed is active."},
    )
    http_timeout: int = field(
        default=60,
        metadata={"description": "HTTP timeout in seconds for all feed/registry requests."},
    )
    feed_sync_timeout: int = field(
        default=7200,
        metadata={
            "description": "Maximum seconds to wait for all feeds to sync (0=fall back to no timeout).",
        },
    )


@dataclass
class OutputConfig:
    """Output formatting configuration.

    Attributes:
        color: Whether to use colored terminal output.
        json_mode: Whether to emit JSON output (for CI consumption).
        verbose: Whether to enable verbose output.
        show_ascii_banner: Whether to show ASCII banner in help output.
        intel_exclude_severity: List of severity levels to exclude from intel report output.
        search_exclude_severity: List of severity levels to exclude from search output.
    """

    color: bool = field(
        default=True,
        metadata={"description": "Whether to use colored terminal output."},
    )
    json_mode: bool = field(
        default=False,
        metadata={"description": "Whether to emit JSON output (for CI consumption)."},
    )
    verbose: bool = field(
        default=False,
        metadata={"description": "Whether to enable verbose logging/output."},
    )
    show_ascii_banner: bool = field(
        default=True,
        metadata={"description": "Whether to show the ASCII banner in help output."},
    )
    intel_exclude_severity: list[str] = field(
        default_factory=lambda: ["UNKNOWN"],
        metadata={"description": "Severity levels to exclude from intel report output."},
    )
    search_exclude_severity: list[str] = field(
        default_factory=lambda: ["UNKNOWN"],
        metadata={"description": "Severity levels to exclude from search output."},
    )


@dataclass
class BypassConfig:
    """Bypass command configuration.

    Controls whether the ``pkgd bypass`` CLI command is available.
    Disabled by default — must be explicitly enabled via config or env var.

    Attributes:
        command_enabled: If False, the bypass command returns an error.
            Default False — admins must opt in.
    """

    command_enabled: bool = field(
        default=False,
        metadata={
            "description": "If False, the bypass CLI command returns an error. Disabled by default — opt-in only.",
        },
    )


@dataclass
class DaemonConfig:
    """Configuration for the background daemon process.

    Attributes:
        run_on_battery: If True, allow the daemon to run on battery power.
            Default False — daemon self-terminates when on battery to conserve power.
        sync_interval_hours: Hours between daemon feed sync cycles.
            Default 4 — all feeds sync together in one cycle.
    """

    run_on_battery: bool = field(
        default=False,
        metadata={
            "description": (
                "Allow the daemon to run on battery power. Default False — daemon terminates when on battery."
            ),
        },
    )
    sync_interval_hours: int = field(
        default=4,
        metadata={"description": "Hours between daemon feed sync cycles."},
    )


@dataclass
class DatabaseConfig:
    """Database configuration.

    Attributes:
        wal_mode: Enable WAL journal mode (board: non-negotiable).
        busy_timeout_ms: SQLite busy timeout in milliseconds (board: 5s).
        path: Custom database directory path (defaults to platform data dir).
        snapshot_url: Custom URL for database snapshot download (bypasses GitHub API).
    """

    # Path resolved at runtime via platformdirs
    wal_mode: bool = field(
        default=True,
        metadata={"description": "Enable WAL journal mode for SQLite."},
    )
    busy_timeout_ms: int = field(
        default=5000,
        metadata={"description": "SQLite busy timeout in milliseconds."},
    )
    path: Path | None = field(
        default=None,
        metadata={"description": "Custom database directory path (defaults to platform data dir)."},
    )
    snapshot_url: str = field(
        default="",
        metadata={
            "description": "Custom URL for database snapshot download (bypasses GitHub API).",
            "secret": True,
        },
    )
    retention_days: int | None = field(
        default=None,
        metadata={
            "description": (
                "Number of days to retain threat records. Records with "
                "last_seen older than this are deleted after each feed sync. "
                "None (default) = feature disabled — no automatic pruning."
            ),
        },
    )


@dataclass
class PKGDConfig:
    """Root configuration for pkg-defender.

    Attributes:
        cooldown: Cooldown gate settings.
        feeds: Intelligence feed settings.
        output: Output formatting settings.
        database: SQLite database settings.
    command_timeout_seconds: Timeout in seconds for command execution (default: 30).
    fail_on_threat_enabled: Whether --fail-on-threat is enabled by default (default: True).
    fail_on_warn_enabled: Whether PKGD_FAIL_ON_WARN is active (default: False).
    """

    cooldown: CooldownConfig = field(
        default_factory=CooldownConfig,
        metadata={"description": "Cooldown gate configuration."},
    )
    feeds: FeedConfig = field(
        default_factory=FeedConfig,
        metadata={"description": "Intelligence feed configuration."},
    )
    output: OutputConfig = field(
        default_factory=OutputConfig,
        metadata={"description": "Output formatting configuration."},
    )
    database: DatabaseConfig = field(
        default_factory=DatabaseConfig,
        metadata={"description": "Database configuration."},
    )
    bypass: BypassConfig = field(
        default_factory=BypassConfig,
        metadata={"description": "Bypass command configuration."},
    )
    daemon: DaemonConfig = field(
        default_factory=DaemonConfig,
        metadata={"description": "Daemon process configuration."},
    )
    command_timeout_seconds: int = field(
        default=30,
        metadata={"description": "Timeout in seconds for command execution."},
    )
    registry_api_timeout: float = field(
        default=10.0,
        metadata={
            "description": "Timeout in seconds for individual registry API calls (resolve version, get publish time)."
        },  # noqa: E501
    )
    per_ecosystem_registry_timeout: dict[str, float] = field(
        default_factory=dict,
        metadata={"description": "Per-ecosystem override for registry API timeout (ecosystem → seconds)."},
    )
    fail_on_threat_enabled: bool = field(
        default=True,
        metadata={"description": "Whether --fail-on-threat is enabled by default."},
    )
    fail_on_warn_enabled: bool = field(
        default=False,
        metadata={"description": "Whether PKGD_FAIL_ON_WARN (block on warning) is active."},
    )
    enable_homebrew_formula_commit: bool = field(
        default=True,
        metadata={"description": "Enable homebrew-core commit timestamp resolution."},
    )


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------


def get_config_dir() -> Path:
    """Return platform-appropriate config directory using platformdirs.

    Creates the directory (and parents) if it doesn't exist.

    If the directory cannot be created (permission denied, invalid parent
    path, or filesystem error) a warning is logged and the path is still
    returned — callers must handle the case where the directory does not
    actually exist on disk.

    Returns:
        Path to config directory.
    """
    config_dir = Path(platformdirs.user_config_dir("pkg-defender"))
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        _logger.warning(
            "Cannot create config directory %s: Permission denied. Continuing with default configuration.",
            config_dir,
        )
        import click

        click.echo(
            f"Error: Cannot create config directory {config_dir}: Permission denied. "
            f"Check filesystem permissions. Continuing with default configuration.",
            err=True,
        )
    except FileNotFoundError as exc:
        _logger.warning(
            "Cannot create config directory %s: parent path is not a "
            "directory (%s). Continuing with default configuration.",
            config_dir,
            exc,
        )
        import click

        click.echo(
            f"Error: Cannot create config directory {config_dir}: "
            f"parent path is not a directory ({exc}). "
            f"Check the path exists. Continuing with default configuration.",
            err=True,
        )
    except OSError:
        _logger.warning(
            "Cannot create config directory %s due to a filesystem error. Continuing with default configuration.",
            config_dir,
        )
        import click

        click.echo(
            f"Error: Cannot create config directory {config_dir} due to a filesystem error. "
            f"Check disk space and permissions. Continuing with default configuration.",
            err=True,
        )
    return config_dir


def get_data_dir() -> Path:
    """Return platform-appropriate data directory using platformdirs.

    Creates the directory (and parents) if it doesn't exist.

    If the directory cannot be created (permission denied, invalid parent
    path, or filesystem error) a warning is logged and the path is still
    returned — callers must handle the case where the directory does not
    actually exist on disk.

    Returns:
        Path to data directory.
    """
    data_dir = Path(platformdirs.user_data_dir("pkg-defender"))
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        _logger.warning(
            "Cannot create data directory %s: Permission denied. Continuing with default configuration.",
            data_dir,
        )
        import click

        click.echo(
            f"Error: Cannot create data directory {data_dir}: Permission denied. "
            f"Check filesystem permissions. Continuing with default configuration.",
            err=True,
        )
    except FileNotFoundError as exc:
        _logger.warning(
            "Cannot create data directory %s: parent path is not a "
            "directory (%s). Continuing with default configuration.",
            data_dir,
            exc,
        )
        import click

        click.echo(
            f"Error: Cannot create data directory {data_dir}: "
            f"parent path is not a directory ({exc}). "
            f"Check the path exists. Continuing with default configuration.",
            err=True,
        )
    except OSError:
        _logger.warning(
            "Cannot create data directory %s due to a filesystem error. Continuing with default configuration.",
            data_dir,
        )
        import click

        click.echo(
            f"Error: Cannot create data directory {data_dir} due to a filesystem error. "
            f"Check disk space and permissions. Continuing with default configuration.",
            err=True,
        )
    return data_dir


def get_default_config_path() -> Path:
    """Return the default config file path.

    Returns:
        Path to ``~/.config/pkg-defender/pkgd.toml`` (platform equivalent).
    """
    return get_config_dir() / "pkgd.toml"


# System config path (read-only, admin-managed)
SYSTEM_CONFIG_PATH = Path("/etc/pkgd/pkgd.toml")

# Project config filename
PROJECT_CONFIG_NAME = "pkgd.toml"


def _find_git_root(cwd: Path) -> Path | None:
    """Find the git root directory by walking up from cwd.

    Stops at filesystem root if no .git directory is found.

    Args:
        cwd: Starting directory for the search.

    Returns:
        Path to git root if found, None otherwise.
    """
    current = cwd.resolve()
    for parent in [current] + list(current.parents):
        if (parent / ".git").is_dir():
            return parent
    return None


def _find_project_config_path(cwd: Path) -> Path | None:
    """Find a project-level config file by walking up from cwd.

    Walks up from the current working directory looking for pkgd.toml.
    Stops at git root or filesystem root boundary.

    Args:
        cwd: Starting directory for the search.

    Returns:
        Path to pkgd.toml if found, None otherwise.
    """
    git_root = _find_git_root(cwd)

    current = cwd.resolve()
    for parent in [current] + list(current.parents):
        # Stop at git root boundary
        if git_root and parent != git_root and not str(parent).startswith(str(git_root)):
            break
        # Stop at filesystem root
        if parent.parent == parent:
            break

        config_path = parent / PROJECT_CONFIG_NAME
        if config_path.is_file():
            return config_path

    return None


def get_db_path(config: PKGDConfig | None = None) -> Path:
    """Return the SQLite database path.

    Uses custom path if configured, otherwise falls back to platform data dir.

    Args:
        config: Optional config instance. If None, loads default config.

    Returns:
        Path to ``threats.db`` inside custom directory or platform data directory.
    """
    if config is None:
        config = load_config()
    if config.database.path:
        return config.database.path / "threats.db"
    return get_data_dir() / "threats.db"


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def _read_toml_bytes_cached(path: Path) -> bytes | None:
    """Read raw TOML file bytes with automatic cache invalidation on file change.

    The cache is keyed by ``(path, mtime, size)`` so any file modification
    on disk — whether via ``config set``, ``config reset``, ``setup``, or
    an external editor — automatically invalidates the cached entry.

    Returns ``None`` if the file is missing or unreadable (FileNotFoundError,
    PermissionError, OSError). Errors are NOT cached: if a file is temporarily
    unreadable, the next call will retry the stat and read.

    This function caches only the I/O cost. The caller (``load_config()``)
    still parses TOML, applies data to config, and applies env var overrides
    fresh on every call — those are NOT cached.
    """
    import logging as _log

    _logger = _log.getLogger(__name__)
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        return None
    except PermissionError:
        _logger.warning(
            "Cannot stat config file %s: Permission denied. Skipping.",
            path,
        )
        return None
    except OSError:
        return None

    return _read_toml_bytes_impl(str(path), stat_result.st_mtime, stat_result.st_size)


@functools.lru_cache(maxsize=128)
def _read_toml_bytes_impl(path_str: str, mtime: float, size: int) -> bytes | None:
    """Internal cached reader keyed by path + mtime + size.

    Args:
        path_str: String form of the config file path.
        mtime: File modification time (from ``stat_result.st_mtime``).
        size: File size in bytes (from ``stat_result.st_size``).

    Returns:
        Raw file bytes, or ``None`` if the file is missing or unreadable.
    """
    import logging as _log

    _logger = _log.getLogger(__name__)
    try:
        return Path(path_str).read_bytes()
    except FileNotFoundError:
        return None
    except PermissionError:
        _logger.warning(
            "Cannot read config file %s: Permission denied. Skipping.",
            path_str,
        )
        return None
    except OSError:
        return None


def load_config(
    config_path: Path | None = None,
    *,
    _cwd: Path | None = None,
) -> PKGDConfig:
    """Load configuration from multiple sources with proper precedence.

    Resolution order (highest wins):
      1. Defaults
      2. System config (/etc/pkgd/pkgd.toml) — loaded first, can be overridden
      3. User config (~/.config/pkg-defender/pkgd.toml, platform equivalent) — overrides system
      4. Project config (./pkgd.toml or nearest parent) — highest file priority
      5. PKGD_CONFIG_PATH environment variable — only consulted if config_path param is None
      6. PKGD_* environment variable overrides — highest priority, always applied

    Behavior:
      - If config_path parameter is provided: uses that file directly, PKGD_CONFIG_PATH is ignored
      - Otherwise: uses PKGD_CONFIG_PATH env var, or falls back to system → user → project discovery
      - PKGD_* environment variables always override everything (even when config_path is provided)

    Args:
        config_path: Explicit path to config TOML. If provided, skips all
            automatic discovery (system/user/project/env var).
        _cwd: Internal: starting directory for project config search.
            Defaults to current working directory.

    Returns:
        Fully resolved PKGDConfig instance.
    """
    import logging as _log

    logger = _log.getLogger(__name__)
    config = PKGDConfig()

    # Determine config sources to load
    if config_path is None:
        if env_config_path := os.environ.get("PKGD_CONFIG_PATH"):
            config_path = Path(env_config_path)
        else:
            # Load system config first (if readable)
            _load_system_config(config, logger)

            # Load user config
            config_path = get_default_config_path()

            # Load project config (overrides user)
            project_path = _find_project_config_path(_cwd or Path.cwd())
            if project_path and project_path != config_path:
                config_path = project_path

    # Apply TOML file if it exists (cached file read)
    if config_path and config_path.exists():
        raw_bytes = _read_toml_bytes_cached(config_path)
        if raw_bytes is not None:
            try:
                data: dict[str, Any] = tomllib.load(io.BytesIO(raw_bytes))
            except tomllib.TOMLDecodeError as exc:
                logger.error(
                    "Config file %s is corrupt: %s. Using defaults. "
                    "Fix the file or run 'pkgd config reset' to recreate it.",
                    config_path,
                    exc,
                )
                import click

                click.echo(
                    f"Error: Config file {config_path} is corrupt: {exc}. "
                    f"Using defaults. Fix the file or run 'pkgd config reset'.",
                    err=True,
                )
            else:
                config = _apply_toml_data(config, data, _source=str(config_path))

    config = _apply_env_overrides(config)
    return config


def _load_system_config(config: PKGDConfig, logger: Any) -> None:
    """Load system-level config from /etc/pkgd/pkgd.toml.

    Handles missing, unreadable, or corrupt system config gracefully by
    logging (where appropriate) and continuing with defaults.  Uses a
    single try/except around ``open()`` instead of TOCTOU-prone
    ``.exists()`` check + ``open()``.

    Args:
        config: Config instance to merge system settings into.
        logger: Logger instance for debug/warning messages.
    """
    try:
        with open(SYSTEM_CONFIG_PATH, "rb") as fh:
            data: dict[str, Any] = tomllib.load(fh)
        config = _apply_toml_data(config, data, _source=str(SYSTEM_CONFIG_PATH))
    except FileNotFoundError:
        return
    except PermissionError:
        logger.debug(
            "System config %s not readable (permission denied). Skipping.",
            SYSTEM_CONFIG_PATH,
        )
    except OSError:
        logger.debug(
            "System config %s not readable (OS error). Skipping.",
            SYSTEM_CONFIG_PATH,
        )
    except tomllib.TOMLDecodeError as exc:
        logger.warning(
            "System config %s is corrupt: %s. Skipping.",
            SYSTEM_CONFIG_PATH,
            exc,
        )


def _apply_toml_data(
    config: PKGDConfig,
    data: dict[str, Any],
    *,
    _source: str = "config",
) -> PKGDConfig:
    """Merge TOML-parsed dict into a PKGDConfig instance using dataclass introspection.

    Args:
        config: The config instance to modify (mutated in place).
        data: Parsed TOML dictionary.
        _source: Source identifier for weakening warning messages (e.g. file path).

    Returns:
        The modified config instance.
    """
    import dataclasses

    # Resolve annotation strings to actual types (from __future__ annotations
    # makes dataclasses.fields().type return strings, not type objects).
    _field_types = typing.get_type_hints(PKGDConfig)

    # Handle top-level PKGDConfig fields
    for f in dataclasses.fields(PKGDConfig):
        if f.name in data and f.name not in ("cooldown", "feeds", "output", "database", "bypass", "daemon"):
            value = data[f.name]
            # Type coercion for lists and dicts
            _resolved = _field_types[f.name]
            origin = get_origin(_resolved)
            if origin is list:
                value = list(value)
            elif origin is dict:
                value = dict(value)
            if not _validate_toml_value(_resolved, value):
                _logger.warning(
                    "Invalid %s value for %s.%s: %r. Using default.",
                    type(value).__name__,
                    "config",
                    f.name,
                    value,
                )
                continue
            setattr(config, f.name, value)
            warning = _check_toml_weakening((f.name,), value, _source)
            if warning:
                _logger.warning("%s", warning)

    for section_name, section_cls in section_mapping:
        if section_name not in data:
            continue

        section_data = data[section_name]
        section_obj = getattr(config, section_name)

        # Resolve annotation strings to actual types for this section class
        _section_field_types = typing.get_type_hints(section_cls)

        for f in dataclasses.fields(section_cls):
            if f.name not in section_data:
                continue

            value = section_data[f.name]

            # Type coercion for lists and dicts
            _resolved = _section_field_types[f.name]
            origin = get_origin(_resolved)
            if origin is list:
                value = list(value)
            elif origin is dict:
                value = dict(value)

            if not _validate_toml_value(_resolved, value):
                _logger.warning(
                    "Invalid %s value for %s.%s: %r. Using default.",
                    type(value).__name__,
                    section_name,
                    f.name,
                    value,
                )
                continue

            setattr(section_obj, f.name, value)
            warning = _check_toml_weakening((section_name, f.name), value, _source)
            if warning:
                _logger.warning("%s", warning)

    return config


def _validate_toml_value(field_type: type | types.UnionType, value: Any) -> bool:
    """Check whether a TOML-parsed value matches the expected field type.

    Returns ``True`` if the value is acceptable, ``False`` if it should
    be rejected (caller logs a warning and preserves the default).

    Handles:
    - Primitive types: ``int``, ``float``, ``bool``, ``str``
    - ``Path`` and ``Path | None`` (``types.UnionType`` in 3.10+)
    - ``typing.Optional[X]`` (``typing.Union[X, None]``)
    - ``list`` and ``dict`` origins (always accepted — caller coerces)
    - ``None`` values for Optional fields (accepted)
    """
    origin = get_origin(field_type)

    # list/dict are handled by the caller's coercion logic — always accept
    if origin is list or origin is dict:
        return True

    # Handle Union types: Path | None, typing.Optional[X], typing.Union[X, None]
    if origin is types.UnionType or origin is Union:
        inner_types = [t for t in get_args(field_type) if t is not type(None)]
        if not inner_types:
            return True
        if value is None:
            return True
        return any(isinstance(value, t) for t in inner_types)

    # Primitive types: int, float, bool, str
    # Special case: bool is a subclass of int in Python, but TOML
    # distinguishes them — a TOML `true` (bool) must not pass for an
    # int field.
    if field_type is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, field_type)


# ---------------------------------------------------------------------------
# Env var override mapping (declarative)
# ---------------------------------------------------------------------------

# ── Lifted from _apply_env_overrides (module-level helpers) ──

bool_true = {"1", "true", "yes", "on"}
bool_false = {"0", "false", "no", "off"}


def _parse_bool(value: str) -> bool:
    """Parse a string into a boolean value."""
    lower = value.strip().lower()
    if lower in bool_true:
        return True
    if lower in bool_false:
        return False
    raise ValueError(f"Cannot parse {value!r} as bool")


def _safe_int(value: str, key: str) -> int | None:
    """Parse an integer from an env var, with error handling.

    Args:
        value: The raw string value from the env var.
        key: The env var name (for diagnostic logging).

    Returns:
        The parsed integer, or None if parsing failed.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        _logger.warning(
            "Invalid integer value for %s: %r. Using default.",
            key,
            value,
        )
        return None


def _safe_bool(value: str, key: str) -> bool | None:
    """Parse a boolean from an env var, with error handling.

    Args:
        value: The raw string value from the env var.
        key: The env var name (for diagnostic logging).

    Returns:
        The parsed boolean, or None if parsing failed.
    """
    try:
        return _parse_bool(value)
    except ValueError:
        _logger.warning(
            "Invalid boolean value for %s: %r. Accepted values: %s. Using default.",
            key,
            value,
            ", ".join(sorted(bool_true | bool_false)),
        )
        return None


_secret_keys: set[str] = {
    "PKGD_FEEDS_GHSA_TOKEN",
    "PKGD_FEEDS_REDDIT_CLIENT_ID",
    "PKGD_FEEDS_REDDIT_CLIENT_SECRET",
    "PKGD_FEEDS_X_TWITTER_TOKEN",
    "PKGD_FEEDS_SOCKET_API_KEY",
    "PKGD_DB_SNAPSHOT_URL",
    "PKGD_GITHUB_TOKEN",
    "PKGD_LIBRARIES_IO_KEY",  # Used by TimestampResolver in registry/_timestamp.py
    "PKGD_TWITTER_API_KEY",
}


_weakening_env: dict[str, tuple[bool | int, str]] = {
    "PKGD_FAIL_ON_THREAT": (False, "config.fail_on_threat_enabled"),
    "PKGD_COOLDOWN_STRICT_MODE": (False, "config.cooldown.strict_mode"),
    "PKGD_BYPASS_COMMAND_ENABLED": (True, "config.bypass.command_enabled"),
    "PKGD_COOLDOWN_DEFAULT_DAYS": (7, "config.cooldown.default_days"),
    "PKGD_COOLDOWN_BYPASS_REQUIRE_REASON": (False, "config.cooldown.bypass_require_reason"),
    "PKGD_DATABASE_WAL_MODE": (False, "config.database.wal_mode"),
    "PKGD_FAIL_ON_WARN": (False, "config.fail_on_warn_enabled"),
    "PKGD_DAEMON_RUN_ON_BATTERY": (True, "config.daemon.run_on_battery"),
}

_weakening_toml: dict[tuple[str, ...], tuple[Any, ...]] = {
    # Top-level fields
    ("fail_on_threat_enabled",): (False,),
    ("fail_on_warn_enabled",): (False,),
    # Cooldown section
    ("cooldown", "enabled"): (False,),
    ("cooldown", "strict_mode"): (False,),
    ("cooldown", "bypass_require_reason"): (False,),
    ("cooldown", "default_days"): (0, 1, 2, 3, 4, 5, 6),  # values < 7 weaken (special check)
    # Bypass section
    ("bypass", "command_enabled"): (True,),
    # Database section
    ("database", "wal_mode"): (False,),
    # Daemon section
    ("daemon", "run_on_battery"): (True,),
    # Feeds section
    ("feeds", "osv_enabled"): (False,),
    ("feeds", "ghsa_enabled"): (False,),
    ("feeds", "rss_enabled"): (False,),
    ("feeds", "socket_enabled"): (False,),
    ("feeds", "npm_advisory_enabled"): (False,),
    ("feeds", "ossf_malicious_enabled"): (False,),
}


def _check_toml_weakening(
    key_path: tuple[str, ...],
    value: Any,
    source: str = "config",
) -> str | None:
    """Check if a TOML config value weakens security posture.

    Args:
        key_path: Attribute path tuple, e.g. (\"cooldown\", \"enabled\").
        value: The value being assigned (already type-coerced).
        source: Description of the config source (file path or label).

    Returns:
        A warning message string if weakened, None if safe.
    """
    weakening_values = _weakening_toml.get(key_path, ())
    if not weakening_values:
        return None

    # Skip warning if value equals the Python dataclass default —
    # prevents false-positive warnings for fields where the default
    # is inherently weakening (e.g. fail_on_warn_enabled=False).
    try:
        default_value = functools.reduce(getattr, key_path, PKGDConfig())
        if value == default_value:
            return None
    except AttributeError:
        # If the key path doesn't resolve, continue with the normal check.
        pass

    # Special case for cooldown.default_days — numeric range check
    if key_path == ("cooldown", "default_days"):
        if isinstance(value, int) and value < 7:
            return (
                f"Security posture weakened by {source}: "
                f"cooldown.default_days={value} (< 7). "
                f"Cooldown window is dangerously short."
            )
        return None

    if value in weakening_values:
        return (
            f"Security posture weakened by {source}: "
            f"{'.'.join(key_path)}={value!r}."
            f" Consider restoring this to a safe value."
        )
    return None


def _log_override(
    key: str,
    target: str,
    value: Any,
) -> None:
    """Log a successful env var override at INFO, WARNING if security-weakening."""
    display_value = "***" if key in _secret_keys else repr(value)
    _logger.info("Override: %s=%s \u2192 %s=%s", key, display_value, target, display_value)

    if key in _weakening_env:
        weaken_threshold, target_path = _weakening_env[key]
        is_weakened = False
        if key == "PKGD_COOLDOWN_DEFAULT_DAYS":
            is_weakened = isinstance(value, int) and value < weaken_threshold
        else:
            is_weakened = value == weaken_threshold
        if is_weakened:
            _logger.warning(
                "Security posture weakened: %s=%s \u2192 %s=%s",
                key,
                display_value,
                target_path,
                display_value,
            )


# ── Lifted from _apply_toml_data so both functions can reference it ──
section_mapping: list[tuple[str, Any]] = [
    ("cooldown", CooldownConfig),
    ("feeds", FeedConfig),
    ("output", OutputConfig),
    ("database", DatabaseConfig),
    ("bypass", BypassConfig),
    ("daemon", DaemonConfig),
]


def _coerce_env_value(raw: str, field_type: type, env_var: str) -> Any | None:
    """Coerce a raw env var string to the target field type.

    Args:
        raw: The raw string value from the environment variable.
        field_type: The Python type to coerce to (from dataclass field annotation).
        env_var: The env var name (for diagnostic logging).

    Returns:
        Coerced value, or None if coercion failed (warning already logged).
    """
    if field_type is bool:
        return _safe_bool(raw, env_var)
    if field_type is int:
        return _safe_int(raw, env_var)
    if field_type is float:
        try:
            return float(raw)
        except (ValueError, TypeError):
            _logger.warning(
                "Invalid float value for %s: %r. Using default.",
                env_var,
                raw,
            )
            return None
    if field_type is Path:
        return Path(raw)

    origin = get_origin(field_type)
    if origin is list:
        # list[str] — comma-split, strip, and uppercase (matching existing
        # behavior of PKGD_OUTPUT_INTEL_EXCLUDE_SEVERITY and
        # PKGD_OUTPUT_SEARCH_EXCLUDE_SEVERITY)
        args = get_args(field_type)
        elem_type = args[0] if args else str
        if elem_type is str:
            return [s.strip().upper() for s in raw.split(",") if s.strip()]
        return [s.strip() for s in raw.split(",") if s.strip()]

    if origin is dict or (isinstance(field_type, type) and issubclass(field_type, dict)):
        # dict types — accept JSON-encoded env var values
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            _logger.warning(
                "Invalid dict value for %s: JSON parsed but not a dict. Using default.",
                env_var,
            )
            return None
        except (json.JSONDecodeError, ValueError):
            _logger.warning(
                "Invalid dict value for %s: not valid JSON (%r). Using default.",
                env_var,
                raw,
            )
            return None

    # str or any other type — strip and assign
    # (`.strip()` preserves backward compat with PKGD_DB_SNAPSHOT_URL behavior)
    return raw.strip()


# ── Special handler functions ──


def _handle_data_dir_alias(env: Mapping[str, str]) -> None:
    """PKGD_DATA_DIR \u2192 PKGD_DATABASE_PATH alias (must run first)."""
    if "PKGD_DATA_DIR" in env and "PKGD_DATABASE_PATH" not in env:
        os.environ["PKGD_DATABASE_PATH"] = env["PKGD_DATA_DIR"]
        _logger.info("Alias: PKGD_DATA_DIR=%s \u2192 PKGD_DATABASE_PATH (set)", env["PKGD_DATA_DIR"])


def _handle_config_file_alias(env: Mapping[str, str]) -> None:
    """PKGD_CONFIG_FILE \u2192 PKGD_CONFIG_PATH alias."""
    if "PKGD_CONFIG_FILE" in env and "PKGD_CONFIG_PATH" not in env:
        os.environ["PKGD_CONFIG_PATH"] = env["PKGD_CONFIG_FILE"]
        _logger.info("Alias: PKGD_CONFIG_FILE=%s \u2192 PKGD_CONFIG_PATH (set)", env["PKGD_CONFIG_FILE"])


def _handle_github_token_alias(config: PKGDConfig, value: str, env_var: str) -> None:
    """PKGD_GITHUB_TOKEN → config.feeds.ghsa_token (legacy alias).

    The PKGD_GITHUB_TOKEN env var is dual-use:
    1. Mapped to config.feeds.ghsa_token (GHSA feed, OSSF malicious feed)
    2. Read directly by TimestampResolver in registry/_timestamp.py
       (which also falls back to config.feeds.ghsa_token if env var is unset)
    """
    if "PKGD_FEEDS_GHSA_TOKEN" not in os.environ:
        config.feeds.ghsa_token = value
        _log_override(env_var, "config.feeds.ghsa_token", value)


def _handle_twitter_api_key_alias(config: PKGDConfig, value: str, env_var: str) -> None:
    """PKGD_TWITTER_API_KEY \u2192 config.feeds.socket_api_key (legacy alias)."""
    if "PKGD_FEEDS_SOCKET_API_KEY" not in os.environ:
        config.feeds.socket_api_key = value
        _log_override(env_var, "config.feeds.socket_api_key", value)


def _handle_extra_feed_url(config: PKGDConfig, value: str, env_var: str) -> None:
    """PKGD_EXTRA_FEED_URL \u2192 append to config.feeds.rss_urls."""
    extra_url = value.strip()
    if extra_url and extra_url not in config.feeds.rss_urls:
        config.feeds.rss_urls = list(config.feeds.rss_urls) + [extra_url]
        _logger.info("Override: PKGD_EXTRA_FEED_URL=%s appended to config.feeds.rss_urls", extra_url)


def _handle_database_path(config: PKGDConfig, value: str, env_var: str) -> None:
    """PKGD_DATABASE_PATH \u2192 config.database.path (Path)."""
    config.database.path = Path(value)
    _logger.info("Override: PKGD_DATABASE_PATH=%s \u2192 config.database.path=%s", value, config.database.path)


# Env vars whose names don't match PKGD_<SECTION>_<FIELD> convention
_ENV_EXPLICIT_OVERRIDES: list[tuple[str, str | None, str]] = [
    # (env_var, section_or_None, field)
    # FeedConfig — name mismatches
    ("PKGD_FEEDS_X_TWITTER_TOKEN", "feeds", "x_twitter_bearer_token"),
    ("PKGD_FEEDS_STALENESS_HOURS", "feeds", "staleness_threshold_hours"),
    ("PKGD_HTTP_TIMEOUT", "feeds", "http_timeout"),
    # OutputConfig — name/prefix mismatches
    ("PKGD_OUTPUT_JSON", "output", "json_mode"),
    ("PKGD_SHOW_ASCII_BANNER", "output", "show_ascii_banner"),
    # DatabaseConfig — name/prefix mismatches
    ("PKGD_DATABASE_BUSY_TIMEOUT", "database", "busy_timeout_ms"),
    ("PKGD_DB_SNAPSHOT_URL", "database", "snapshot_url"),
    # Root-level (no section)
    ("PKGD_COMMAND_TIMEOUT", None, "command_timeout_seconds"),
    ("PKGD_REGISTRY_API_TIMEOUT", None, "registry_api_timeout"),
    ("PKGD_FAIL_ON_THREAT", None, "fail_on_threat_enabled"),
    ("PKGD_FAIL_ON_WARN", None, "fail_on_warn_enabled"),
    ("PKGD_GLOBAL_ENABLE_HOMEBREW_FORMULA_COMMIT", None, "enable_homebrew_formula_commit"),
    ("PKGD_PER_ECOSYSTEM_REGISTRY_TIMEOUT", None, "per_ecosystem_registry_timeout"),
]

# Ordered list of special-handler env vars (each entry has env_var, handler_callable)
_ENV_ALIAS_PREPROCESSORS: list[tuple[str, Callable[[Mapping[str, str]], None]]] = [
    # These set env vars, must run before all other processing
    ("PKGD_DATA_DIR", _handle_data_dir_alias),
    ("PKGD_CONFIG_FILE", _handle_config_file_alias),
]

_ENV_SPECIAL_HANDLERS: list[tuple[str, Callable[[PKGDConfig, str, str], None]]] = [
    # These set config values with non-trivial logic
    ("PKGD_GITHUB_TOKEN", _handle_github_token_alias),
    ("PKGD_TWITTER_API_KEY", _handle_twitter_api_key_alias),
    ("PKGD_DATABASE_PATH", _handle_database_path),
    ("PKGD_EXTRA_FEED_URL", _handle_extra_feed_url),
]

# Env vars that must be skipped by the auto-derivation loop to prevent
# double-processing (e.g. PKGD_DATABASE_PATH processed by both Phase 2 and Phase 4).
# Computed at module load from the explicit and special-handler lists above.
_SKIP_AUTO_ENV_NAMES: set[str] = {entry[0] for entry in _ENV_EXPLICIT_OVERRIDES} | {
    entry[0] for entry in _ENV_SPECIAL_HANDLERS
}


def _apply_env_overrides(config: PKGDConfig) -> PKGDConfig:
    """Apply ``PKGD_*`` environment variable overrides to config.

    Uses a declarative mapping derived from dataclass fields. For standard
    options, the env var name follows ``PKGD_<SECTION>_<FIELD>`` convention.
    Non-standard names and special cases are handled via explicit override
    lists (``_ENV_EXPLICIT_OVERRIDES``, ``_ENV_SPECIAL_HANDLERS``).

    Processing order:
      1. Alias preprocessors (e.g., PKGD_DATA_DIR \u2192 PKGD_DATABASE_PATH)
      2. Standard section-field overrides (auto-derived from dataclass fields)
      3. Explicit overrides (non-standard env var names)
      4. Special handlers (append, legacy aliases, path — including PKGD_DATABASE_PATH)

    Args:
        config: The config instance to override.

    Returns:
        The config instance with env var overrides applied.
    """
    import dataclasses
    import typing

    env = os.environ

    # ---- Phase 1: Alias preprocessors (env var \u2192 env var) ----
    for _aev, _pre in _ENV_ALIAS_PREPROCESSORS:
        _pre(env)

    # ---- Phase 2: Standard section-field overrides (auto-derived) ----
    for _section_name, _section_cls in section_mapping:
        _section_obj = getattr(config, _section_name)
        _field_types = typing.get_type_hints(_section_cls)
        for _f in dataclasses.fields(_section_cls):
            _env_name = f"PKGD_{_section_name.upper()}_{_f.name.upper()}"
            # Skip env vars already claimed by explicit overrides or special handlers
            # (prevents double-processing — e.g. PKGD_DATABASE_PATH would be processed
            #  by both Phase 2 and Phase 4, with Phase 2 setting wrong type via fallthrough)
            if _env_name in _SKIP_AUTO_ENV_NAMES:
                continue
            _raw = env.get(_env_name)
            if _raw is None:
                continue
            _value = _coerce_env_value(_raw, _field_types[_f.name], _env_name)
            if _value is not None:
                setattr(_section_obj, _f.name, _value)
                _log_override(_env_name, f"{_section_name}.{_f.name}", _value)

    # ---- Phase 3: Explicit overrides (non-standard env var names) ----
    for _env_var, _section, _field in _ENV_EXPLICIT_OVERRIDES:
        _raw = env.get(_env_var)
        if _raw is None:
            continue

        if _section is None:
            # Root-level field (on PKGDConfig itself)
            _target = config
            _target_path = _field
            _field_type = typing.get_type_hints(PKGDConfig)[_field]
        else:
            _target = getattr(config, _section)
            _target_path = f"{_section}.{_field}"
            _section_cls = dict(section_mapping)[_section]
            _field_type = typing.get_type_hints(_section_cls)[_field]

        _value = _coerce_env_value(_raw, _field_type, _env_var)
        if _value is not None:
            setattr(_target, _field, _value)
            _log_override(_env_var, _target_path, _value)

    # ---- Phase 4: Special handlers (aliases, append, path) ----
    for _sev, _s_handler in _ENV_SPECIAL_HANDLERS:
        _raw = env.get(_sev)
        if _raw is not None:
            _s_handler(config, _raw, _sev)

    return config


def get_http_timeout(config: PKGDConfig | None = None, *, override_default: int | None = None) -> int:
    """Get HTTP timeout value from config or default.

    Args:
        config: Optional config instance. If None, loads default config.
        override_default: Override the fallback default (15s) for adapters
            that require a different default (e.g. brew uses 30s). Keyword-only.

    Returns:
        HTTP timeout in seconds (default: 15, or override_default).
    """
    default = override_default if override_default is not None else 15
    if config is None:
        config = load_config()
    return getattr(config.feeds, "http_timeout", default)


INTEL_FEED_MAX_RETRIES: int = 3
"""Maximum retry attempts for intel feed and registry adapter HTTP requests."""


def get_max_retries(config: PKGDConfig | None = None) -> int:
    """Get max retries value from config or default.

    Args:
        config: Optional config instance. If None, loads default config.

    Returns:
        Max retries count (default: 3).
    """
    if config is None:
        config = load_config()
    return getattr(config.feeds, "max_retries", INTEL_FEED_MAX_RETRIES)
