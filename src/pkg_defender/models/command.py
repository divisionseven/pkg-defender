"""Data models for command parsing and package management.

This module contains the core data structures used by the pkgd command wrapper
to represent parsed commands, package references, and installation intents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, StrEnum, auto


class CommandIntent(Enum):
    """Intent classification for package manager commands.

    Represents the type of operation being performed by a package manager command.
    Determines the level of interception and security checks applied by pkgd.
    """

    INSTALL = auto()  # Add new packages
    UPDATE = auto()  # Update existing packages
    SYNC = auto()  # Install from lockfile/manifest
    REMOVE = auto()  # Uninstall
    EXECUTE = auto()  # Download and execute a package (npx, dlx, bunx)
    SAFE_PASSTHROUGH = auto()  # list, show, search — no interception
    UNKNOWN = auto()  # Couldn't classify


DANGEROUS_INTENTS: frozenset[CommandIntent] = frozenset(
    {
        CommandIntent.INSTALL,
        CommandIntent.UPDATE,
        CommandIntent.SYNC,
        CommandIntent.REMOVE,
        CommandIntent.EXECUTE,
    }
)


class Action(StrEnum):
    """Package manager action being performed.

    String-valued enum for serialization.
    """

    INSTALL = "install"
    UPDATE = "update"
    UPGRADE = "upgrade"
    REINSTALL = "reinstall"
    EXECUTE = "execute"
    FETCH = "fetch"


class RiskLevel(StrEnum):
    """Risk level for a package operation.

    String-valued enum for serialization.
    """

    CRITICAL = "critical"
    IMPORTANT = "important"
    WATCH = "watch"


def action_to_intent(action: Action) -> CommandIntent:
    """Convert an Action enum value to the corresponding CommandIntent.

    This mapping bridges the parser's Action classification with the
    pipeline's CommandIntent system.

    Args:
        action: The Action enum value from parsing.

    Returns:
        The corresponding CommandIntent enum value.
    """
    _mapping: dict[Action, CommandIntent] = {
        Action.INSTALL: CommandIntent.INSTALL,
        Action.UPDATE: CommandIntent.UPDATE,
        Action.UPGRADE: CommandIntent.UPDATE,
        Action.REINSTALL: CommandIntent.INSTALL,
        Action.EXECUTE: CommandIntent.EXECUTE,
        Action.FETCH: CommandIntent.SYNC,
    }
    return _mapping.get(action, CommandIntent.UNKNOWN)


class InstallSource(Enum):
    """Source type for package installation.

    Indicates where a package is being installed from, which determines
    what security checks pkgd can perform.
    """

    REGISTRY = auto()  # Standard registry (PyPI, npm, etc.)
    FILE = auto()  # -r requirements.txt, package.json, etc.
    LOCAL_PATH = auto()  # pip install ./mypackage
    VCS = auto()  # pip install git+https://...
    URL = auto()  # pip install https://example.com/pkg.tar.gz
    UNKNOWN = auto()


class BlockReason(Enum):
    """Reason why pkgd blocked an installation.

    Indicates the specific reason for blocking a package installation,
    used for error reporting and logging.
    """

    THREAT = auto()  # Known malicious package
    COOLDOWN = auto()  # Package published too recently
    VCS_SOURCE = auto()  # Installing from VCS source
    LOCAL_PATH = auto()  # Installing from local path


@dataclass
class PackageRef:
    """Reference to a package with parsed metadata.

    Represents a single package specification as extracted from a command line.
    Contains both the raw input and parsed components.

    Attributes:
        name: The package name (e.g., 'requests', '@types/node').
        version: The exact version if specified (e.g., '2.31.0'), None if latest.
        version_constraint: Full constraint string (e.g., '>=2.0,<3.0').
        extras: List of extras (e.g., ['security', 'socks'] for requests[security,socks]).
        source: The installation source type.
        raw: The original input string exactly as typed by the user.
    """

    name: str
    version: str | None = None
    version_constraint: str | None = None
    extras: list[str] = field(default_factory=list)
    ecosystem: str = ""
    source: InstallSource = InstallSource.REGISTRY
    raw: str = ""
    is_latest: bool = False

    @property
    def is_pinned(self) -> bool:
        """True if an exact version was specified (not a range).

        Returns:
            True if version is set and no constraint range was provided.
        """
        return self.version is not None and self.version_constraint is None


@dataclass
class ParsedCommand:
    """Parsed package manager command with extracted metadata.

    Represents a fully parsed command from a package manager, including
    the intent, packages, flags, and other metadata needed for security
    checks and command reconstruction.

    Attributes:
        manager: The package manager name (e.g., 'pip', 'npm', 'brew').
        intent: The classified command intent.
        packages: List of package references being installed/updated.
        manager_subcommand: The subcommand (e.g., 'install', 'add', 'update').
        manager_flags: Flags to pass through to the underlying manager.
        pkgd_flags: Extracted pkgd-specific flags.
        file_targets: Files to audit (e.g., -r requirements.txt).
        git_url: Optional git URL for the package source.
        source: Where the command originated (e.g., 'cli', 'file').
        ecosystem: Package ecosystem (e.g., 'pypi', 'npm', 'crates').
        risk: Risk level as a string ("critical", "important", "watch").
        raw_args: Original args verbatim for exec reconstruction.
        requires_file_audit: True if installing from a file (needs file parsing).
        is_global: True if installing globally (npm install -g, brew install).
        is_dev_dependency: True if installing as dev dependency.
    """

    manager: str = ""
    intent: CommandIntent = CommandIntent.SAFE_PASSTHROUGH
    packages: list[PackageRef] = field(default_factory=list)
    manager_subcommand: str = ""
    manager_flags: list[str] = field(default_factory=list)
    pkgd_flags: dict[str, str | bool] = field(default_factory=dict)
    file_targets: list[str] = field(default_factory=list)
    git_url: str | None = None
    source: str = ""
    ecosystem: str = ""
    risk: str = ""  # ("critical", "important", "watch")
    raw_args: list[str] = field(default_factory=list)
    requires_file_audit: bool = False
    is_global: bool = False
    is_dev_dependency: bool = False
