"""Base class for package registry adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Protocol, runtime_checkable

import aiohttp

from pkg_defender.models import VersionInfo
from pkg_defender.models.command import CommandIntent, ParsedCommand


@runtime_checkable
class ManagerAdapter(Protocol):
    """Protocol for adapters that can parse CLI commands and build exec args.

    This is the interface that manager-side adapters must implement.
    Used by UNIFIED_MANAGER_REGISTRY to provide type-safe lookups
    without depending on managers.BaseAdapter.

    Satisfied by both:
    - UnifiedRegistryAdapter subclasses (registry-side unified adapters)
    - BaseAdapter subclasses (legacy manager-side adapters)
    """

    ecosystem: str
    manager_name: str
    coverage_tier: CoverageTier

    def parse(self, manager_args: list[str]) -> ParsedCommand: ...
    def build_exec_args(self, parsed: ParsedCommand) -> list[str]: ...


@runtime_checkable
class PipelineAdapterProtocol(Protocol):
    """Protocol for adapters that support pipeline operations.

    Provides ``resolve_latest_version``, ``get_release_date``, and
    ``get_publish_time`` bridge methods required by the audit pipeline
    (dispatcher). Satisfied by:
    - ``UnifiedRegistryAdapter`` subclasses (via bridge methods at class level)
    - ``PipelineAdapter`` (via delegation to wrapped adapter)

    Marked ``@runtime_checkable`` so consumers can use ``isinstance()``
    to check capability at runtime.
    """

    async def resolve_latest_version(self, package: str) -> str | None: ...
    async def get_release_date(self, package: str, version: str, is_latest: bool = False) -> datetime | None: ...
    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]: ...


class EcosystemCapability(Enum):
    """Capabilities that describe what an ecosystem's registry supports."""

    VERIFIED_PUBLISH_TIMESTAMPS = "verified_timestamps"
    PROXIED_PUBLISH_TIMESTAMPS = "proxied_timestamps"
    NO_PUBLISH_TIMESTAMPS = "no_timestamps"
    THREAT_INTEL_SUPPORT = "threat_intel"


class CoverageTier(Enum):
    """Coverage tier for a package manager's security checks.

    Determines which security checks run when a package is installed:
    - FULL:     Both threat DB check and cooldown check run.
    - PARTIAL:  Both threat check and cooldown check run (same as FULL).
    - AUDIT:    Threat check runs; cooldown check skipped (no publish timestamps available).
    """

    FULL = "full"
    PARTIAL = "partial"
    AUDIT = "audit"

    def __str__(self) -> str:
        """Return the string value (e.g. 'full', 'partial', 'audit')."""
        return self.value


@dataclass(frozen=True)
class ManagerConfig:
    """Configuration for a registry adapter.

    Provides ecosystem identity, API base URL, and capability metadata
    via a single frozen dataclass instead of three separate properties.
    Subclasses set ``config = ManagerConfig(...)`` at the class level.
    """

    ecosystem: str
    registry_url: str
    capabilities: list[EcosystemCapability]


class HTTPMixin:
    """Shared HTTP session handling for registry adapters."""

    @staticmethod
    async def _fetch_json(
        url: str,
        session: aiohttp.ClientSession | None = None,
        timeout: int = 15,
        max_retries: int = 3,
        manager: str | None = None,
    ) -> dict[str, Any]:
        """Fetch JSON from URL with timeout and retry.

        Delegates to ``pkg_defender._http.fetch_json`` — the shared
        HTTP utility with exponential backoff, jitter, and config-driven
        defaults.

        Args:
            url: The URL to fetch.
            session: Optional existing aiohttp session.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of             retry attempts.
            manager: Optional package manager name for SSRF domain
                allowlist check. Passed through to ``_http.fetch_json``.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            aiohttp.ClientResponseError: On non-retryable HTTP errors.
            aiohttp.ClientError: On transport-level failure after retries.
            asyncio.TimeoutError: When the request times out after retries.
            SecurityError: When the URL domain is not in the manager's allowlist.
        """
        from pkg_defender._http import fetch_json as _fetch_json_impl

        result = await _fetch_json_impl(
            url,
            timeout=timeout,
            max_retries=max_retries,
            session=session,
            on_404="raise",
            manager=manager,
        )
        if not result.success or result.data is None:
            raise RuntimeError(f"Failed to fetch {url}: {result.error}")
        # result.data is dict[str, Any] | list[Any] at the type level,
        # but _fetch_json's contract is dict[str, Any]
        return dict(result.data)


class RegistryAdapter(ABC, HTTPMixin):
    """Abstract base for all package registry adapters.

    Uses mixins for shared HTTP handling and version comparison.
    Each concrete subclass must define ``config = ManagerConfig(...)``.
    """

    config: ClassVar[ManagerConfig]
    ecosystem: str

    def __init__(self) -> None:
        """Initialize the adapter."""

    registry_base_url: str

    @property
    def capabilities(self) -> list[EcosystemCapability]:
        """Return the capabilities supported by this ecosystem."""
        return list(self.config.capabilities)

    @abstractmethod
    async def get_publish_time(
        self,
        package: str,
        version: str,
        session: aiohttp.ClientSession | None = None,
        is_latest: bool = False,
    ) -> tuple[datetime | None, str]:
        """Get the publish time for a specific version.

        Args:
            package: Package name.
            version: Version string.
            session: Shared aiohttp session (created if None).

        Returns:
            Tuple of (publish_time, source) where source is a string
            indicating where the publish time was obtained from
            (e.g., "registry", "github_releases", "unresolved").
        """

    @abstractmethod
    async def get_all_versions(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> list[VersionInfo]:
        """Get all published versions with their publish times.

        Args:
            package: Package name.
            session: Shared aiohttp session (created if None).

        Returns:
            List of VersionInfo objects sorted by publish_time descending.
        """

    @abstractmethod
    async def get_latest_version(
        self,
        package: str,
        session: aiohttp.ClientSession | None = None,
    ) -> str | None:
        """Get the latest stable version string.

        Args:
            package: Package name.
            session: Shared aiohttp session (created if None).

        Returns:
            Latest version string, or None if package not found.
        """

    @abstractmethod
    async def get_installed_version(self, package: str) -> str | None:
        """Get the currently installed version of a package.

        Args:
            package: Package name.

        Returns:
            Installed version string, or None if package is not installed.
        """


class UnifiedRegistryAdapter(RegistryAdapter):
    """Unified adapter combining registry lookups + command parsing + exec reconstruction.

    Combines the functionality of:
    - adapters/BaseAdapter (resolve_latest_version, get_release_date)
    - registry/RegistryAdapter (get_publish_time, get_all_versions, etc.)
    - managers/BaseAdapter (parse, build_exec_args, classify_intent, etc.)

    Concrete subclasses must implement:
    - All RegistryAdapter abstract methods
    - parse() — extract packages/versions from raw args
    - build_exec_args() — reconstruct command for exec
    """

    config: ClassVar[ManagerConfig]

    # Manager identity (may differ from ecosystem, e.g. manager="pip" vs ecosystem="pypi")
    manager_name: str = ""

    # Security coverage tier — determines which checks run for this adapter
    coverage_tier: CoverageTier = CoverageTier.AUDIT

    COMMAND_INTENT_MAP: dict[str, CommandIntent] = {}

    VALUE_FLAGS: frozenset[str] = frozenset()

    PKGD_FLAGS: frozenset[str] = frozenset(
        {
            "--dry-run",
            "--cooldown",
            "--force",
            "--json",
            "--verbose",
            "-v",
            "--ci",
            "--non-interactive",
            "--explain",
            "--allow-once",
            "--bypass-cooldown",
            "--bypass-threat",
        }
    )

    @abstractmethod
    def parse(self, manager_args: list[str]) -> ParsedCommand:
        """Parse raw manager args into structured ParsedCommand."""
        ...

    @abstractmethod
    def build_exec_args(self, parsed: ParsedCommand) -> list[str]:
        """Reconstruct command args for exec after pkgd clears."""
        ...

    # --- Concrete methods from managers/BaseAdapter ---

    def classify_intent(self, subcommand: str) -> CommandIntent:
        """Classify subcommand as dangerous or safe."""
        return self.COMMAND_INTENT_MAP.get(subcommand, CommandIntent.SAFE_PASSTHROUGH)

    def split_pkgd_flags(
        self,
        args: list[str],
    ) -> tuple[list[str], dict[str, str | bool]]:
        """Separate pkgd-specific flags from manager args.

        Returns:
            Tuple of (clean_args, pkgd_flags_dict).
        """
        clean_args: list[str] = []
        pkgd_flags: dict[str, str | bool] = {}
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in self.PKGD_FLAGS:
                if arg == "--cooldown" and i + 1 < len(args):
                    pkgd_flags["cooldown"] = args[i + 1]
                    i += 2
                elif arg in ("--verbose", "-v"):
                    pkgd_flags["verbose"] = True
                    i += 1
                else:
                    key = arg.lstrip("-").replace("-", "_")
                    pkgd_flags[key] = True
                    i += 1
            elif "=" in arg:
                flag_name, value = arg.split("=", 1)
                if flag_name in self.PKGD_FLAGS:
                    flag_key = flag_name.lstrip("-").replace("-", "_")
                    pkgd_flags[flag_key] = value
                    i += 1
                    continue
                clean_args.append(arg)
                i += 1
            else:
                clean_args.append(arg)
                i += 1
        return clean_args, pkgd_flags

    def tokenize_args(self, args: list[str]) -> list[str | tuple[str, str]]:
        """Walk args and group value-consuming flags with their values."""
        result: list[str | tuple[str, str]] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in self.VALUE_FLAGS:
                if i + 1 < len(args):
                    result.append((arg, args[i + 1]))
                    i += 2
                else:
                    result.append(arg)
                    i += 1
            elif "=" in arg and arg.split("=")[0] in self.VALUE_FLAGS:
                flag, value = arg.split("=", 1)
                result.append((flag, value))
                i += 1
            else:
                result.append(arg)
                i += 1
        return result

    def extract_packages_and_flags(
        self,
        tokens: list[str | tuple[str, str]],
    ) -> tuple[list[str], list[str]]:
        """Separate package strings from manager flags."""
        package_strings: list[str] = []
        manager_flags: list[str] = []
        for token in tokens:
            if isinstance(token, tuple):
                flag, value = token
                manager_flags.extend([flag, value])
            elif isinstance(token, str):
                if token.startswith("-"):
                    manager_flags.append(token)
                else:
                    package_strings.append(token)
        return package_strings, manager_flags

    def _safe_passthrough(
        self,
        raw_args: list[str],
        pkgd_flags: dict[str, str | bool],
        subcommand: str = "",
        remaining: list[str] | None = None,
    ) -> ParsedCommand:
        """Return a safe passthrough ParsedCommand for non-dangerous commands."""
        return ParsedCommand(
            manager=self.manager_name,
            intent=CommandIntent.SAFE_PASSTHROUGH,
            packages=[],
            manager_subcommand=subcommand,
            manager_flags=list(remaining) if remaining else [],
            pkgd_flags=pkgd_flags,
            file_targets=[],
            raw_args=raw_args,
            ecosystem=self.ecosystem,
        )

    # --- Bridge methods: adapters/ API → registry/ implementation ---

    async def resolve_latest_version(self, package: str) -> str | None:
        """Bridge: resolve_latest_version delegates to get_latest_version.

        Converts errors from registry layer to pipeline-expected types:
        - Python TimeoutError → PipelineTimeoutError
        - aiohttp.ClientError → NetworkError
        """
        try:
            return await self.get_latest_version(package)
        except TimeoutError as e:
            from pkg_defender.audit.errors import (
                TimeoutError as PipelineTimeoutError,
            )

            raise PipelineTimeoutError(
                registry=self.ecosystem,
                package=package,
                timeout_seconds=15,
                reason=e,
            ) from e
        except aiohttp.ClientError as e:
            from pkg_defender.audit.errors import NetworkError

            raise NetworkError(
                registry=self.ecosystem,
                package=package,
                reason=e,
            ) from e

    async def get_release_date(self, package: str, version: str, is_latest: bool = False) -> datetime | None:
        """Bridge: get_release_date delegates to get_publish_time.

        Returns just the datetime (not the source).
        Converts errors from registry layer to pipeline-expected types.
        """
        try:
            dt, _source = await self.get_publish_time(package, version, is_latest=is_latest)
            return dt
        except TimeoutError as e:
            from pkg_defender.audit.errors import (
                TimeoutError as PipelineTimeoutError,
            )

            raise PipelineTimeoutError(
                registry=self.ecosystem,
                package=package,
                timeout_seconds=15,
                reason=e,
            ) from e
        except aiohttp.ClientError as e:
            from pkg_defender.audit.errors import NetworkError

            raise NetworkError(
                registry=self.ecosystem,
                package=package,
                reason=e,
            ) from e

    async def fetch_release_date(
        self,
        package: str,
        version: str,
        session: Any = None,
        is_latest: bool = False,
    ) -> datetime | None:
        """Bridge: fetch_release_date delegates to get_publish_time.

        Converts errors from registry layer to pipeline-expected types.
        """
        try:
            dt, _source = await self.get_publish_time(package, version, session, is_latest=is_latest)
            return dt
        except TimeoutError as e:
            from pkg_defender.audit.errors import (
                TimeoutError as PipelineTimeoutError,
            )

            raise PipelineTimeoutError(
                registry=self.ecosystem,
                package=package,
                timeout_seconds=15,
                reason=e,
            ) from e
        except aiohttp.ClientError as e:
            from pkg_defender.audit.errors import NetworkError

            raise NetworkError(
                registry=self.ecosystem,
                package=package,
                reason=e,
            ) from e


class PipelineAdapter:
    """Wraps a RegistryAdapter to provide the pipeline-compatible API.

    The audit pipeline expects ``resolve_latest_version(package)`` and
    ``get_release_date(package, version)`` — these are bridge methods
    that exist on UnifiedRegistryAdapter but not on plain RegistryAdapter.
    This wrapper provides them for any RegistryAdapter instance.

    **Delegation strategy:**
    - If the wrapped adapter is a ``UnifiedRegistryAdapter``, delegates
      directly to its bridge methods (``resolve_latest_version``,
      ``get_release_date``). This preserves the error conversion logic
      (aiohttp.ClientError → NetworkError, Python TimeoutError →
      PipelineTimeoutError) and automatically inherits any future
      bridge method improvements.
    - If the wrapped adapter is a plain ``RegistryAdapter``, implements
      its own error conversion by calling the low-level methods
      (``get_latest_version``, ``get_publish_time``).

    **Ecosystem identity:**
    The ``ecosystem`` property returns the *requested* ecosystem key
    (e.g. ``"npm"``), NOT the wrapped adapter's ecosystem (which might
    be ``"bun"``). This prevents semantic confusion in consumers that
    check ``adapter.ecosystem`` to determine which ecosystem they're
    working with. The original adapter ecosystem is available via
    ``adapter_ecosystem`` if needed.

    PipelineAdapter wraps any RegistryAdapter to provide the
    resolve_latest_version/get_release_date bridge methods. It normalizes
    ecosystem key identity (adapter.ecosystem returns the requested key)
    and delegates to bridge methods on UnifiedRegistryAdapter subclasses
    when available.
    """

    def __init__(
        self,
        adapter: RegistryAdapter,
        requested_ecosystem: str,
    ) -> None:
        self._adapter = adapter
        self._requested_ecosystem = requested_ecosystem

    @property
    def ecosystem(self) -> str:
        """The ecosystem key that was originally requested.

        Returns the key passed to ``get_pipeline_adapter()`` (e.g. ``"npm"``),
        NOT the wrapped adapter's ecosystem (which might be ``"bun"``).
        This preserves semantic clarity — if a caller requests an adapter
        for ``"npm"``, ``adapter.ecosystem`` should return ``"npm"``.
        """
        return self._requested_ecosystem

    @property
    def adapter_ecosystem(self) -> str:
        """The wrapped adapter's own ecosystem identifier.

        May differ from ``requested_ecosystem`` (e.g. ``"bun"`` when
        ``"npm"`` was requested, because UNIFIED_MANAGER_REGISTRY["npm"] = BunAdapter).
        Available for debugging or when the actual registry ecosystem
        identifier is needed.
        """
        return self._adapter.ecosystem

    async def resolve_latest_version(self, package: str) -> str | None:
        """Bridge: resolve_latest_version for the pipeline.

        Delegates to the UnifiedRegistryAdapter bridge method when
        available (preserving its error conversion), otherwise calls
        get_latest_version with manual error conversion.
        """
        if isinstance(self._adapter, UnifiedRegistryAdapter):
            return await self._adapter.resolve_latest_version(package)

        try:
            return await self._adapter.get_latest_version(package)
        except TimeoutError as e:
            from pkg_defender.audit.errors import (
                TimeoutError as PipelineTimeoutError,
            )

            raise PipelineTimeoutError(
                registry=self._adapter.ecosystem,
                package=package,
                timeout_seconds=15,
                reason=e,
            ) from e
        except aiohttp.ClientError as e:
            from pkg_defender.audit.errors import NetworkError

            raise NetworkError(
                registry=self._adapter.ecosystem,
                package=package,
                reason=e,
            ) from e

    async def get_release_date(self, package: str, version: str, is_latest: bool = False) -> datetime | None:
        """Bridge: get_release_date for the pipeline.

        Delegates to the UnifiedRegistryAdapter bridge method when
        available (preserving its error conversion), otherwise calls
        get_publish_time with manual error conversion.
        """
        if isinstance(self._adapter, UnifiedRegistryAdapter):
            return await self._adapter.get_release_date(package, version, is_latest=is_latest)

        try:
            dt, _source = await self._adapter.get_publish_time(package, version, is_latest=is_latest)
            return dt
        except TimeoutError as e:
            from pkg_defender.audit.errors import (
                TimeoutError as PipelineTimeoutError,
            )

            raise PipelineTimeoutError(
                registry=self._adapter.ecosystem,
                package=package,
                timeout_seconds=15,
                reason=e,
            ) from e
        except aiohttp.ClientError as e:
            from pkg_defender.audit.errors import NetworkError

            raise NetworkError(
                registry=self._adapter.ecosystem,
                package=package,
                reason=e,
            ) from e
