"""Manager dispatcher that routes commands to the appropriate package manager adapter."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from pkg_defender.cli._exit_codes import (
    EXIT_COOLDOWN,
    EXIT_GENERAL_ERROR,
    EXIT_THREAT_DETECTED,
)
from pkg_defender.cli._progress import feed_sync_progress, handle_feed_complete
from pkg_defender.db.schema import (
    get_connection,
    insert_resolution_attempt,
    insert_version_timestamp,
    query_threats_by_source,
)
from pkg_defender.models.command import BlockReason, CommandIntent, PackageRef, ParsedCommand
from pkg_defender.registry.base import CoverageTier, PipelineAdapterProtocol, UnifiedRegistryAdapter
from pkg_defender.registry.brew import brew_get_installed_version

if TYPE_CHECKING:
    from pkg_defender.audit.bypass_service import BypassService
    from pkg_defender.audit.cooldown import ThreatCooldownContext
    from pkg_defender.config.settings import PKGDConfig
    from pkg_defender.registry.base import ManagerAdapter

_INTENT_TO_ACTION: dict[CommandIntent, str] = {
    CommandIntent.INSTALL: "install",
    CommandIntent.UPDATE: "update",
    CommandIntent.SYNC: "fetch",
    CommandIntent.EXECUTE: "execute",
}


def _derive_failure_status(source_label: str, session_errors: set[str]) -> str:
    """Derive ``resolution_status`` from adapter's ``source_label`` and session errors.

    The adapter's ``source_label`` on failure is the raw failure reason string
    from ``_fetch_json`` (e.g., ``"rate_limited"``, ``"not_found"``). Session
    errors provide cross-tier context captured by the resolver.

    Args:
        source_label: The source label returned by ``adapter.get_publish_time()``.
        session_errors: Error codes from ``resolver.get_session_errors()``.

    Returns:
        A valid ``resolution_status`` string for the ``resolution_attempts`` table.
    """
    if "rate_limited" in session_errors or source_label == "rate_limited":
        return "rate_limited"
    if source_label in (
        "not_found",
        "timeout",
        "network_error",
        "server_error",
        "unknown_error",
    ):
        return source_label
    if source_label == "unresolved":
        return "all_sources_failed"
    return "all_sources_failed"


@dataclass
class ThreatCheckResult:
    """Result of a threat check with audit-relevant counts."""

    passed: bool
    threat_count_general: int = 0
    threat_count_versioned: int = 0
    threat_context_map: dict[str, ThreatCooldownContext] | None = None
    block_decision: BlockDecision | None = None


@dataclass
class CooldownCheckResult:
    """Result of a cooldown check with audit-relevant data."""

    passed: bool
    cooldown_pass: bool = True
    cooldown_days_remaining: int = 0
    block_decision: BlockDecision | None = None


@dataclass
class BlockDecision:
    """Captures a blocking decision for deferred user interaction.

    Used to separate detection logic (which runs inside timeout) from
    user interaction (which runs outside timeout via input()).
    """

    reason: BlockReason
    package: PackageRef
    parsed: ParsedCommand
    safe_version: str | None = None
    clears_at: datetime | None = None
    checks_performed: str = "bypassed"
    ecosystem: str | None = None
    window_days: int | None = None
    release_date: datetime | None = None
    date_source: str = ""


class ManagerDispatcher:
    """
    Routes package manager commands to the appropriate adapter.

    The dispatcher:
    1. Looks up the adapter class via get_adapter_class_for_manager() from the registry package
    2. Calls adapter.parse() to get a ParsedCommand
    3. Routes based on intent:
       - SAFE_PASSTHROUGH → immediate exec
       - INSTALL/UPDATE/SYNC → route to PreInstallChecker (Phase 5)
       - REMOVE → exec (safe, no intercept needed)
    """

    # Track which managers have already shown the AUDIT-tier cooldown-skipped
    # note to avoid repeating it on subsequent dispatches in the same session.
    _warned_audit_managers: set[str] = set()

    # Class-level default: allows __new__-based test construction
    # without bypassing the adapter attribute. Tests that use
    # ManagerDispatcher.__new__() set .adapter after construction.
    adapter: ManagerAdapter | None = None

    def __init__(self, manager_name: str) -> None:
        """Initialize dispatcher for a specific manager name."""
        from pkg_defender.registry import get_adapter_class_for_manager

        self.manager_name = manager_name

        adapter_class = get_adapter_class_for_manager(manager_name)
        if not adapter_class:
            raise ValueError(f"Unknown package manager: {manager_name}")

        self.adapter = adapter_class()
        self._session_id: str = str(uuid.uuid4())

    def run(self, manager_args: list[str], ctx: click.Context) -> None:
        """
        Parse and route a manager command.

        Args:
            manager_args: Raw arguments after the manager name (e.g., ["install", "requests"])
            ctx: Click context for error handling
        """
        from pkg_defender.cli.exec import handle_cleared_command

        # self.adapter is always set here (set in __init__ via constructor path)
        assert self.adapter is not None
        parsed = self.adapter.parse(manager_args)
        parsed.manager = self.manager_name

        # Merge global Click flags into parsed pkgd_flags (fixes prefix/postfix gap)
        if ctx and ctx.obj:
            # Only merge keys that correspond to known PKGD_FLAGS entries.
            # Convert PKGD_FLAGS (e.g., "--dry-run") to canonical key form (e.g., "dry_run")
            pkgd_flag_keys: set[str] = set()
            for flag in UnifiedRegistryAdapter.PKGD_FLAGS:
                if flag.startswith("--"):
                    pkgd_flag_keys.add(flag[2:].replace("-", "_"))
            # Handle short flag "-v" → "verbose" (split_pkgd_flags maps -v to "verbose")
            pkgd_flag_keys.add("verbose")
            for key, value in ctx.obj.items():
                if key in pkgd_flag_keys and key not in parsed.pkgd_flags and value is not None and value is not False:
                    parsed.pkgd_flags[key] = value

        if parsed.intent == CommandIntent.SAFE_PASSTHROUGH or parsed.intent == CommandIntent.REMOVE:
            handle_cleared_command(parsed, passthrough=True)
        elif parsed.intent == CommandIntent.EXECUTE:
            # EXECUTE (dlx, bunx, uv run, cargo run, poetry run, bundle exec)
            # may install and run arbitrary code — route through pre-install checks
            self._run_pre_install_with_timeout(parsed, ctx)
        else:
            # INSTALL, UPDATE, SYNC — route through pre-install checks
            self._run_pre_install_with_timeout(parsed, ctx)

    @property
    def bypass_service(self) -> BypassService:
        """Lazy-loaded BypassService instance.

        Uses ``getattr`` to handle ``__new__``-based test construction
        where ``__init__`` is not called.
        """
        svc = getattr(self, "_bypass_service", None)
        if svc is None:
            from pkg_defender.audit.bypass_service import BypassService
            from pkg_defender.config import get_db_path

            svc = BypassService(get_db_path())
            self._bypass_service = svc
        return svc

    async def _resolve_latest_versions_async(
        self,
        parsed: ParsedCommand,
    ) -> None:
        """Resolve latest versions for packages without an explicit version.

        Runs in the async wrapper before dispatching to the thread executor.
        Mutates pkg.version in-place for each resolved package.
        Handles resolution failures gracefully — CI mode blocks, interactive warns.
        """
        import logging

        logger = logging.getLogger(__name__)
        adapter = self.adapter

        # Only resolve if adapter has the capability
        if not isinstance(adapter, PipelineAdapterProtocol):
            return

        from pkg_defender.config import load_config

        _config = load_config()
        for pkg in parsed.packages:
            if pkg.version is not None:
                continue  # Already has a version

            _timeout_val = _config.registry_api_timeout
            _adapter_eco: str | None = getattr(adapter, "ecosystem", None)
            if isinstance(_adapter_eco, str) and _adapter_eco in _config.per_ecosystem_registry_timeout:
                _timeout_val = _config.per_ecosystem_registry_timeout[_adapter_eco]

            try:
                resolved = await asyncio.wait_for(
                    adapter.resolve_latest_version(pkg.name),
                    timeout=_timeout_val,
                )
            except TimeoutError:
                resolved = None
                logger.warning("Timed out resolving latest version for %s", pkg.name)
            except Exception as exc:
                resolved = None
                logger.warning(
                    "Failed to resolve latest version for %s: %s",
                    pkg.name,
                    exc,
                )

            if resolved:
                pkg.version = resolved
                pkg.is_latest = True
                logger.info("Resolved latest version for %s: %s", pkg.name, resolved)
            else:
                if parsed.pkgd_flags.get("ci"):
                    click.echo(
                        f"[PKGD] Error: Could not resolve latest version for "
                        f"'{pkg.name}' — specify an explicit version in CI mode.",
                        err=True,
                    )
                    raise SystemExit(EXIT_GENERAL_ERROR)
                else:
                    click.echo(
                        f"[PKGD] Warning: Could not determine the latest version for "
                        f"'{pkg.name}'.\n"
                        f"[PKGD]        Specify a version: pkgd pip install "
                        f"{pkg.name}==X.Y.Z\n"
                        f"[PKGD]        Or use --allow-once to bypass "
                        f"(logged to audit trail).",
                        err=True,
                    )

    async def _cache_version_timestamps_async(
        self,
        parsed: ParsedCommand,
    ) -> None:
        """Cache publish timestamps for all package versions in the DB.

        Fetches publish_time from the registry adapter for each package
        version and stores it in the ``version_timestamps`` table so that
        subsequent cooldown checks can look up release dates.

        This is a best-effort operation — failures are logged but do NOT
        block the install. A failed cache write means the cooldown check
        will fail-closed (same behavior as before this fix).
        """
        logger = logging.getLogger(__name__)
        adapter = self.adapter

        # Only cache if the adapter supports pipeline operations
        if not isinstance(adapter, PipelineAdapterProtocol):
            return

        # Resolve ecosystem from adapter for DB storage
        _eco: str | None = None
        _ae = getattr(adapter, "ecosystem", None)
        if isinstance(_ae, str):
            _eco = _ae

        from pkg_defender.config import get_db_path, load_config

        _config = load_config()
        db_path = get_db_path()
        if db_path is None or not isinstance(db_path, Path) or not db_path.exists():
            logger.warning("No threat DB available for caching version timestamps; skipping")
            return

        conn = get_connection(db_path)

        # Snapshot session errors ONCE before iterating packages so all
        # failure records in this batch share the same session-level context.
        from pkg_defender.registry._timestamp import get_resolver

        _session_errors_snapshot: set[str] = set()
        try:
            _resolver = get_resolver()
            _session_errors_snapshot = _resolver.get_session_errors()
        except Exception:
            logger.debug("_cache_version_timestamps_async: failed to snapshot session errors", exc_info=True)

        try:
            for pkg in parsed.packages:
                if pkg.version is None:
                    continue

                _timeout_val = _config.registry_api_timeout
                if _eco and _eco in _config.per_ecosystem_registry_timeout:
                    _timeout_val = _config.per_ecosystem_registry_timeout[_eco]

                try:
                    publish_time, source_label = await asyncio.wait_for(
                        adapter.get_publish_time(pkg.name, pkg.version, is_latest=pkg.is_latest),
                        timeout=_timeout_val,
                    )
                except TimeoutError:
                    logger.warning(
                        "Timed out fetching release date for %s@%s",
                        pkg.name,
                        pkg.version,
                    )
                    ecosystem = pkg.ecosystem or _eco or self.manager_name
                    try:

                        def _insert_timeout(
                            _ecosystem=ecosystem,
                            _name=pkg.name,
                            _version=pkg.version,
                        ) -> None:
                            _conn = get_connection(db_path)
                            try:
                                insert_resolution_attempt(
                                    conn=_conn,
                                    ecosystem=_ecosystem,
                                    package_name=_name,
                                    version=_version,
                                    publish_time=None,
                                    resolution_status="timeout",
                                    source_label="timeout",
                                    last_error="timeout",
                                    retry_after=None,
                                )
                                _conn.commit()
                            finally:
                                _conn.close()

                        await asyncio.to_thread(_insert_timeout)
                    except Exception as exc:
                        logger.warning(
                            "Failed to record resolution timeout for %s@%s: %s",
                            pkg.name,
                            pkg.version,
                            exc,
                        )
                    continue
                except Exception as exc:
                    logger.warning(
                        "Failed to fetch release date for %s@%s: %s",
                        pkg.name,
                        pkg.version,
                        exc,
                    )
                    ecosystem = pkg.ecosystem or _eco or self.manager_name
                    try:

                        def _insert_failure(
                            _ecosystem=ecosystem,
                            _name=pkg.name,
                            _version=pkg.version,
                            _exc=exc,
                            _snapshot=_session_errors_snapshot,
                        ) -> None:
                            _conn = get_connection(db_path)
                            try:
                                insert_resolution_attempt(
                                    conn=_conn,
                                    ecosystem=_ecosystem,
                                    package_name=_name,
                                    version=_version,
                                    publish_time=None,
                                    resolution_status=_derive_failure_status(
                                        str(_exc),
                                        _snapshot,
                                    ),
                                    source_label=str(_exc),
                                    last_error=str(_exc),
                                    retry_after=None,
                                )
                                _conn.commit()
                            finally:
                                _conn.close()

                        await asyncio.to_thread(_insert_failure)
                    except Exception as write_exc:
                        logger.warning(
                            "Failed to record resolution failure for %s@%s: %s",
                            pkg.name,
                            pkg.version,
                            write_exc,
                        )
                    continue

                if publish_time is None:
                    # When publish_time is None but source_label is meaningful
                    # (e.g., "unresolved"), update only the source_label to
                    # heal pre-Session-39 rows without touching their valid
                    # publish_time. The UPDATE is a no-op if the row doesn't
                    # exist (it will get the correct source_label on next
                    # successful cache via ON CONFLICT DO UPDATE SET).
                    ecosystem = pkg.ecosystem or _eco or self.manager_name
                    if source_label:
                        try:

                            def _update_label(
                                _source_label=source_label,
                                _ecosystem=ecosystem,
                                _pkg=pkg,
                            ) -> None:
                                _conn = get_connection(db_path)
                                try:
                                    _conn.execute(
                                        "UPDATE version_timestamps SET source_label = ?"
                                        " WHERE ecosystem = ? AND package_name = ? AND version = ?"
                                        " AND (source_label IS NULL OR source_label = '')",
                                        (_source_label, _ecosystem, _pkg.name, _pkg.version),
                                    )
                                    _conn.commit()
                                finally:
                                    _conn.close()

                            await asyncio.to_thread(_update_label)
                        except Exception as exc:
                            logger.warning(
                                "Failed to update source_label for %s@%s: %s",
                                pkg.name,
                                pkg.version,
                                exc,
                            )
                    # Write failure record to resolution_attempts table.
                    try:

                        def _insert_failure_resolution(
                            _ecosystem=ecosystem,
                            _name=pkg.name,
                            _version=pkg.version,
                            _source_label=source_label,
                            _snapshot=_session_errors_snapshot,
                        ) -> None:
                            _conn = get_connection(db_path)
                            try:
                                insert_resolution_attempt(
                                    conn=_conn,
                                    ecosystem=_ecosystem,
                                    package_name=_name,
                                    version=_version,
                                    publish_time=None,
                                    resolution_status=_derive_failure_status(
                                        _source_label,
                                        _snapshot,
                                    ),
                                    source_label=_source_label,
                                    last_error=_source_label,
                                    retry_after=None,
                                )
                                _conn.commit()
                            finally:
                                _conn.close()

                        await asyncio.to_thread(_insert_failure_resolution)
                    except Exception as exc:
                        logger.warning(
                            "Failed to record resolution failure for %s@%s: %s",
                            pkg.name,
                            pkg.version,
                            exc,
                        )
                    continue

                ecosystem = pkg.ecosystem or _eco or self.manager_name
                from pkg_defender.models import VersionInfo

                info = VersionInfo(
                    version=pkg.version,
                    publish_time=publish_time,
                    date_source=source_label,
                    ecosystem=ecosystem,
                    package_name=pkg.name,
                )
                try:

                    def _insert_ts(
                        _info=info,
                    ) -> None:
                        _conn = get_connection(db_path)
                        try:
                            insert_version_timestamp(_conn, _info)
                            _conn.commit()
                        finally:
                            _conn.close()

                    await asyncio.to_thread(_insert_ts)
                except Exception as exc:
                    logger.warning(
                        "Failed to cache version timestamp for %s@%s: %s",
                        pkg.name,
                        pkg.version,
                        exc,
                    )
                # Best-effort: also write success to resolution_attempts so
                # _build_release_date_map can JOIN against it.  Failure here
                # is non-fatal — success already in version_timestamps.
                with contextlib.suppress(Exception):

                    def _insert_resolved(
                        _ecosystem=ecosystem,
                        _name=pkg.name,
                        _version=pkg.version,
                        _publish_time=publish_time,
                        _source_label=source_label,
                    ) -> None:
                        _conn = get_connection(db_path)
                        try:
                            insert_resolution_attempt(
                                conn=_conn,
                                ecosystem=_ecosystem,
                                package_name=_name,
                                version=_version,
                                publish_time=_publish_time,
                                resolution_status="resolved",
                                source_label=_source_label,
                                last_error=None,
                                retry_after=None,
                            )
                            _conn.commit()
                        finally:
                            _conn.close()

                    await asyncio.to_thread(_insert_resolved)
        except Exception as exc:
            logger.warning(
                "Unexpected error caching version timestamps: %s",
                exc,
            )
        finally:
            conn.close()

    async def _run_pre_install_check_async(
        self,
        parsed: ParsedCommand,
        ctx: click.Context,
    ) -> list[BlockDecision]:
        """
        Async wrapper for pre-install checker with timeout support.

        Returns a list of BlockDecision objects for any blocking conditions
        found during detection. The caller processes these OUTSIDE the timeout.

        Args:
            parsed: The parsed command containing packages to check.
            ctx: Click context for accessing fail_on_threat flag.
        """
        # Resolve latest versions for packages without a version
        await self._resolve_latest_versions_async(parsed)

        # Cache publish timestamps for cooldown checks
        await self._cache_version_timestamps_async(parsed)

        # Show resolver degradation warning — CI-mode-aware
        from pkg_defender.cli.exec import _stderr_write
        from pkg_defender.registry._timestamp import get_resolver

        resolver = get_resolver()
        errors = resolver.get_session_errors()
        if errors:
            if parsed.pkgd_flags.get("ci"):
                # CI mode: plain text via _stderr_write (no Rich
                # dependencies — safe for CI logs, no ANSI codes).
                _stderr_write(
                    "[PKGD] Warning: GitHub timestamp lookup unavailable.\n"
                    "  Set PKGD_GITHUB_TOKEN in your environment or configure\n"
                    "  [feeds] ghsa_token in pkgd.toml for reliable lookups.\n"
                    "  Create a token: https://github.com/settings/tokens\n"
                )
            else:
                # Interactive mode: plain [PKGD] text with remediation advice.
                _stderr_write("[PKGD] Timestamp resolution notice — GitHub timestamp lookup unavailable.")
                _stderr_write("[PKGD]   Set PKGD_GITHUB_TOKEN in your environment or configure")
                _stderr_write("[PKGD]   [feeds] ghsa_token in pkgd.toml for reliable lookups.")
                _stderr_write("[PKGD]   Create a token: https://github.com/settings/tokens")

        # Run the synchronous pre-install check in an executor
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_pre_install_check, parsed, ctx)

    def _run_pre_install_check(
        self,
        parsed: ParsedCommand,
        ctx: click.Context,
    ) -> list[BlockDecision]:
        """
        Route to the pre-install checker for threat/cooldown validation.

        Checks each package for threats, then handles local/VCS sources,
        and finally executes the command if all checks pass.

        Returns a list of BlockDecision objects for any blocking conditions
        found. The caller is responsible for processing these decisions
        (calling handle_blocked_command) OUTSIDE the timeout scope.

        Args:
            parsed: The parsed command containing packages to check.
            ctx: Click context for accessing fail_on_threat flag.
        """
        from pkg_defender.cli.exec import (
            _print_explain_local_path,
            _print_explain_vcs,
            handle_cleared_command,
        )
        from pkg_defender.config import load_config
        from pkg_defender.models.command import InstallSource

        # Guard: dispatcher may not have an adapter in all code paths
        # (e.g., test setup via __new__ which bypasses __init__).
        if self.adapter is None:
            return []

        # Safe ecosystem resolution: guard against mock adapters in tests
        _adapter_ecosystem: str | None = None
        _ae = getattr(self.adapter, "ecosystem", None)
        if isinstance(_ae, str):
            _adapter_ecosystem = _ae

        # Timing instrumentation
        _start_time_ms: int | None = None
        with contextlib.suppress(OSError):
            _start_time_ms = int(datetime.now(UTC).timestamp() * 1000)

        explain = bool(parsed.pkgd_flags.get("explain"))

        block_decisions: list[BlockDecision] = []

        for pkg in parsed.packages:
            if pkg.source == InstallSource.LOCAL_PATH:
                self._log_audit_event(
                    parsed=parsed,
                    package=pkg,
                    verdict="PASS",
                    exit_code=0,
                    start_time_ms=_start_time_ms,
                )
                if explain:
                    _print_explain_local_path(pkg)
                block_decisions.append(
                    BlockDecision(
                        reason=BlockReason.LOCAL_PATH,
                        package=pkg,
                        parsed=parsed,
                        ecosystem=_adapter_ecosystem,
                    )
                )
                return block_decisions

            if pkg.source == InstallSource.VCS:
                self._log_audit_event(
                    parsed=parsed,
                    package=pkg,
                    verdict="WARN",
                    exit_code=0,
                    start_time_ms=_start_time_ms,
                )
                if explain:
                    _print_explain_vcs(pkg)
                block_decisions.append(
                    BlockDecision(
                        reason=BlockReason.VCS_SOURCE,
                        package=pkg,
                        parsed=parsed,
                        ecosystem=_adapter_ecosystem,
                    )
                )
                return block_decisions

        # Check coverage tier to determine which security checks run
        tier = self.adapter.coverage_tier

        if tier == CoverageTier.AUDIT:
            # AUDIT-tier: skip cooldown (semantically wrong for curated
            # distributions), but still check threats.
            threat_result = self._check_threats(parsed, ctx, _start_time_ms)
            if not threat_result.passed:
                if threat_result.block_decision:
                    block_decisions.append(threat_result.block_decision)
                return block_decisions  # audit event written inside _check_threats
            # AUDIT tier PASS — write audit event before exec
            self._log_audit_pass_event(
                parsed,
                threat_result,
                _start_time_ms,
                ctx=ctx,
                fail_on_threat_enabled=ctx.obj.get("fail_on_threat", True) if ctx.obj else True,
                cooldown_enabled=load_config().cooldown.enabled,
                coverage_tier=self.adapter.coverage_tier.value,
            )
            if not parsed.pkgd_flags.get("json"):
                from pkg_defender.cli.exec import _format_source_label
                from pkg_defender.display import is_quiet_mode

                release_dates = self._build_release_date_map(parsed)
                for pkg in parsed.packages:
                    release_info = release_dates.get(pkg.name)
                    if release_info is not None:
                        release_date, source_label = release_info
                        source_display = _format_source_label(source_label) if source_label else "unknown"
                        pub_date = release_date.strftime("%Y-%m-%d %H:%M:%S") if release_date else "unknown"
                    else:
                        source_display = "unknown"
                        pub_date = "unknown"
                    pkg_version = pkg.version or "latest"
                    click.echo(
                        f"[PKGD] Resolved {pkg.name}@{pkg_version}"
                        f" — source: {source_display}"
                        f" — published: {pub_date} UTC",
                        err=True,
                    )
                    click.echo(
                        f"[PKGD] Threat check passed — no known threats for {pkg.name}@{pkg_version}",
                        err=True,
                    )
                # Cooldown-skipped note: once per manager per session
                if self.manager_name not in self._warned_audit_managers:
                    self._warned_audit_managers.add(self.manager_name)
                    if not is_quiet_mode():
                        click.echo(
                            "[PKGD] Cooldown check skipped — AUDIT-tier support",
                            err=True,
                        )
            handle_cleared_command(parsed)
            return block_decisions

        # Build release_dates from DB cache before cooldown check
        release_dates = self._build_release_date_map(parsed)

        if tier == CoverageTier.PARTIAL:
            # PARTIAL tier: run threat check, then cooldown (same structure as FULL)
            threat_result = self._check_threats(parsed, ctx, _start_time_ms)
            if not threat_result.passed:
                if threat_result.block_decision:
                    block_decisions.append(threat_result.block_decision)
                return block_decisions  # audit event written inside _check_threats
            cooldown_result = self._check_cooldown(
                parsed,
                ctx,
                release_dates,
                _start_time_ms,
                threat_context_map=threat_result.threat_context_map,
            )
            if not cooldown_result.passed:
                if cooldown_result.block_decision:
                    block_decisions.append(cooldown_result.block_decision)
                return block_decisions  # audit event written inside _check_cooldown
            # Both passed — write audit event before exec
            self._log_audit_pass_event(
                parsed,
                threat_result,
                _start_time_ms,
                ctx=ctx,
                fail_on_threat_enabled=ctx.obj.get("fail_on_threat", True) if ctx.obj else True,
                cooldown_enabled=load_config().cooldown.enabled,
                coverage_tier=self.adapter.coverage_tier.value,
            )
            if not parsed.pkgd_flags.get("json"):
                from pkg_defender.audit.cooldown import get_cooldown_window
                from pkg_defender.cli.exec import _format_source_label
                from pkg_defender.config import load_config as _load_config

                for pkg in parsed.packages:
                    release_info = release_dates.get(pkg.name)
                    if release_info is not None:
                        release_date, source_label = release_info
                        source_display = _format_source_label(source_label) if source_label else "unknown"
                        pub_date = release_date.strftime("%Y-%m-%d %H:%M:%S") if release_date else "unknown"
                    else:
                        release_date = None
                        source_display = "unknown"
                        pub_date = "unknown"
                    pkg_version = pkg.version or "latest"
                    click.echo(
                        f"[PKGD] Resolved {pkg.name}@{pkg_version}"
                        f" — source: {source_display}"
                        f" — published: {pub_date} UTC",
                        err=True,
                    )
                    click.echo(
                        f"[PKGD] Threat check passed — no known threats for {pkg.name}@{pkg_version}",
                        err=True,
                    )
                    if release_date is not None:
                        if release_date.tzinfo is None:
                            release_date = release_date.replace(tzinfo=UTC)
                        _cfg = _load_config()
                        age_days = (datetime.now(UTC) - release_date).days
                        ecosystem = pkg.ecosystem or self.manager_name
                        window_days = get_cooldown_window(_cfg.cooldown, ecosystem)
                        click.echo(
                            f"[PKGD] Cooldown check passed"
                            f" — {age_days}d since release"
                            f" > {window_days}d cooldown window",
                            err=True,
                        )
            handle_cleared_command(parsed)
            return block_decisions

        # FULL tier — run both checks
        threat_result = self._check_threats(parsed, ctx, _start_time_ms)
        if not threat_result.passed:
            if threat_result.block_decision:
                block_decisions.append(threat_result.block_decision)
            return block_decisions  # audit event written inside _check_threats
        cooldown_result = self._check_cooldown(
            parsed,
            ctx,
            release_dates,
            _start_time_ms,
            threat_context_map=threat_result.threat_context_map,
        )
        if not cooldown_result.passed:
            if cooldown_result.block_decision:
                block_decisions.append(cooldown_result.block_decision)
            return block_decisions  # audit event written inside _check_cooldown
        # Both passed — write audit event before exec
        self._log_audit_pass_event(
            parsed,
            threat_result,
            _start_time_ms,
            ctx=ctx,
            fail_on_threat_enabled=ctx.obj.get("fail_on_threat", True) if ctx.obj else True,
            cooldown_enabled=load_config().cooldown.enabled,
            coverage_tier=self.adapter.coverage_tier.value,
        )
        if not parsed.pkgd_flags.get("json"):
            from pkg_defender.audit.cooldown import get_cooldown_window
            from pkg_defender.cli.exec import _format_source_label
            from pkg_defender.config import load_config as _load_config

            for pkg in parsed.packages:
                release_info = release_dates.get(pkg.name)
                if release_info is not None:
                    release_date, source_label = release_info
                    source_display = _format_source_label(source_label) if source_label else "unknown"
                    pub_date = release_date.strftime("%Y-%m-%d %H:%M:%S") if release_date else "unknown"
                else:
                    release_date = None
                    source_display = "unknown"
                    pub_date = "unknown"
                pkg_version = pkg.version or "latest"
                click.echo(
                    f"[PKGD] Resolved {pkg.name}@{pkg_version} — source: {source_display} — published: {pub_date} UTC",
                    err=True,
                )
                click.echo(
                    f"[PKGD] Threat check passed — no known threats for {pkg.name}@{pkg_version}",
                    err=True,
                )
                if release_date is not None:
                    if release_date.tzinfo is None:
                        release_date = release_date.replace(tzinfo=UTC)
                    _cfg = _load_config()
                    age_days = (datetime.now(UTC) - release_date).days
                    ecosystem = pkg.ecosystem or self.manager_name
                    window_days = get_cooldown_window(_cfg.cooldown, ecosystem)
                    click.echo(
                        f"[PKGD] Cooldown check passed — {age_days}d since release > {window_days}d cooldown window",
                        err=True,
                    )
        handle_cleared_command(parsed)
        return block_decisions

    def _ensure_db_fresh(
        self,
        config: PKGDConfig,
        ctx: click.Context,
        explain: bool = False,
        ecosystems: list[str] | None = None,
    ) -> bool:
        """Check DB staleness and auto-refresh if needed.

        When ``ecosystems`` is ``None`` (default), queries ``feed_state.last_sync``
        for the OSV feed and compares against the staleness threshold. When
        ``ecosystems`` is specified, performs the same staleness check — skips
        sync if the feed_state timestamp is fresh, otherwise syncs for the
        requested ecosystems.

        Args:
            config: The current application configuration.
            ctx: Click context for error handling.
            ecosystems: Optional list of ecosystems to sync. If None (default),
                syncs all ecosystems. When specified, only syncs the listed
                ecosystems (e.g., ``["pypi"]`` for a pip install command). Also
                performs the same feed_state staleness check — skips sync if
                the feed_state timestamp is fresh.

        Returns:
            True if the DB is fresh or refresh succeeded.

        Raises:
            SystemExit: If the DB is stale and auto-refresh fails.
        """
        logger = logging.getLogger(__name__)

        # If no DB exists yet, let existing fail-closed in _check_threats handle it
        from pkg_defender.config import get_db_path

        db_path = get_db_path()
        if db_path is None or not isinstance(db_path, Path) or not db_path.exists():
            return True

        try:
            from pkg_defender.db.schema import get_connection, get_feed_state

            conn = get_connection(db_path, config=config.database)
        except sqlite3.Error as e:
            logger.warning("Could not open threat DB for staleness check: %s, skipping", e)
            return True

        try:
            state: dict[str, str | None] | None = None

            if ecosystems is None:
                # Check staleness using the osv feed (always enabled, primary threat source)
                state = get_feed_state(conn, "osv")
                is_stale = False

                if state is None or state.get("last_sync") is None:
                    is_stale = True
                else:
                    try:
                        last_sync_str = state["last_sync"]
                        if last_sync_str is None:
                            is_stale = True
                        else:
                            last_sync = datetime.fromisoformat(last_sync_str)
                            if last_sync.tzinfo is None:
                                last_sync = last_sync.replace(tzinfo=UTC)
                            age = datetime.now(UTC) - last_sync
                            threshold = timedelta(hours=config.feeds.staleness_threshold_hours)
                            if age > threshold:
                                is_stale = True
                    except (ValueError, TypeError):
                        is_stale = True

                if not is_stale:
                    return True

                # DB is stale — trigger auto-refresh of all enabled feeds
                click.echo("[PKGD] Threat database is stale — refreshing...", err=True)
            else:
                state = get_feed_state(conn, "osv")
                is_stale = False

                if state is None or state.get("last_sync") is None:
                    is_stale = True
                else:
                    try:
                        last_sync_str = state["last_sync"]
                        if last_sync_str is None:
                            is_stale = True
                        else:
                            last_sync = datetime.fromisoformat(last_sync_str)
                            if last_sync.tzinfo is None:
                                last_sync = last_sync.replace(tzinfo=UTC)
                            age = datetime.now(UTC) - last_sync
                            threshold = timedelta(hours=config.feeds.staleness_threshold_hours)
                            if age > threshold:
                                is_stale = True
                    except (ValueError, TypeError):
                        is_stale = True

                if not is_stale:
                    click.echo("[PKGD] Threat data fresh — skipping ecosystem sync.", err=True)
                    return True

                click.echo("[PKGD] Syncing threat data for requested ecosystem...", err=True)
        finally:
            conn.close()

        # Build feed list and sync (outside DB connection scope)
        try:
            from pkg_defender.intel.aggregator import FeedAggregator, OSVFeedAdapter
            from pkg_defender.intel.base import FeedSource
            from pkg_defender.intel.feeds.homebrew import HomebrewFeedAdapter
            from pkg_defender.intel.ghsa import GHSAFeed
            from pkg_defender.intel.mastodon import MastodonFeed
            from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
            from pkg_defender.intel.ossf_malicious import OSSFMaliciousFeed
            from pkg_defender.intel.reddit import RedditFeed
            from pkg_defender.intel.rss_feed import RSSFeed
            from pkg_defender.intel.socket import SocketFeed
            from pkg_defender.intel.x_twitter import XTwitterFeed

            feeds: list[FeedSource] = [OSVFeedAdapter()]
            if shutil.which("brew") is not None:
                feeds.append(HomebrewFeedAdapter())
            if config.feeds.ghsa_enabled:
                feeds.append(GHSAFeed())
            if config.feeds.socket_enabled:
                feeds.append(SocketFeed())
            if config.feeds.npm_advisory_enabled:
                feeds.append(NpmAdvisoryFeed())
            if config.feeds.mastodon_enabled:
                feeds.append(MastodonFeed())
            if config.feeds.reddit_enabled:
                feeds.append(RedditFeed())
            if config.feeds.rss_enabled:
                feeds.append(RSSFeed())
            if config.feeds.x_twitter_enabled:
                feeds.append(XTwitterFeed())
            if config.feeds.ossf_malicious_enabled:
                feeds.append(OSSFMaliciousFeed())

            aggregator = FeedAggregator(
                feeds,
                db_path,
                config=config,
                retention_days=config.database.retention_days,
            )
            sync_start = datetime.now(UTC)
            with feed_sync_progress(len(feeds)) as progress:
                task: Any = 0  # placeholder, only used when progress is not None
                if progress is not None:
                    task = progress.add_task("Syncing all feeds concurrently...", total=len(feeds))

                def _on_feed_complete(feed_name: str, record_count: int) -> None:
                    handle_feed_complete(progress, task, feed_name, record_count)

                results = asyncio.run(
                    asyncio.wait_for(
                        aggregator.sync_all(
                            ecosystems=ecosystems,
                            progress_callback=_on_feed_complete,
                        ),
                        timeout=config.feeds.feed_sync_timeout if config.feeds.feed_sync_timeout > 0 else None,
                    )
                )

            # ── Homebrew Vulnerability Alert (dispatcher) ──
            homebrew_count = results.get("homebrew", 0) if isinstance(results, dict) else 0
            if homebrew_count > 0:
                conn = sqlite3.connect(db_path)
                try:
                    homebrew_records = query_threats_by_source(
                        conn,
                        ecosystem="homebrew",
                        source="homebrew_osv",
                        ingested_since=sync_start.isoformat(),
                    )
                finally:
                    conn.close()

                if homebrew_records:
                    click.echo(
                        f"[PKGD] \u26a0 BREW: {len(homebrew_records)} Vulnerable Package"
                        f"{'s' if len(homebrew_records) != 1 else ''} Found",
                        err=True,
                    )
                    click.echo("", err=True)
                    for rec in homebrew_records:
                        version = asyncio.run(brew_get_installed_version(rec["package_name"])) or ""
                        version_str = f" ({version})" if version else ""
                        cvss = f" \u2014 CVSS {rec['cvss_score']}" if rec.get("cvss_score") else ""
                        click.echo(f"[PKGD]   Package: {rec['package_name']}{version_str}", err=True)
                        click.echo(f"[PKGD]   Severity: {rec['severity']}{cvss}", err=True)
                        if rec.get("summary"):
                            click.echo(f"[PKGD]   Summary: {rec['summary']}", err=True)
                        click.echo(f"[PKGD]   Fix: brew upgrade {rec['package_name']}", err=True)
                        if rec.get("detail_url"):
                            click.echo(f"[PKGD]   {rec['detail_url']}", err=True)
                        click.echo("", err=True)

            return True
        except TimeoutError:
            logger.error("Auto-refresh of threat database timed out after %ds", config.feeds.feed_sync_timeout)
            from pkg_defender.cli._exit_codes import EXIT_DB_ERROR

            click.echo(
                f"[PKGD] Error: Feed sync timed out after {config.feeds.feed_sync_timeout} seconds. "
                "Run 'pkgd intel sync' manually or increase feed_sync_timeout in config.",
                err=True,
            )
            raise SystemExit(EXIT_DB_ERROR) from None
        except Exception as exc:
            logger.error("Auto-refresh of threat database failed: %s", exc)
            from pkg_defender.cli._exit_codes import EXIT_DB_ERROR

            if explain:
                from pkg_defender.cli.exec import _print_explain_stale_db

                _print_explain_stale_db(
                    db_path=str(db_path),
                    last_sync=state.get("last_sync") if state else None,
                    threshold_hours=config.feeds.staleness_threshold_hours,
                    error_msg=str(exc),
                )

            click.echo(
                "[PKGD] Error: Threat database is stale and auto-refresh failed. Run 'pkgd intel sync' manually.",
                err=True,
            )
            raise SystemExit(EXIT_DB_ERROR) from exc

    def _run_pre_install_with_timeout(
        self,
        parsed: ParsedCommand,
        ctx: click.Context,
    ) -> None:
        """Run pre-install checks with DB freshness guarantee and timeout.

        Shared by EXECUTE and INSTALL/UPDATE/SYNC command paths to eliminate
        a ~30-line copy-paste that had already started diverging (type annotation
        drift on _adapter_eco).

        Ensures DB is fresh BEFORE the timeout scope — feed sync can take
        several minutes (OSV bulk dumps ~334MB). Must complete fully to
        avoid partial-commit inconsistency on timeout.
        """
        from pkg_defender.config import load_config

        config = load_config()

        explain = bool(parsed.pkgd_flags.get("explain"))
        _adapter_eco: str | None = None
        if self.adapter is not None:
            _ae = getattr(self.adapter, "ecosystem", None)
            if isinstance(_ae, str) and len(_ae) > 0:
                _adapter_eco = _ae
        ecosystems = [_adapter_eco] if _adapter_eco else None
        self._ensure_db_fresh(config, ctx, explain, ecosystems=ecosystems)
        self._check_protection_warning(config, parsed, ctx)

        try:
            block_decisions = asyncio.run(
                asyncio.wait_for(
                    self._run_pre_install_check_async(parsed, ctx),
                    timeout=config.command_timeout_seconds,
                )
            )
        except TimeoutError:
            logger = logging.getLogger(__name__)
            logger.error(f"Pre-install check timed out after {config.command_timeout_seconds} seconds")
            if parsed.pkgd_flags.get("explain"):
                from pkg_defender.cli.exec import _print_explain_timeout

                _print_explain_timeout(config.command_timeout_seconds)
            click.echo(
                f"[PKGD] Error: Pre-install check timed out after {config.command_timeout_seconds} seconds",
                err=True,
            )
            raise SystemExit(EXIT_GENERAL_ERROR) from None

        # Process block decisions OUTSIDE the timeout scope.
        # handle_blocked_command() calls input() which must not be time-bounded.
        if block_decisions:
            from pkg_defender.cli.exec import handle_blocked_command

            for decision in block_decisions:
                handle_blocked_command(
                    decision.parsed,
                    decision.reason,
                    decision.package,
                    safe_version=decision.safe_version,
                    clears_at=decision.clears_at,
                    checks_performed=decision.checks_performed,
                    ecosystem=decision.ecosystem,
                    window_days=decision.window_days,
                    release_date=decision.release_date,
                    date_source=decision.date_source,
                )

    def _check_protection_warning(
        self,
        config: PKGDConfig,
        parsed: ParsedCommand,
        ctx: click.Context,
    ) -> None:
        """Print a warning if protection is not fully secure.

        Checks config-level protection status via ``_get_protection_status()``.
        Skips if quiet mode, JSON output, or status is already ``"secure"``.

        Args:
            config: Current application configuration.
            parsed: The parsed command (used to check json flag).
            ctx: Click context (unused, kept for API consistency with other
                pipeline methods).
        """
        from pkg_defender.cli.common import _get_protection_status
        from pkg_defender.display import is_quiet_mode

        # Fast path: do nothing if protection is fully secure.
        # _get_protection_status is pure config-read with zero I/O.
        status = _get_protection_status(config)
        if status["level"] == "secure":
            return

        # Skip if quiet mode or JSON output
        if is_quiet_mode() or parsed.pkgd_flags.get("json"):
            return

        click.echo(f"[PKGD] Protection Status: {status['level'].replace('_', ' ').title()}", err=True)
        for issue in status["issues"]:
            click.echo(f"[PKGD]   {issue}", err=True)
        click.echo("[PKGD]   Run 'pkgd health' for full details.", err=True)

    def _check_threats(
        self,
        parsed: ParsedCommand,
        ctx: click.Context,
        start_time_ms: int | None = None,
    ) -> ThreatCheckResult:
        """
        Check packages for known threats using core/checker.py.

        Args:
            parsed: The parsed command containing packages to check.
            ctx: Click context for accessing fail_on_threat flag.
            start_time_ms: Optional start timestamp in ms for runtime computation.

        Returns:
            ThreatCheckResult with pass/fail and threat counts.
        """
        from pkg_defender.audit.cooldown import ThreatCooldownContext
        from pkg_defender.cli._manager_constants import resolve_ecosystem
        from pkg_defender.config import get_db_path, load_config
        from pkg_defender.core.checker import check_packages_batch

        logger = logging.getLogger(__name__)

        try:
            db_path = get_db_path()
            if db_path is None or not isinstance(db_path, Path):
                logger.warning(
                    "db_path is not a valid Path: %r, blocking install",
                    db_path,
                )
                return ThreatCheckResult(passed=False)
            if not db_path.exists():
                # No threat DB — cannot verify safety, block install (fail-closed)
                if parsed.pkgd_flags.get("explain"):
                    from pkg_defender.cli.exec import _print_explain_no_db

                    _print_explain_no_db(
                        PackageRef(name="(all packages)"),
                        str(db_path),
                    )
                click.echo(
                    "[PKGD] Error: Threat database not found. Run 'pkgd setup' to initialize the threat"
                    " database before installing packages.\n"
                    "[PKGD]        Without a threat database, all package installations are blocked"
                    " for safety.",
                    err=True,
                )
                logger.warning("No threat DB found, blocking install")
                return ThreatCheckResult(passed=False)

            conn = get_connection(db_path)
        except sqlite3.Error as e:
            if parsed.pkgd_flags.get("explain"):
                from pkg_defender.cli.exec import _print_explain_db_connection

                pkg_ref = parsed.packages[0] if parsed.packages else PackageRef(name="(unknown)")
                _print_explain_db_connection(pkg_ref, str(e))
            logger.warning(f"Could not open threat DB: {e}, blocking install")
            return ThreatCheckResult(passed=False)

        # Resolve ecosystem from the adapter (source of truth) rather than
        # resolve_ecosystem(manager_name) which uses the MANAGER_TO_ECOSYSTEM
        # mapping (e.g., "pip" → "pypi").
        _adapter_eco: str | None = None
        if self.adapter is not None:
            _ae = getattr(self.adapter, "ecosystem", None)
            if isinstance(_ae, str):
                _adapter_eco = _ae
        ecosystem = _adapter_eco or resolve_ecosystem(self.manager_name)

        # Query active bypasses for this ecosystem
        active_bypasses = self.bypass_service.get_active_bypasses(ecosystem)

        try:
            # Build typed package list, verifying all have versions in one pass
            packages_for_batch: list[tuple[str, str, str]] = []
            pkg_ref_map: dict[tuple[str, str, str], PackageRef] = {}
            for pkg in parsed.packages:
                if pkg.version is None:
                    if parsed.pkgd_flags.get("explain"):
                        from pkg_defender.cli.exec import _print_explain_no_version

                        _print_explain_no_version(pkg)
                    logger.warning(f"No version specified for {pkg.name}, blocking install")
                    block_decision = BlockDecision(
                        reason=BlockReason.THREAT,
                        package=pkg,
                        parsed=parsed,
                        checks_performed="none",
                        ecosystem=_adapter_eco,
                    )
                    return ThreatCheckResult(passed=False, block_decision=block_decision)
                key = (ecosystem, pkg.name, pkg.version)
                packages_for_batch.append(key)
                pkg_ref_map[key] = pkg

            # Single batch call with timing
            _start = datetime.now(UTC)
            batch_results = check_packages_batch(
                conn=conn,
                packages=packages_for_batch,
            )
            _elapsed = (datetime.now(UTC) - _start).total_seconds()

            # Count threats across all results for audit trail
            total_threats_general = 0
            total_threats_versioned = 0
            threat_context_map: dict[str, ThreatCooldownContext] = {}

            # Process batch results
            for key, pkg in pkg_ref_map.items():
                result = batch_results.get(key)
                if result is None:
                    if parsed.pkgd_flags.get("explain"):
                        from pkg_defender.cli.exec import _print_explain_no_result

                        _print_explain_no_result(pkg)
                    logger.warning(f"No result returned for {pkg.name}, blocking install")
                    return ThreatCheckResult(passed=False)

                # Build threat context for signal-based cooldown escalation (§8.3)
                _tc_ctx = ThreatCooldownContext()
                for scored_threat in result.threats:
                    rec = scored_threat.record
                    if not rec.is_unverified:
                        _tc_ctx.has_verified_advisory = True
                    elif rec.source in {"mastodon", "reddit", "x_twitter"}:
                        _tc_ctx.has_tier3_signals = True
                    elif rec.source == "rss":
                        # RSS is structured feed, not social media — treat as verified
                        _tc_ctx.has_verified_advisory = True
                    else:
                        # Unknown unverified source — safe fallback to Tier 3
                        _tc_ctx.has_tier3_signals = True
                threat_context_map[pkg.name] = _tc_ctx

                # Accumulate threat counts for audit trail
                total_threats_general += len(result.threats)
                total_threats_versioned += sum(1 for t in result.threats if t.version_match_type != "unversioned")

                # Check if this package has an active bypass
                if (pkg.name, pkg.version) in active_bypasses:
                    logger.info(
                        "Bypass active for %s@%s -- skipping threat check",
                        pkg.name,
                        pkg.version,
                    )
                    continue

                if result.blocked:
                    logger.info(
                        f"Blocking install of {pkg.name} "
                        f"(score={result.highest_score:.2f}, severity={result.highest_severity})"
                    )
                    if parsed.pkgd_flags.get("explain"):
                        from pkg_defender.cli.exec import _print_explain_threat

                        _print_explain_threat(pkg, result)
                    fail_on_threat = ctx.obj.get("fail_on_threat", True) if ctx.obj else True
                    if fail_on_threat:
                        # Write audit event before terminal action
                        self._log_audit_event(
                            parsed=parsed,
                            package=pkg,
                            verdict="BLOCKED",
                            exit_code=EXIT_THREAT_DETECTED,
                            threat_count_general=total_threats_general,
                            threat_count_versioned=total_threats_versioned,
                            start_time_ms=start_time_ms,
                            fail_on_threat_enabled=ctx.obj.get("fail_on_threat", True) if ctx.obj else True,
                            cooldown_enabled=load_config().cooldown.enabled,
                            coverage_tier=self.adapter.coverage_tier.value if self.adapter else "full",
                        )
                        block_decision = BlockDecision(
                            reason=BlockReason.THREAT,
                            package=pkg,
                            parsed=parsed,
                            checks_performed="threat_only",
                            ecosystem=_adapter_eco,
                        )
                        return ThreatCheckResult(passed=False, block_decision=block_decision)
                    else:
                        logger.warning(f"Threat detected for {pkg.name} but fail_on_threat is disabled, proceeding")
                        pkg_version = pkg.version or "latest"
                        click.echo(
                            f"[PKGD] WARNING — {pkg.name}@{pkg_version}",
                            err=True,
                        )
                        click.echo(
                            "[PKGD]   Reason: Threat detected, but fail_on_threat is disabled",
                            err=True,
                        )
                        click.echo(
                            f"[PKGD]   Score: {result.highest_score:.2f} (severity: {result.highest_severity})",
                            err=True,
                        )
                        click.echo(
                            "[PKGD]   Proceeding with install.",
                            err=True,
                        )

        except sqlite3.Error as e:
            logger.warning(f"Threat check failed: {e}, blocking install")
            return ThreatCheckResult(passed=False)
        finally:
            conn.close()

        return ThreatCheckResult(
            passed=True,
            threat_count_general=total_threats_general,
            threat_count_versioned=total_threats_versioned,
            threat_context_map=threat_context_map,
        )

    def _build_release_date_map(
        self,
        parsed: ParsedCommand,
    ) -> dict[str, tuple[datetime | None, str]]:
        """Build a mapping of package name → release datetime from DB cache.

        Queries ``version_timestamps`` for successful resolutions and
        ``resolution_attempts`` for all outcomes (success + failure).  Success
        from ``version_timestamps`` takes priority.  Packages found only in
        ``resolution_attempts`` with a failure status are mapped to
        ``(None, <failure_status>)`` so the cooldown layer can surface
        diagnostic information instead of a blank "Unknown."

        Args:
            parsed: The parsed command containing packages to check.

        Returns:
            Dict mapping package name →
            ``(publish_time, source_or_failure_status)``.
            ``publish_time`` is ``None`` when resolution failed;
            ``source_or_failure_status`` carries either a success source
            (e.g. ``"github_tags"``) or a failure status (e.g.
            ``"rate_limited"``).
        """
        import logging
        import sqlite3
        from pathlib import Path

        from pkg_defender.config import get_db_path
        from pkg_defender.db.schema import get_connection, get_resolution_attempts_batch, get_version_timestamps_batch

        logger = logging.getLogger(__name__)

        try:
            db_path = get_db_path()
            if db_path is None or not isinstance(db_path, Path) or not db_path.exists():
                logger.warning("No threat DB available for cooldown timestamp lookup; all packages blocked")
                return {}

            conn = get_connection(db_path)
        except sqlite3.Error as e:
            logger.warning("Could not open DB for cooldown timestamp lookup: %s; all packages blocked", e)
            return {}

        try:
            # Group packages by ecosystem for batch query
            by_ecosystem: dict[str, list[tuple[str, str]]] = {}
            # Resolve ecosystem from the adapter (source of truth) for DB queries.
            # Falls back to resolve_ecosystem for compatibility with test setups
            # that don't have a real adapter.
            _eco: str | None = None
            if self.adapter is not None:
                _ae = getattr(self.adapter, "ecosystem", None)
                if isinstance(_ae, str):
                    _eco = _ae
            for pkg in parsed.packages:
                ecosystem = pkg.ecosystem or _eco or self.manager_name
                if pkg.version is not None:
                    by_ecosystem.setdefault(ecosystem, []).append((pkg.name, pkg.version))

            # Batch query each ecosystem and convert to name→datetime map
            release_dates: dict[str, tuple[datetime | None, str]] = {}
            for ecosystem, pkg_versions in by_ecosystem.items():
                # Get successful timestamps (hot path)
                timestamps = get_version_timestamps_batch(conn, ecosystem, pkg_versions)
                for (_ts_eco, name, _ver), (dt, source) in timestamps.items():
                    release_dates[name] = (dt, source)

                # Get ALL resolution attempts (includes failures)
                attempts = get_resolution_attempts_batch(conn, ecosystem, pkg_versions)
                for (_at_eco, name, _ver), attempt in attempts.items():
                    if name not in release_dates:
                        # Package not in version_timestamps — check resolution_attempts
                        if attempt.publish_time is not None:
                            # Shouldn't happen (success would be in version_timestamps),
                            # but handle gracefully.
                            release_dates[name] = (attempt.publish_time, attempt.source_label)
                        else:
                            # Known failure — store None with failure status as source
                            release_dates[name] = (None, attempt.resolution_status)

            return release_dates

        except sqlite3.Error as e:
            logger.warning("Could not query version timestamps: %s; cooldown will block all packages", e)
            return {}
        finally:
            conn.close()

    def _check_cooldown(
        self,
        parsed: ParsedCommand,
        ctx: click.Context,
        release_dates: dict[str, tuple[datetime | None, str]],
        start_time_ms: int | None = None,
        threat_context_map: dict[str, ThreatCooldownContext] | None = None,
    ) -> CooldownCheckResult:
        """Check cooldown for all packages in the parsed command.

        Delegates to the cooldown module's step_check_cooldown for each
        package, blocking install when any package is within the cooldown
        window or has an unknown release date.

        Args:
            parsed: The parsed command containing packages to check.
            ctx: Click context for accessing fail_on_threat flag.
            release_dates: Dict mapping package name -> (release datetime, source string).
            start_time_ms: Optional start timestamp in ms for runtime computation.
            threat_context_map: Optional per-package threat context for signal-based
                cooldown escalation (§8.3). Keyed by package name. When present, each
                package's context is forwarded to ``step_check_cooldown()``.

        Returns:
            CooldownCheckResult with pass/fail and cooldown data.
        """
        from pkg_defender.audit.cooldown import get_cooldown_window, step_check_cooldown
        from pkg_defender.cli._manager_constants import resolve_ecosystem
        from pkg_defender.config import get_db_path, load_config
        from pkg_defender.db.schema import get_connection

        logger = logging.getLogger(__name__)
        config = load_config()

        # Extract --cooldown override from CLI flags (hours)
        _cooldown_val = parsed.pkgd_flags.get("cooldown")
        _override_hours: int | None = None
        if isinstance(_cooldown_val, str):
            with contextlib.suppress(ValueError, TypeError):
                _override_hours = int(_cooldown_val)

        # Time the cooldown check
        _cooldown_start = datetime.now(UTC)

        # Resolve ecosystem for scoping the bypass query
        ecosystem_for_bypass: str | None = getattr(self.adapter, "ecosystem", None)
        if not isinstance(ecosystem_for_bypass, str):
            ecosystem_for_bypass = resolve_ecosystem(self.manager_name)

        # Query active bypasses for cooldown check
        bypassed_packages_cooldown = self.bypass_service.get_active_bypasses(ecosystem_for_bypass)

        for pkg in parsed.packages:
            release_info = release_dates.get(pkg.name)
            if release_info is not None:
                release_date, date_source = release_info
            else:
                release_date = None
                date_source = ""

            # Compute trust_level from date_source via SOURCE_TRUST_MAP
            from pkg_defender.db.schema import SOURCE_TRUST_MAP

            trust_level = SOURCE_TRUST_MAP.get(date_source, "unknown")

            # Check if this package has an active bypass
            if (pkg.name, pkg.version or "") in bypassed_packages_cooldown:
                logger.info(
                    "Bypass active for %s@%s -- skipping cooldown check",
                    pkg.name,
                    pkg.version,
                )
                continue

            # Look up per-package threat context for signal escalation
            ctx_for_pkg = None
            if threat_context_map:
                ctx_for_pkg = threat_context_map.get(pkg.name)

            passed, days_remaining = step_check_cooldown(
                release_date,
                config.cooldown,
                pkg.ecosystem or self.manager_name,
                override_hours=_override_hours,
                threat_context=ctx_for_pkg,
                trust_level=trust_level,
            )

            # Compute safe version and clears_at for user-facing messages
            safe_ver: str | None = None
            clears_at: datetime | None = None
            window: int = days_remaining  # defensive init; when release_date is None, days_remaining IS the window
            if not passed and release_date is not None:
                ecosystem = pkg.ecosystem or self.manager_name
                if _override_hours is not None:
                    window = max(1, math.ceil(_override_hours / 24))
                else:
                    window = get_cooldown_window(config.cooldown, ecosystem)
                # Trust penalty widens the displayed window too
                if trust_level == "claimed":
                    window += 2
                clears_at = release_date + timedelta(days=window)

                # Attempt safe version lookup from cache (best-effort)
                try:
                    from pkg_defender.audit.cooldown import find_safe_version
                    from pkg_defender.config import get_db_path
                    from pkg_defender.db.schema import get_all_version_timestamps_for_package, get_connection
                    from pkg_defender.models import VersionInfo

                    db_path = get_db_path()
                    if db_path is not None and isinstance(db_path, Path) and db_path.exists():
                        conn = get_connection(db_path)
                        try:
                            raw_versions = get_all_version_timestamps_for_package(conn, ecosystem, pkg.name)
                            if raw_versions:
                                version_infos = [
                                    VersionInfo(
                                        version=v,
                                        publish_time=datetime.fromisoformat(pt) if pt else None,
                                        ecosystem=ecosystem,
                                        package_name=pkg.name,
                                    )
                                    for v, pt in raw_versions
                                ]
                                raw_ver = find_safe_version(version_infos, window)
                                if raw_ver:
                                    safe_ver = f"{pkg.name}=={raw_ver}"
                        finally:
                            conn.close()
                except Exception:
                    logger.warning("Could not determine safe version for %s", pkg.name, exc_info=True)

            if not passed:
                if parsed.pkgd_flags.get("explain"):
                    from pkg_defender.cli.exec import _print_explain_cooldown

                    ecosystem = pkg.ecosystem or self.manager_name
                    if _override_hours is not None:
                        window = max(1, math.ceil(_override_hours / 24))
                    else:
                        window = get_cooldown_window(config.cooldown, ecosystem)
                    # Trust penalty widens the displayed window too
                    if trust_level == "claimed":
                        window += 2
                    _print_explain_cooldown(
                        package=pkg,
                        release_date=release_date,
                        days_remaining=days_remaining,
                        ecosystem=ecosystem,
                        window_days=window,
                        safe_version=safe_ver,
                        date_source=date_source,
                    )
                logger.info(f"Blocking install of {pkg.name} (cooldown: {days_remaining} days remaining)")
                fail_on_threat = ctx.obj.get("fail_on_threat", True) if ctx.obj else True
                if fail_on_threat:
                    # Guard: dispatcher may not have an adapter in all code paths
                    # (e.g., test setup via __new__ which bypasses __init__).
                    if self.adapter is None:
                        checks: str = "full"
                    else:
                        # Both PARTIAL and FULL tiers now run threat + cooldown
                        checks = "full"
                    # Write audit event before terminal action
                    self._log_audit_event(
                        parsed=parsed,
                        package=pkg,
                        verdict="BLOCKED",
                        exit_code=EXIT_COOLDOWN,
                        cooldown_pass=False,
                        cooldown_days_remaining=days_remaining,
                        start_time_ms=start_time_ms,
                        fail_on_threat_enabled=ctx.obj.get("fail_on_threat", True) if ctx.obj else True,
                        cooldown_enabled=config.cooldown.enabled,
                        coverage_tier=self.adapter.coverage_tier.value if self.adapter else "full",
                    )
                    _adapter_eco_cooldown: str | None = None
                    if self.adapter is not None:
                        _ae = getattr(self.adapter, "ecosystem", None)
                        if isinstance(_ae, str):
                            _adapter_eco_cooldown = _ae
                    block_decision = BlockDecision(
                        reason=BlockReason.COOLDOWN,
                        package=pkg,
                        parsed=parsed,
                        safe_version=safe_ver,
                        clears_at=clears_at,
                        checks_performed=checks,
                        ecosystem=_adapter_eco_cooldown,
                        window_days=window,
                        release_date=release_date,
                        date_source=date_source,
                    )
                    return CooldownCheckResult(
                        passed=False,
                        cooldown_pass=False,
                        cooldown_days_remaining=days_remaining,
                        block_decision=block_decision,
                    )
                else:
                    logger.warning(
                        f"Cooldown not passed for {pkg.name} but fail_on_threat is disabled, proceeding with install"
                    )
                    pkg_version = pkg.version or "latest"
                    click.echo(
                        f"[PKGD] WARNING — {pkg.name}@{pkg_version}",
                        err=True,
                    )
                    click.echo(
                        "[PKGD]   Reason: Cooldown not passed, but fail_on_threat is disabled",
                        err=True,
                    )
                    click.echo(
                        f"[PKGD]   Days remaining: {days_remaining}",
                        err=True,
                    )
                    click.echo(
                        "[PKGD]   Proceeding with install.",
                        err=True,
                    )

        _cooldown_elapsed = (datetime.now(UTC) - _cooldown_start).total_seconds()

        return CooldownCheckResult(passed=True, cooldown_pass=True)

    def _log_audit_event(
        self,
        parsed: ParsedCommand,
        package: PackageRef,
        verdict: str,
        exit_code: int,
        *,
        error_message: str | None = None,
        threat_count_general: int = 0,
        threat_count_versioned: int = 0,
        cooldown_pass: bool = True,
        cooldown_days_remaining: int = 0,
        start_time_ms: int | None = None,
        fail_on_threat_enabled: bool = True,
        cooldown_enabled: bool = True,
        coverage_tier: str = "full",
    ) -> None:
        """Write an audit event to the database, fail-open.

        Args:
            parsed: The parsed command being dispatched.
            package: The package reference for this audit event.
            verdict: Verdict string (PASS, WARN, BLOCKED, ERROR).
            exit_code: Exit code for the verdict.
            error_message: Optional error message.
            threat_count_general: Total threats found.
            threat_count_versioned: Version-specific threats found.
            cooldown_pass: Whether cooldown check passed.
            cooldown_days_remaining: Days remaining in cooldown window.
            start_time_ms: Start timestamp in ms for runtime computation.
            fail_on_threat_enabled: Whether fail-on-threat was active.
            cooldown_enabled: Whether cooldown checking was active.
            coverage_tier: Coverage tier string (full|partial|audit).
        """
        import getpass as _getpass

        from pkg_defender.config import get_db_path
        from pkg_defender.db.schema import insert_audit_event

        logger = logging.getLogger(__name__)
        try:
            db_path = get_db_path()
            if db_path is None or not isinstance(db_path, Path) or not db_path.exists():
                logger.warning("Cannot write audit event: no database found")
                return
            conn = get_connection(db_path)
            try:
                # Compute runtime if we have a start time
                runtime_ms: int | None = None
                if start_time_ms is not None:
                    try:
                        now_ms = int(datetime.now(UTC).timestamp() * 1000)
                        runtime_ms = now_ms - start_time_ms
                    except OSError:
                        pass

                # Safe ecosystem resolution: guard against missing/mock adapter
                _adapter_eco: str | None = None
                if self.adapter is not None:
                    _ae = getattr(self.adapter, "ecosystem", None)
                    if isinstance(_ae, str):
                        _adapter_eco = _ae

                insert_audit_event(
                    conn=conn,
                    ecosystem=package.ecosystem or _adapter_eco or parsed.manager,
                    package_name=package.name,
                    version=package.version or "",
                    action=_INTENT_TO_ACTION.get(parsed.intent, "install"),
                    risk_level="watch",
                    source=parsed.source or "cli",
                    manager=parsed.manager,
                    subcommand=parsed.manager_subcommand,
                    verdict=verdict,
                    exit_code=exit_code,
                    error_message=error_message,
                    threat_count_general=threat_count_general,
                    threat_count_versioned=threat_count_versioned,
                    cooldown_pass=cooldown_pass,
                    cooldown_days_remaining=cooldown_days_remaining,
                    ci_mode=bool(parsed.pkgd_flags.get("ci")),
                    runtime_ms=runtime_ms,
                    user=_getpass.getuser(),
                    session_id=getattr(self, "_session_id", None),
                    fail_on_threat_enabled=fail_on_threat_enabled,
                    cooldown_enabled=cooldown_enabled,
                    coverage_tier=coverage_tier,
                )
            finally:
                conn.close()
        except Exception:
            logger.warning("Failed to write audit event to database", exc_info=True)

    def _log_audit_pass_event(
        self,
        parsed: ParsedCommand,
        threat_result: ThreatCheckResult,
        start_time_ms: int | None,
        *,
        ctx: click.Context | None = None,
        fail_on_threat_enabled: bool = True,
        cooldown_enabled: bool = True,
        coverage_tier: str = "full",
    ) -> None:
        """Write PASS audit events for all packages in a cleared command.

        Used by all three coverage tiers (AUDIT, PARTIAL, FULL) after
        checks pass and the command is cleared for execution.

        Args:
            parsed: The parsed command being dispatched.
            threat_result: Result from the threat check (provides counts).
            start_time_ms: Start timestamp in ms for runtime computation.
            ctx: Click context for config state extraction.
            fail_on_threat_enabled: Whether fail-on-threat was active.
            cooldown_enabled: Whether cooldown checking was active.
            coverage_tier: Coverage tier string (full|partial|audit).
        """
        for pkg in parsed.packages:
            self._log_audit_event(
                parsed=parsed,
                package=pkg,
                verdict="PASS",
                exit_code=0,
                threat_count_general=threat_result.threat_count_general,
                threat_count_versioned=threat_result.threat_count_versioned,
                cooldown_pass=True,
                cooldown_days_remaining=0,
                start_time_ms=start_time_ms,
                fail_on_threat_enabled=fail_on_threat_enabled,
                cooldown_enabled=cooldown_enabled,
                coverage_tier=coverage_tier,
            )
