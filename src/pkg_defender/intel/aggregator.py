"""Feed aggregator — concurrent sync across all intelligence feeds."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp

from pkg_defender.db.schema import (
    get_connection,
    get_feed_state,
    get_feed_stats_history_thread,
    insert_feed_stats_thread,
    insert_threats_bulk,
    retry_on_busy,
    update_feed_state,
)
from pkg_defender.exceptions import FeedSyncError
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import DatabaseConfig, PKGDConfig

logger = logging.getLogger(__name__)

MAX_CONCURRENT_FEEDS = 10  # Board mandate: asyncio.Semaphore
CIRCUIT_BREAKER_THRESHOLD = 3  # Failures before opening circuit
CIRCUIT_BREAKER_COOLDOWN = 3600  # Seconds to wait before retry

# Anomaly detection thresholds (A-037)
ANOMALY_ZERO_RECORD_CONSECUTIVE = 2  # WARN after N consecutive 0-record syncs
ANOMALY_CONFIDENCE_THRESHOLD = 0.2  # WARN if avg confidence below this
ANOMALY_VOLUME_SPIKE_MULTIPLIER = 5.0  # WARN if count > 5x rolling average
ANOMALY_VOLUME_DROP_MULTIPLIER = 0.1  # ERROR if count < 0.1x rolling average
ANOMALY_HISTORY_DAYS = 7  # Rolling average window for volume comparison


def _get_feed_state_thread(
    db_path: Path,
    config: DatabaseConfig | None,
    feed_name: str,
) -> dict[str, str | None] | None:
    """Thread-safe wrapper around get_feed_state.

    Creates its own connection inside the thread (must not receive a
    connection created on the event loop — sqlite3 check_same_thread=True).
    """
    conn = get_connection(db_path, config=config)
    try:
        return get_feed_state(conn, feed_name)
    finally:
        conn.close()


def _update_feed_state_thread(
    db_path: Path,
    config: DatabaseConfig | None,
    feed_name: str,
    cursor: str | None,
    status: str,
    update_last_sync: bool = True,
    error_message: str | None = None,
) -> None:
    """Thread-safe wrapper around update_feed_state.

    Creates its own connection inside the thread (must not receive a
    connection created on the event loop — sqlite3 check_same_thread=True).
    """
    conn = get_connection(db_path, config=config)
    try:
        update_feed_state(
            conn,
            feed_name,
            cursor=cursor,
            status=status,
            update_last_sync=update_last_sync,
            error_message=error_message,
        )
    finally:
        conn.close()


class CircuitState(StrEnum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Skipping feed due to failures
    HALF_OPEN = "half_open"  # Testing if feed recovered


class FeedAggregator:
    """Orchestrates concurrent sync across all intelligence feed sources.

    Board mandates (non-negotiable):
        1. asyncio.gather(*feeds, return_exceptions=True) — one failing feed
           must NOT cancel others.
        2. asyncio.Semaphore(10) — bound concurrent HTTP connections.
        3. Per-feed transaction boundaries — each feed writes in its own
            transaction.
        4. Cursor advancement only after confirmed writes.
        5. Every HTTP call has 5-second timeout (enforced by individual feeds).
        6. Idempotent: safe to re-run without creating duplicates.
        7. Circuit breaker pattern — skip feeds after repeated failures.
    """

    def __init__(
        self,
        feeds: list[FeedSource],
        db_path: Path,
        config: PKGDConfig | None = None,
        retention_days: int | None = None,
    ) -> None:
        self._feeds = feeds
        self._db_path = db_path  # Store path, create connection per coroutine
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_FEEDS)
        self._config = config
        self._retention_days = retention_days
        # Circuit breaker state per feed: feed_name -> {state, failure_count, opened_at}
        self._circuit_state: dict[str, dict[str, Any]] = {}

        # Restore circuit breaker state from DB on (re)start
        try:
            conn = get_connection(self._db_path)
            try:
                rows = conn.execute("SELECT feed_name FROM feed_state WHERE status = 'circuit_open'").fetchall()
                for row in rows:
                    self._circuit_state[row["feed_name"]] = {
                        "state": CircuitState.OPEN,
                        "failure_count": CIRCUIT_BREAKER_THRESHOLD,
                        "graceful_failures": 0,
                        "opened_at": time.time(),
                    }
            finally:
                conn.close()
        except sqlite3.OperationalError:
            pass  # feed_state table doesn't exist yet (first run / fresh DB)

        # Feed metadata captured during sync (feed_name -> metadata dict)
        self._feed_metadata: dict[str, dict[str, Any]] = {}
        # Track consecutive zero-record syncs per feed (A-037)
        self._zero_record_counts: dict[str, int] = {}
        # Track feeds that failed with FAILED status during sync
        self._failed_feeds: dict[str, str] = {}

    def _get_circuit_state(self, feed_name: str) -> dict[str, Any]:
        """Get circuit breaker state for a feed, initializing if needed."""
        if feed_name not in self._circuit_state:
            self._circuit_state[feed_name] = {
                "state": CircuitState.CLOSED,
                "failure_count": 0,
                "graceful_failures": 0,
                "opened_at": None,
            }
        return self._circuit_state[feed_name]

    def _is_circuit_open(self, feed_name: str) -> bool:
        """Check if circuit is open for a feed and handle half-open transition."""
        state = self._get_circuit_state(feed_name)
        circuit = state["state"]

        if circuit == CircuitState.CLOSED:
            return False

        if circuit == CircuitState.OPEN:
            # Check if cooldown has passed
            opened_at = state.get("opened_at")
            if opened_at is not None:
                elapsed = datetime.now(UTC).timestamp() - opened_at
                if elapsed >= CIRCUIT_BREAKER_COOLDOWN:
                    # Transition to half-open to test recovery
                    state["state"] = CircuitState.HALF_OPEN
                    logger.info(
                        "Circuit for feed '%s' entering half-open state (testing recovery)",
                        feed_name,
                    )
                    return False
            return True

        # HALF_OPEN allows one attempt
        return False

    def _record_success(self, feed_name: str) -> None:
        """Record successful sync, close circuit if half-open."""
        state = self._get_circuit_state(feed_name)
        if state["state"] == CircuitState.HALF_OPEN:
            state["state"] = CircuitState.CLOSED
            state["failure_count"] = 0
            state["graceful_failures"] = 0
            logger.info("Circuit for feed '%s' closed after successful recovery", feed_name)
        elif state["state"] == CircuitState.CLOSED:
            # Reset failure counts on success
            state["failure_count"] = 0
            state["graceful_failures"] = 0

    def _check_data_quality(
        self,
        feed_name: str,
        records: list[ThreatRecord],
        history: list[dict[str, Any]] | None = None,
    ) -> float | None:
        """Run anomaly detection checks on a just-synced feed batch.

        Pure in-memory computation — receives pre-queried history data.
        All checks are WARNING/ERROR log only — never blocks ingestion.
        Follows board mandate: "Log anomaly warnings but don't block
        ingestion (data may still be valuable)."

        Returns avg_confidence for the caller to persist via
        ``insert_feed_stats_thread`` (called from ``_sync_feed``).

        Args:
            feed_name: Name of the feed that was synced.
            records: List of records returned by the feed (may be empty).
            history: Pre-queried feed stats history (None if DB query
                failed or was skipped).
        """
        # --- Check 1: Zero-record consecutive count ---
        if len(records) == 0:
            zero_count = self._zero_record_counts.get(feed_name, 0) + 1
            self._zero_record_counts[feed_name] = zero_count
            if zero_count >= ANOMALY_ZERO_RECORD_CONSECUTIVE:
                logger.warning(
                    "Anomaly [zero_record]: Feed '%s' returned 0 records for %d consecutive syncs",
                    feed_name,
                    zero_count,
                )
        else:
            # Reset counter on any non-zero sync
            self._zero_record_counts[feed_name] = 0

        # --- Check 2: Confidence collapse ---
        if len(records) > 0:
            avg_confidence = sum(r.confidence for r in records) / len(records)
            if avg_confidence < ANOMALY_CONFIDENCE_THRESHOLD:
                logger.warning(
                    "Anomaly [confidence_collapse]: Feed '%s' avg confidence %.3f below threshold %.2f (records: %d)",
                    feed_name,
                    avg_confidence,
                    ANOMALY_CONFIDENCE_THRESHOLD,
                    len(records),
                )
        else:
            avg_confidence = None

        # --- Check 3: Volume anomaly vs historical average ---
        if len(records) > 0 and history:
            historical_counts = [h["record_count"] for h in history if h["record_count"] > 0]
            if historical_counts:
                avg_count = sum(historical_counts) / len(historical_counts)
                current_count = len(records)

                # Spike detection
                if current_count > avg_count * ANOMALY_VOLUME_SPIKE_MULTIPLIER:
                    logger.warning(
                        "Anomaly [volume_spike]: Feed '%s' — %d records vs historical avg %d (%.1f× spike)",
                        feed_name,
                        current_count,
                        int(avg_count),
                        current_count / avg_count,
                    )
                # Drop detection (only meaningful when history has >0 records)
                elif current_count < avg_count * ANOMALY_VOLUME_DROP_MULTIPLIER:
                    logger.error(
                        "Anomaly [volume_drop]: Feed '%s' — %d records vs historical avg %d (%.2f× baseline)",
                        feed_name,
                        current_count,
                        int(avg_count),
                        current_count / avg_count,
                    )
        return avg_confidence

    def _record_failure(self, feed_name: str) -> None:
        """Record failed sync, open circuit if threshold exceeded."""
        state = self._get_circuit_state(feed_name)
        state["failure_count"] += 1

        # Any exception breaks the consecutive graceful failure streak
        state["graceful_failures"] = 0

        if state["state"] == CircuitState.HALF_OPEN:
            # Failed recovery attempt — go back to open
            state["state"] = CircuitState.OPEN
            state["opened_at"] = datetime.now(UTC).timestamp()
            logger.warning(
                "Circuit for feed '%s' reopened after failed recovery attempt (failures: %d)",
                feed_name,
                state["failure_count"],
            )
        elif state["failure_count"] >= CIRCUIT_BREAKER_THRESHOLD:
            state["state"] = CircuitState.OPEN
            state["opened_at"] = datetime.now(UTC).timestamp()
            logger.warning(
                "Circuit for feed '%s' opened after %d consecutive failures (cooldown: %ds)",
                feed_name,
                state["failure_count"],
                CIRCUIT_BREAKER_COOLDOWN,
            )

    async def sync_all(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        progress_callback: Callable[[str, int], None] | None = None,
        error_callback: Callable[[str, Exception], None] | None = None,
    ) -> dict[str, int]:
        """Run all enabled feeds concurrently and return per-feed record counts.

        Creates a shared aiohttp.ClientSession if none is provided. Each feed
        runs as an independent coroutine; one feed failure does NOT cancel
        others (return_exceptions=True).

        Args:
            since: Only fetch records modified after this time.
            ecosystems: Filter to specific ecosystems.
            session: Shared aiohttp session (created if None).
            progress_callback: Optional callback called after each feed syncs.
                Receives (feed_name: str, records_count: int).
            error_callback: Optional callback called when a feed fails.
                Receives (feed_name: str, error: Exception).

        Returns:
            Dict mapping feed name to number of threat records synced.
        """
        # Load config if not provided
        if self._config is None:
            from pkg_defender.config import load_config

            self._config = load_config()

        own_session = session is None
        if own_session:
            from pkg_defender.config.settings import get_http_timeout

            timeout_seconds = get_http_timeout(self._config)
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_seconds))

        assert session is not None

        try:
            tasks = [
                self._sync_feed(
                    feed,
                    since,
                    ecosystems,
                    session,
                    progress_callback=progress_callback,
                    error_callback=error_callback,
                )
                for feed in self._feeds
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            summary: dict[str, int] = {}
            for feed, result in zip(self._feeds, results, strict=True):
                if isinstance(result, BaseException):
                    logger.error("Feed %s failed: %s", feed.name, result)
                    logger.debug("Feed %s failed — full traceback:", feed.name, exc_info=result)
                    summary[feed.name] = 0
                else:
                    assert isinstance(result, tuple)
                    name, count = result
                    summary[name] = count

            return summary
        finally:
            if own_session:
                await session.close()

    @staticmethod
    @retry_on_busy(max_retries=3)
    def _sync_feed_db_ops(
        db_path: Path,
        config: DatabaseConfig | None,
        feed: FeedSource,
        records: list[ThreatRecord],
        effective_since: datetime | None,
        feed_name: str,
        retention_days: int | None = None,
    ) -> int:
        """Perform all synchronous SQLite operations for a single feed sync.

        This method creates its own SQLite connection (must run in a worker
        thread via ``asyncio.to_thread()`` to avoid blocking the event loop).
        The connection is closed before returning.

        Args:
            db_path: Path to the SQLite database file.
            config: Optional DatabaseConfig for PRAGMA settings.
            feed: The feed source being synced.
            records: Deduplicated threat records to insert.
            effective_since: Effective sync cursor timestamp.
            feed_name: Name of the feed being synced.
            retention_days: Number of days to retain threat records. Records
                with last_seen older than this are deleted after each feed sync.
                None (default) = feature disabled — no automatic pruning.

        Returns:
            Number of threat records successfully inserted (post-validation).

        Raises:
            Exception: On DB write failure (caller handles rollback).
        """
        conn = get_connection(db_path, config=config)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                inserted = insert_threats_bulk(conn, records, commit=False)

                if len(records) > 0:
                    cursor_value = None
                    if feed.supports_incremental:
                        cursor_value = datetime.now(UTC).isoformat()
                    elif effective_since is not None:
                        cursor_value = effective_since.isoformat()

                    update_feed_state(
                        conn,
                        feed_name,
                        cursor=cursor_value,
                        status="idle",
                        update_last_sync=True,
                        commit=False,
                    )
                else:
                    existing_state = get_feed_state(conn, feed_name)
                    existing_cursor = existing_state.get("cursor") if existing_state else None
                    update_feed_state(
                        conn,
                        feed_name,
                        cursor=existing_cursor,
                        status="idle",
                        update_last_sync=True,
                        commit=False,
                    )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

            # Prune threats older than retention_days (opt-in via config)
            if retention_days is not None:
                cursor = conn.execute(
                    "DELETE FROM threats WHERE last_seen < datetime('now', '-' || ? || ' days')",
                    (retention_days,),
                )
                deleted = cursor.rowcount
                conn.commit()
                if deleted > 0:
                    logger.info("Pruned %d threat record(s) older than %d day(s)", deleted, retention_days)

            skipped = len(records) - inserted
            if skipped > 0:
                logger.warning(
                    "Feed '%s': %d of %d records skipped by validation (%.1f%% loss rate)",
                    feed_name,
                    skipped,
                    len(records),
                    (skipped / len(records)) * 100 if len(records) > 0 else 0.0,
                )
            return inserted
        finally:
            conn.close()

    async def _sync_feed(
        self,
        feed: FeedSource,
        since: datetime | None,
        ecosystems: list[str] | None,
        session: aiohttp.ClientSession,
        progress_callback: Callable[[str, int], None] | None = None,
        error_callback: Callable[[str, Exception], None] | None = None,
    ) -> tuple[str, int]:
        """Sync a single feed with semaphore-bounded concurrency.

        Acquires the semaphore, fetches records, writes them to the DB in
        per-record transactions (INSERT OR REPLACE for idempotency), then
        advances the cursor only after confirmed writes.

        Args:
            feed: The feed source to sync.
            since: Only fetch records modified after this time.
            ecosystems: Filter to specific ecosystems.
            session: Shared aiohttp session.
            progress_callback: Optional callback called after each feed syncs.
                Receives (feed_name: str, records_count: int).
            error_callback: Optional callback called when a feed fails.
                Receives (feed_name: str, error: Exception).

        Returns:
            Tuple of (feed_name, record_count).
        """
        # Check if feed is configured before attempting sync.
        # (Config check is pure Python — fast, no I/O.)
        if self._config is not None and not feed.is_configured(self._config):
            logger.info(
                "Feed '%s' is not configured — skipping sync (set status to not_configured)",
                feed.name,
            )
            # Update state to not_configured (offloaded to thread)
            await asyncio.to_thread(
                _update_feed_state_thread,
                self._db_path,
                self._config.database if self._config is not None else None,
                feed.name,
                cursor=None,
                status="not_configured",
                update_last_sync=False,
            )
            if progress_callback is not None:
                progress_callback(feed.name, 0)
            return (feed.name, 0)

        # Check circuit breaker before attempting sync.
        # (Circuit state is in-memory — fast, no I/O.)
        if self._is_circuit_open(feed.name):
            logger.warning(
                "Circuit open for feed '%s' — skipping sync (cooldown in progress)",
                feed.name,
            )
            # Update state to circuit_open (offloaded to thread)
            await asyncio.to_thread(
                _update_feed_state_thread,
                self._db_path,
                self._config.database if self._config is not None else None,
                feed.name,
                cursor=None,
                status="circuit_open",
                update_last_sync=False,
            )
            # Return 0 but don't count as failure (circuit will test itself)
            if progress_callback is not None:
                progress_callback(feed.name, 0)
            return (feed.name, 0)

        async with self._semaphore:
            try:
                # Determine sync cursor (offloaded to thread)
                effective_since = since
                if feed.supports_incremental:
                    state = await asyncio.to_thread(
                        _get_feed_state_thread,
                        self._db_path,
                        self._config.database if self._config is not None else None,
                        feed.name,
                    )
                    cursor_str = state.get("cursor") if state else None
                    if cursor_str:
                        with contextlib.suppress(ValueError, TypeError):
                            effective_since = datetime.fromisoformat(cursor_str)

                # Fetch records from feed
                # OSV (and other bulk download feeds) need longer timeouts than
                # the 5-second session provides. Pass None to let them create
                # their own session with appropriate timeout.
                feed_session = None if feed.name == "osv" else session
                fetch_kwargs: dict[str, Any] = {
                    "since": effective_since,
                    "ecosystems": ecosystems,
                    "session": feed_session,
                    "config": self._config,
                }
                # Pass db_path and progress_callback only to feeds that accept them
                if feed.name == "ossf_malicious":
                    fetch_kwargs["db_path"] = self._db_path
                raw_result = await feed.fetch(**fetch_kwargs)

                # Backward compat: handle legacy feeds that return bare list[ThreatRecord]
                if isinstance(raw_result, list):
                    raw_result = FeedFetchResult(records=raw_result, feed_metadata={})

                # Check if the fetch returned FAILED status
                if raw_result.status == FetchStatus.FAILED:
                    error_msg = raw_result.feed_metadata.get("error", "Unknown error")
                    self._failed_feeds[feed.name] = error_msg
                    self._feed_metadata[feed.name] = raw_result.feed_metadata
                    logger.warning(
                        "Feed '%s' fetch returned FAILED status: %s",
                        feed.name,
                        error_msg,
                    )

                    # Update feed_state — cursor is NOT advanced on failure
                    # to ensure the failed data window is retried.
                    # last_sync is NOT updated here — preserving the
                    # previous successful sync timestamp is intentional
                    # so downstream consumers can detect freshness gaps.
                    await asyncio.to_thread(
                        _update_feed_state_thread,
                        self._db_path,
                        self._config.database if self._config is not None else None,
                        feed.name,
                        cursor=None,
                        status="error",
                        error_message=error_msg,
                        update_last_sync=False,
                    )

                    # Track consecutive graceful failures for circuit breaker.
                    # Directly manipulate circuit state at threshold — do NOT
                    # call _record_failure() which checks failure_count, not
                    # graceful_failures.
                    circuit = self._get_circuit_state(feed.name)
                    circuit["graceful_failures"] += 1
                    if circuit["graceful_failures"] >= CIRCUIT_BREAKER_THRESHOLD:
                        circuit["state"] = CircuitState.OPEN
                        circuit["opened_at"] = datetime.now(UTC).timestamp()
                        circuit["graceful_failures"] = 0  # Reset for next cycle
                        logger.warning(
                            "Circuit breaker OPEN for feed '%s' after %d graceful failures",
                            feed.name,
                            CIRCUIT_BREAKER_THRESHOLD,
                        )

                    if progress_callback is not None:
                        progress_callback(feed.name, -1)

                    if error_callback is not None:
                        try:
                            error_callback(
                                feed.name,
                                FeedSyncError(feed.name, error_msg),
                            )
                        except Exception:
                            logger.exception(
                                "error_callback raised for feed %s",
                                feed.name,
                            )

                    return (feed.name, 0)

                # Extract records and metadata from FeedFetchResult
                records = raw_result.records
                self._feed_metadata[feed.name] = raw_result.feed_metadata

                # Clear any previous failure tracking on success
                self._failed_feeds.pop(feed.name, None)

                records = self._deduplicate(records)

                # Offload all blocking SQLite operations to a thread to
                # avoid stalling the event loop during concurrent feed sync.
                # _sync_feed_db_ops creates its own connection (must not use
                # the main-thread conn — sqlite3 defaults check_same_thread=True).
                inserted = await asyncio.to_thread(
                    self._sync_feed_db_ops,
                    self._db_path,
                    self._config.database if self._config is not None else None,
                    feed,
                    records,
                    effective_since,
                    feed.name,
                    retention_days=self._retention_days,
                )
                skipped = len(records) - inserted

                self._record_success(feed.name)

                # Run data quality checks (anomaly detection — A-037).
                # DB queries (get_feed_stats_history, insert_feed_stats) are
                # offloaded to threads. _check_data_quality itself is pure
                # in-memory and stays on the event loop.
                # Skip for tree SHA cache hits — not a real data quality issue
                feed_meta = self._feed_metadata.get(feed.name, {})
                if not feed_meta.get("tree_sha_hit"):
                    try:
                        history = await asyncio.to_thread(
                            get_feed_stats_history_thread,
                            self._db_path,
                            feed.name,
                            days=ANOMALY_HISTORY_DAYS,
                            config=self._config.database if self._config is not None else None,
                        )
                        avg_confidence = self._check_data_quality(feed.name, records, history)
                        await asyncio.to_thread(
                            insert_feed_stats_thread,
                            self._db_path,
                            feed.name,
                            inserted,
                            avg_confidence,
                            skipped_count=skipped,
                            config=self._config.database if self._config is not None else None,
                        )
                    except Exception:
                        logger.error(
                            "Data quality check failed for feed '%s' — anomaly detection degraded",
                            feed.name,
                        )
                        logger.debug(
                            "Data quality check failed for feed '%s' — full traceback:",
                            feed.name,
                            exc_info=True,
                        )

                if progress_callback is not None:
                    progress_callback(feed.name, inserted)

                return (feed.name, inserted)

            except Exception as exc:
                feed_name = feed.name
                logger.error("Feed %s sync failed: %s", feed_name, exc)
                self._failed_feeds[feed_name] = str(exc)
                self._record_failure(feed_name)

                # Attempt to persist error state to DB (best-effort)
                try:
                    await asyncio.to_thread(
                        _update_feed_state_thread,
                        self._db_path,
                        self._config.database if self._config is not None else None,
                        feed_name,
                        cursor=None,
                        status="error",
                        error_message=str(exc),
                        update_last_sync=False,
                    )
                except Exception:
                    logger.warning(
                        "Failed to persist error state for feed '%s' — feed_state remains at previous value",
                        feed_name,
                    )

                if error_callback is not None:
                    try:
                        error_callback(feed_name, exc)
                    except Exception:
                        logger.exception(
                            "error_callback raised for feed %s",
                            feed_name,
                        )

                # Inform user AFTER state updates
                if progress_callback is not None:
                    progress_callback(feed_name, -1)

                raise

    def _deduplicate(self, records: list[ThreatRecord]) -> list[ThreatRecord]:
        """Deduplicate threat records within a single feed's batch.

        Groups by (ecosystem, package_name, source, source_id). For duplicates:
        keeps latest last_seen, highest hit_count, most complete data.

        Args:
            records: List of potentially duplicate ThreatRecord objects.

        Returns:
            Deduplicated list of ThreatRecord objects.
        """
        seen: dict[tuple[str, str | None, str, str | None], ThreatRecord] = {}
        for record in records:
            key = (
                record.ecosystem,
                record.package_name,
                record.source,
                record.source_id,
            )
            if key in seen:
                existing = seen[key]
                first_seen = min(existing.first_seen, record.first_seen)
                last_seen = max(existing.last_seen, record.last_seen)
                all_versions = list(set(existing.affected_versions + record.affected_versions))
                all_ranges = list(set(existing.affected_ranges + record.affected_ranges))
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
                severity = (
                    existing.severity
                    if severity_order.get(existing.severity, 0) >= severity_order.get(record.severity, 0)
                    else record.severity
                )
                confidence = max(existing.confidence, record.confidence)
                hit_count = existing.hit_count + record.hit_count
                summary = existing.summary if len(existing.summary) >= len(record.summary) else record.summary
                detail_url = existing.detail_url or record.detail_url
                is_malicious = existing.is_malicious or record.is_malicious
                is_unverified = existing.is_unverified or record.is_unverified
                cvss_score = existing.cvss_score if existing.cvss_score is not None else record.cvss_score

                seen[key] = ThreatRecord(
                    id=existing.id,
                    ecosystem=existing.ecosystem,
                    package_name=existing.package_name,
                    affected_versions=all_versions,
                    affected_ranges=all_ranges,
                    severity=severity,
                    confidence=confidence,
                    source=existing.source,
                    source_id=existing.source_id,
                    summary=summary,
                    detail_url=detail_url,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    hit_count=hit_count,
                    cvss_score=cvss_score,
                    published_at=existing.published_at or record.published_at,
                    ingested_at=record.ingested_at,
                    is_malicious=is_malicious,
                    is_unverified=is_unverified,
                )
            else:
                seen[key] = record
        return list(seen.values())

    def get_sync_summary(self) -> dict[str, dict[str, Any]]:
        """Query feed_state table for all feeds and return their sync status."""
        conn = get_connection(
            self._db_path,
            config=self._config.database if self._config is not None else None,
        )
        try:
            rows = conn.execute("SELECT feed_name, last_sync, cursor, status, error_message FROM feed_state").fetchall()

            result: dict[str, dict[str, Any]] = {}
            for row in rows:
                result[row[0]] = {
                    "last_sync": row[1],
                    "cursor": row[2],
                    "status": row[3],
                    "error_message": row[4],
                }
            return result
        finally:
            conn.close()

    def get_feed_metadata(self) -> dict[str, dict[str, Any]]:
        """Get feed metadata captured during sync.

        Returns:
            Dict mapping feed name to metadata (e.g., ecosystem_results for OSV).
        """
        return self._feed_metadata.copy()

    def get_failed_feeds(self) -> dict[str, str]:
        """Get feeds that failed during the last sync, with their error messages.

        Returns:
            Dict mapping feed name to error message for feeds whose fetch()
            returned FAILED status.
        """
        return self._failed_feeds.copy()

    def sync_has_errors(self) -> bool:
        """Check if any feeds failed during the last sync.

        Returns:
            True if at least one feed returned FAILED status.
        """
        return len(self._failed_feeds) > 0


class OSVFeedAdapter(FeedSource):
    """Wraps the standalone OSV functions into the FeedSource interface.

    The OSV feed in intel/feeds/osv.py uses standalone functions rather than
    the FeedSource ABC. This adapter bridges the gap so the aggregator can
    treat OSV uniformly with other feed sources.

    Uses bulk data dumps from OSV for comprehensive vulnerability data.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "osv"

    @property
    def supports_incremental(self) -> bool:
        """OSV supports incremental via dump timestamps (not yet implemented)."""
        return False  # Full dumps only for now

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if OSV feed is configured.

        OSV is a public API, always configured.

        Args:
            config: The current configuration object.

        Returns:
            True — OSV is a public API.
        """
        return True

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch vulnerabilities from OSV bulk data dumps.

        Downloads the full dump for each ecosystem and returns parsed
        vulnerability records. This is comprehensive but slower than
        the query API.

        Args:
            since: Ignored — OSV dumps don't support time filtering directly.
            ecosystems: Filter to specific ecosystems (e.g. ``["npm", "pypi"]``).
            session: Shared aiohttp session.
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with records and feed_metadata (ecosystem_results).
        """
        from pkg_defender.cli._progress import download_progress
        from pkg_defender.intel.feeds.osv import fetch_from_dump

        logger.info("Fetching OSV vulnerabilities from bulk dumps")
        try:
            with download_progress(f"Downloading {self.name}...") as progress_callback:
                return await fetch_from_dump(
                    ecosystems=ecosystems,
                    session=session,
                    config=config,
                    progress_callback=progress_callback,
                )
        except Exception as e:
            logger.warning("Failed to fetch OSV from dumps: %s", e)
            return FeedFetchResult(
                records=[],
                feed_metadata={
                    "ecosystem_results": [
                        {
                            "ecosystem": "all",
                            "count": 0,
                            "url": "",
                            "status": "failed",
                            "error": str(e),
                        }
                    ]
                },
                status=FetchStatus.FAILED,
            )

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Check a single package@version against OSV.

        Args:
            package: Package name.
            version: Package version.
            ecosystem: Ecosystem identifier.
            session: Shared aiohttp session.
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with matching ThreatRecord objects.
        """
        from pkg_defender.intel.feeds.osv import check_package

        records = await check_package(ecosystem, package, version, session=session)
        return FeedFetchResult(records=records, feed_metadata={})
