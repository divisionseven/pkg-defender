"""Tests for the FeedAggregator and OSVFeedAdapter."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from pkg_defender.config.settings import PKGDConfig
from pkg_defender.db.schema import (
    SCHEMA_SQL,
    get_feed_state,
    get_feed_stats_history,
    init_db,
    insert_feed_stats,
)
from pkg_defender.intel.aggregator import (
    CIRCUIT_BREAKER_THRESHOLD,
    MAX_CONCURRENT_FEEDS,
    CircuitState,
    FeedAggregator,
    OSVFeedAdapter,
)
from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_threat(
    *,
    id: str = "test:001",
    ecosystem: str = "npm",
    package_name: str = "lodash",
    source: str = "osv",
    source_id: str = "CVE-2025-0001",
    severity: str = "HIGH",
    confidence: float = 0.85,
    summary: str = "Test vulnerability",
    affected_versions: list[str] | None = None,
    affected_ranges: list[str] | None = None,
    hit_count: int = 1,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> ThreatRecord:
    now = datetime.now(UTC)
    return ThreatRecord(
        id=id,
        ecosystem=ecosystem,
        package_name=package_name,
        affected_versions=affected_versions or [],
        affected_ranges=affected_ranges or [],
        severity=severity,
        confidence=confidence,
        source=source,
        source_id=source_id,
        summary=summary,
        detail_url=f"https://example.com/{id}",
        first_seen=first_seen or now,
        last_seen=last_seen or now,
        hit_count=hit_count,
    )


class _MockFeed(FeedSource):
    """A mock feed that returns pre-set records."""

    def __init__(
        self,
        name: str,
        records: list[ThreatRecord] | None = None,
        *,
        should_fail: bool = False,
        fail_exception: Exception | None = None,
        fetch_delay: float = 0.0,
        supports_incremental: bool = True,
        fail_status: bool = False,
    ) -> None:
        self._name = name
        self._records = records or []
        self._should_fail = should_fail
        self._fail_exception = fail_exception or RuntimeError(f"Feed {name} failed")
        self._fetch_delay = fetch_delay
        self._supports_incremental = supports_incremental
        self._fail_status = fail_status

    @property
    def name(self) -> str:
        return self._name

    @property
    def supports_incremental(self) -> bool:
        return self._supports_incremental

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: Any = None,
    ) -> FeedFetchResult:
        if self._fetch_delay:
            await asyncio.sleep(self._fetch_delay)
        if self._fail_status:
            return FeedFetchResult(records=[], feed_metadata={"error": "Simulated failure"}, status=FetchStatus.FAILED)
        if self._should_fail:
            raise self._fail_exception
        return FeedFetchResult(records=list(self._records), feed_metadata={})

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: Any = None,
    ) -> FeedFetchResult:
        return FeedFetchResult(records=[], feed_metadata={})

    def is_configured(self, config: Any) -> bool:
        return True


class _SemaphoreTrackingFeed(FeedSource):
    """A mock feed that tracks how many feeds run concurrently."""

    _active: int = 0
    _max_active: int = 0
    _lock: asyncio.Lock

    def __init__(self, name: str, delay: float = 0.05) -> None:
        self._name = name
        self._delay = delay
        # Class-level tracking
        if not hasattr(_SemaphoreTrackingFeed, "_lock"):
            _SemaphoreTrackingFeed._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return self._name

    @property
    def supports_incremental(self) -> bool:
        return False

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        async with _SemaphoreTrackingFeed._lock:
            _SemaphoreTrackingFeed._active += 1
            if _SemaphoreTrackingFeed._active > _SemaphoreTrackingFeed._max_active:
                _SemaphoreTrackingFeed._max_active = _SemaphoreTrackingFeed._max_active

        try:
            await asyncio.sleep(self._delay)
            return FeedFetchResult(records=[], feed_metadata={})
        finally:
            async with _SemaphoreTrackingFeed._lock:
                _SemaphoreTrackingFeed._active -= 1

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        return FeedFetchResult(records=[], feed_metadata={})

    def is_configured(self, config: PKGDConfig | None) -> bool:
        return True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path() -> Generator[Path, None, None]:
    """Temp file path for SQLite database."""
    import tempfile

    # Create temp file, close it so SQLite can use it
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        path = Path(tmp_file.name)

    yield path

    # Cleanup after test
    path.unlink(missing_ok=True)


@pytest.fixture()
def conn(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Temp file SQLite database with schema initialized."""
    c = sqlite3.connect(str(db_path))
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA cache_size=-80000")
    c.execute("PRAGMA temp_store=MEMORY")
    c.executescript(SCHEMA_SQL)
    c.commit()
    yield c
    c.close()


# ---------------------------------------------------------------------------
# Tests: sync_all with mocked feeds
# ---------------------------------------------------------------------------


class TestSyncAll:
    """Tests for FeedAggregator.sync_all()."""

    async def test_syncs_single_feed(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """A single feed returns its record count."""
        records = [_make_threat(id="osv:GHSA-0001")]
        feed = _MockFeed("test-feed", records)
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all()

        assert summary == {"test-feed": 1}

        # Verify record was written
        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("osv:GHSA-0001",)).fetchone()
        assert row is not None

    async def test_invokes_bulk_insert_on_sync(self, conn: sqlite3.Connection, db_path: Path, mocker: Any) -> None:
        """sync_all() calls insert_threats_bulk() instead of per-record insert_threat()."""
        from pkg_defender.db.schema import insert_threats_bulk as real_bulk

        spy = mocker.patch(
            "pkg_defender.intel.aggregator.insert_threats_bulk",
            side_effect=real_bulk,
        )

        records = [_make_threat(id="osv:GHSA-bulk-01")]
        feed = _MockFeed("test-bulk-feed", records)
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all()

        assert summary == {"test-bulk-feed": 1}
        spy.assert_called_once()

        # Verify the record was actually written (real function ran via side_effect)
        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("osv:GHSA-bulk-01",)).fetchone()
        assert row is not None

    async def test_syncs_multiple_feeds(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Multiple feeds each return their counts independently."""
        feed_a = _MockFeed(
            "feed-a",
            [
                _make_threat(id="a:1", source_id="a-1"),
                _make_threat(id="a:2", source_id="a-2"),
            ],
        )
        feed_b = _MockFeed("feed-b", [_make_threat(id="b:1", source_id="b-1")])
        feed_c = _MockFeed("feed-c", [])
        agg = FeedAggregator([feed_a, feed_b, feed_c], db_path)

        summary = await agg.sync_all()

        assert summary == {"feed-a": 2, "feed-b": 1, "feed-c": 0}

    async def test_one_feed_failure_does_not_cancel_others(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Board mandate: return_exceptions=True — one failing feed must NOT
        cancel others."""
        good_records = [_make_threat(id="good:1")]
        good_feed = _MockFeed("good-feed", good_records)
        bad_feed = _MockFeed("bad-feed", should_fail=True, fail_exception=RuntimeError("API down"))
        agg = FeedAggregator([good_feed, bad_feed], db_path)

        summary = await agg.sync_all()

        # Good feed succeeded
        assert summary["good-feed"] == 1
        # Bad feed reported 0 (not re-raised)
        assert summary["bad-feed"] == 0

        # Good feed's records are in DB
        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("good:1",)).fetchone()
        assert row is not None

    async def test_all_feeds_fail_returns_all_zeros(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When all feeds fail, summary shows 0 for each."""
        feed_a = _MockFeed("a", should_fail=True)
        feed_b = _MockFeed("b", should_fail=True)
        agg = FeedAggregator([feed_a, feed_b], db_path)

        summary = await agg.sync_all()

        assert summary == {"a": 0, "b": 0}

    async def test_empty_feed_list(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """No feeds → empty summary."""
        agg = FeedAggregator([], db_path)
        summary = await agg.sync_all()
        assert summary == {}


# ---------------------------------------------------------------------------
# Tests: FetchStatus.FAILED handling
# ---------------------------------------------------------------------------


class TestFailedStatus:
    """Tests for feeds that return FetchStatus.FAILED instead of raising."""

    async def test_failed_status_feed_updates_failed_feeds(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """A failed-status feed appears in get_failed_feeds() but a successful one does not."""
        failed_feed = _MockFeed("failed-feed", should_fail=False, fail_status=True)
        good_feed = _MockFeed("good-feed", [_make_threat(id="good:1")])
        agg = FeedAggregator([failed_feed, good_feed], db_path)

        await agg.sync_all()

        failed_feeds = agg.get_failed_feeds()
        assert "failed-feed" in failed_feeds
        assert "good-feed" not in failed_feeds

    async def test_failed_status_feed_does_not_write_threats(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """FAILED status prevents any threat records from being written to DB."""
        records = [_make_threat(id="fail:1")]
        feed = _MockFeed("failed-feed", records, fail_status=True)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()

        # No threats should have been written
        count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 0

    async def test_failed_status_feed_does_not_cancel_others(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """One feed returning FAILED status does not cancel or affect other feeds."""
        failed_feed = _MockFeed("failed-feed", [_make_threat(id="fail:1")], fail_status=True)
        good_a = _MockFeed("good-a", [_make_threat(id="a:1")])
        good_b = _MockFeed("good-b", [_make_threat(id="b:1")])
        agg = FeedAggregator([failed_feed, good_a, good_b], db_path)

        await agg.sync_all()

        # Good feeds' records should be in DB
        row_a = conn.execute("SELECT id FROM threats WHERE id = ?", ("a:1",)).fetchone()
        assert row_a is not None, "feed good-a records should be in DB"
        row_b = conn.execute("SELECT id FROM threats WHERE id = ?", ("b:1",)).fetchone()
        assert row_b is not None, "feed good-b records should be in DB"

        # Failed feed's records should NOT be in DB
        row_fail = conn.execute("SELECT id FROM threats WHERE id = ?", ("fail:1",)).fetchone()
        assert row_fail is None, "failed feed records should NOT be in DB"

    async def test_sync_has_errors_returns_true_when_feeds_fail(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """sync_has_errors() returns True when a feed returns FAILED status."""
        feed = _MockFeed("failed-feed", fail_status=True)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()

        assert agg.sync_has_errors() is True

    async def test_sync_has_errors_returns_false_when_all_succeed(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """sync_has_errors() returns False when all feeds succeed."""
        feed_a = _MockFeed("feed-a", [_make_threat(id="a:1")])
        feed_b = _MockFeed("feed-b", [_make_threat(id="b:1")])
        agg = FeedAggregator([feed_a, feed_b], db_path)

        await agg.sync_all()

        assert agg.sync_has_errors() is False

    async def test_failed_status_preserves_last_sync(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When a feed returns FetchStatus.FAILED, last_sync from previous
        successful sync is preserved (not overwritten to current time)."""
        from pkg_defender.db.schema import get_feed_state, update_feed_state

        # Step 1: Simulate a successful sync at 10:00:00
        last_sync_time = "2026-04-07 10:00:00"
        update_feed_state(
            conn,
            "test-feed",
            cursor="2026-04-07T10:00:00+00:00",
            status="idle",
            update_last_sync=True,
        )
        conn.execute(
            "UPDATE feed_state SET last_sync = ? WHERE feed_name = ?",
            (last_sync_time, "test-feed"),
        )
        conn.commit()

        # Verify initial state
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["last_sync"] == last_sync_time

        # Step 2: Create a feed that returns FetchStatus.FAILED (NOT an exception)
        feed = _MockFeed("test-feed", fail_status=True)
        agg = FeedAggregator([feed], db_path)

        # Step 3: Trigger sync — should fail with status "error"
        await agg.sync_all()

        # Step 4: Verify last_sync is preserved, NOT overwritten to current time
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["status"] == "error", "Status should be error"
        assert state["error_message"] is not None
        assert state["last_sync"] == last_sync_time, (
            f"last_sync should be preserved as {last_sync_time}, not overwritten"
        )


# ---------------------------------------------------------------------------
# Tests: Stale threat cleanup (DELETE after sync)
# ---------------------------------------------------------------------------


class TestStaleThreatCleanup:
    """Tests for stale threat pruning in ``_sync_feed``.

    After each sync completes, threats with ``last_seen`` older than 30 days
    are deleted. These tests verify that pruning:
    - Removes old threats (>30 days)
    - Preserves recent threats (<=30 days)
    - Is idempotent across multiple syncs
    """

    async def test_stale_threats_pruned_after_sync(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """Threats not seen in 30+ days are pruned after a sync.

        Root cause: aggregator.py:539-541 (DELETE query after sync commit).
        Before the fix, threats accumulated indefinitely.
        This test FAILS before the fix (stale threat survives) and
        PASSES after (stale threat deleted).

        Scenario: A threat with ``last_seen`` = 60 days ago exists in the DB.
        Expected: After ``sync_all()``, the stale threat is deleted.
        Previously: It persisted indefinitely.
        """
        conn.execute(
            """INSERT INTO threats
               (id, ecosystem, package_name, severity, confidence,
                source, source_id, summary, detail_url,
                first_seen, last_seen)
               VALUES (?, 'npm', 'lodash', 'HIGH', 0.85,
                       'osv', 'CVE-OLD', 'old threat', 'https://ex.com',
                       datetime('now', '-70 days'), datetime('now', '-60 days'))""",
            ("stale:prune-001",),
        )
        conn.commit()

        feed = _MockFeed("test-feed", [])
        agg = FeedAggregator([feed], db_path, retention_days=30)
        await agg.sync_all()

        count = conn.execute("SELECT COUNT(*) FROM threats WHERE id = ?", ("stale:prune-001",)).fetchone()[0]
        assert count == 0, "Stale threat (>30 days) should be deleted"

    async def test_recent_threats_not_pruned(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """Threats seen within 30 days survive the cleanup."""
        conn.execute(
            """INSERT INTO threats
               (id, ecosystem, package_name, severity, confidence,
                source, source_id, summary, detail_url,
                first_seen, last_seen)
               VALUES (?, 'npm', 'lodash', 'HIGH', 0.85,
                       'osv', 'CVE-FRESH', 'fresh threat', 'https://ex.com',
                       datetime('now'), datetime('now'))""",
            ("fresh:keep-001",),
        )
        conn.commit()

        feed = _MockFeed("test-feed", [])
        agg = FeedAggregator([feed], db_path, retention_days=30)
        await agg.sync_all()

        count = conn.execute("SELECT COUNT(*) FROM threats WHERE id = ?", ("fresh:keep-001",)).fetchone()[0]
        assert count == 1, "Recent threat (<=30 days) should survive"

    @pytest.mark.parametrize(
        "age_days,threat_id,expected_count",
        [
            (1, "age:001d", 1),
            (10, "age:010d", 1),
            (20, "age:020d", 1),
            (29, "age:029d", 1),
            (31, "age:031d", 0),
            (60, "age:060d", 0),
        ],
    )
    async def test_cleanup_idempotent(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        age_days: int,
        threat_id: str,
        expected_count: int,
    ) -> None:
        """Cleanup is idempotent — multiple syncs don't delete extra threats.

        Boundary: threats at 1, 10, 20, 29 days old survive (<=30).
        Threats at 31, 60 days old are deleted (>30).
        """
        conn.execute(
            f"""INSERT INTO threats
               (id, ecosystem, package_name, severity, confidence,
                source, source_id, summary, detail_url,
                first_seen, last_seen)
               VALUES (?, 'npm', 'lodash', 'HIGH', 0.85,
                       'osv', ?, 'aged threat', 'https://ex.com',
                       datetime('now', '-{age_days + 1} days'),
                       datetime('now', '-{age_days} days'))""",
            (threat_id, f"CVE-{age_days:03d}"),
        )
        conn.commit()

        feed = _MockFeed("test-feed", [])
        agg = FeedAggregator([feed], db_path, retention_days=30)
        # Run sync twice to verify idempotency
        await agg.sync_all()
        await agg.sync_all()

        count = conn.execute("SELECT COUNT(*) FROM threats WHERE id = ?", (threat_id,)).fetchone()[0]
        assert count == expected_count, f"Threat aged {age_days}d: expected {expected_count}, got {count}"

    async def test_pruning_disabled_when_retention_none(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When retention_days=None, old threats survive sync."""
        conn.execute(
            """INSERT INTO threats
               (id, ecosystem, package_name, severity, confidence,
                source, source_id, summary, detail_url,
                first_seen, last_seen)
               VALUES (?, 'npm', 'lodash', 'HIGH', 0.85,
                       'osv', 'CVE-AGED', 'aged threat', 'https://ex.com',
                       datetime('now', '-70 days'), datetime('now', '-60 days'))""",
            ("aged:no-prune-001",),
        )
        conn.commit()

        feed = _MockFeed("test-feed", [])
        agg = FeedAggregator([feed], db_path, retention_days=None)
        await agg.sync_all()

        count = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE id = ?",
            ("aged:no-prune-001",),
        ).fetchone()[0]
        assert count == 1, "Old threat must survive when retention_days=None"


# ---------------------------------------------------------------------------
# Tests: per-feed transaction isolation
# ---------------------------------------------------------------------------


class TestTransactionIsolation:
    """Per-feed transaction boundaries — one feed's error doesn't roll back
    another's writes."""

    async def test_feed_a_writes_survive_feed_b_error(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When feed B fails after feed A has written, feed A's records persist."""
        feed_a_records = [
            _make_threat(id="a:1", source_id="a-1"),
            _make_threat(id="a:2", source_id="a-2"),
            _make_threat(id="a:3", source_id="a-3"),
        ]
        feed_a = _MockFeed("feed-a", feed_a_records)
        feed_b = _MockFeed(
            "feed-b",
            should_fail=True,
            fail_exception=ConnectionError("timeout"),
        )
        agg = FeedAggregator([feed_a, feed_b], db_path)

        await agg.sync_all()

        # All of feed A's records must be in DB
        for i in range(1, 4):
            row = conn.execute("SELECT id FROM threats WHERE id = ?", (f"a:{i}",)).fetchone()
            assert row is not None, f"Record a:{i} should be in DB"

        # Feed B should have an error state
        state = get_feed_state(conn, "feed-b")
        assert state is not None
        assert state["status"] == "error"
        assert "timeout" in (state["error_message"] or "")

    async def test_feed_a_writes_even_if_feed_b_fails_first(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Even if feed B is first in the list and fails, feed A still writes."""
        feed_b = _MockFeed("feed-b", should_fail=True)
        feed_a = _MockFeed("feed-a", [_make_threat(id="a:1")])
        agg = FeedAggregator([feed_b, feed_a], db_path)

        summary = await agg.sync_all()

        assert summary["feed-a"] == 1
        assert summary["feed-b"] == 0

        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("a:1",)).fetchone()
        assert row is not None


# ---------------------------------------------------------------------------
# Tests: idempotent sync
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Running sync twice does not create duplicate records."""

    async def test_rerun_sync_no_duplicates(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Syncing the same feed twice results in the same record count."""
        records = [
            _make_threat(id="osv:GHSA-001", source_id="GHSA-001"),
            _make_threat(id="osv:GHSA-002", source_id="GHSA-002"),
        ]
        feed = _MockFeed("test", records)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()
        await agg.sync_all()

        # Still only 2 unique records
        count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 2

    async def test_rerun_increments_hit_count(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Re-syncing existing records increments hit_count."""
        records = [_make_threat(id="osv:GHSA-001")]
        feed = _MockFeed("test", records)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()
        await agg.sync_all()

        row = conn.execute("SELECT hit_count FROM threats WHERE id = ?", ("osv:GHSA-001",)).fetchone()
        assert row is not None
        assert row[0] >= 2

    async def test_cursor_advances_only_after_writes(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """After sync, the feed_state cursor is updated."""
        records = [_make_threat(id="osv:GHSA-001")]
        feed = _MockFeed("test", records)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()

        state = get_feed_state(conn, "test")
        assert state is not None
        assert state["status"] == "idle"
        assert state["cursor"] is not None

    async def test_failed_feed_cursor_not_advanced(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When a feed fails, its cursor is not advanced (error state set)."""
        feed = _MockFeed("test", should_fail=True)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()

        state = get_feed_state(conn, "test")
        assert state is not None
        assert state["status"] == "error"
        assert state["cursor"] is None


# ---------------------------------------------------------------------------
# Tests: _deduplicate
# ---------------------------------------------------------------------------


class TestDeduplicate:
    """Tests for the internal _deduplicate method."""

    def test_no_duplicates_returns_same_list(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Records with different keys pass through unchanged."""
        records = [
            _make_threat(id="a:1", source="osv", source_id="CVE-1"),
            _make_threat(id="b:1", source="ghsa", source_id="GHSA-1"),
        ]
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate(records)
        assert len(result) == 2

    def test_duplicates_merged_by_key(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Records with same (ecosystem, package, source, source_id) are merged."""
        t1 = _make_threat(
            id="osv:GHSA-001",
            source="osv",
            source_id="GHSA-001",
            affected_versions=["1.0.0"],
            hit_count=1,
            last_seen=datetime(2025, 1, 1, tzinfo=UTC),
        )
        t2 = _make_threat(
            id="osv:GHSA-001",
            source="osv",
            source_id="GHSA-001",
            affected_versions=["1.1.0"],
            hit_count=3,
            last_seen=datetime(2025, 6, 1, tzinfo=UTC),
        )
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate([t1, t2])

        assert len(result) == 1
        merged = result[0]
        assert merged.last_seen == datetime(2025, 6, 1, tzinfo=UTC)
        assert merged.hit_count == 4  # 1 + 3
        assert "1.0.0" in merged.affected_versions
        assert "1.1.0" in merged.affected_versions

    def test_different_source_ids_not_merged(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Records with different source_ids are kept separate."""
        t1 = _make_threat(id="a:1", source="osv", source_id="CVE-1")
        t2 = _make_threat(id="a:2", source="osv", source_id="CVE-2")
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate([t1, t2])
        assert len(result) == 2

    def test_different_ecosystems_not_merged(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Records with different ecosystems are kept separate."""
        t1 = _make_threat(id="a:1", ecosystem="npm", source="osv", source_id="CVE-1")
        t2 = _make_threat(id="a:2", ecosystem="pypi", source="osv", source_id="CVE-1")
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate([t1, t2])
        assert len(result) == 2

    def test_empty_list(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Empty list returns empty list."""
        agg = FeedAggregator([], db_path)
        assert agg._deduplicate([]) == []

    def test_keeps_non_unknown_severity(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When merging, the non-UNKNOWN severity is preferred."""
        t1 = _make_threat(
            id="a:1",
            source="osv",
            source_id="CVE-1",
            severity="UNKNOWN",
        )
        t2 = _make_threat(
            id="a:1",
            source="osv",
            source_id="CVE-1",
            severity="CRITICAL",
        )
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate([t1, t2])
        assert result[0].severity == "CRITICAL"

    def test_keeps_highest_confidence(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When merging, the higher confidence is kept."""
        t1 = _make_threat(id="a:1", source="osv", source_id="CVE-1", confidence=0.5)
        t2 = _make_threat(id="a:1", source="osv", source_id="CVE-1", confidence=0.9)
        agg = FeedAggregator([], db_path)
        result = agg._deduplicate([t1, t2])
        assert result[0].confidence == 0.9


# ---------------------------------------------------------------------------
# Tests: get_sync_summary
# ---------------------------------------------------------------------------


class TestGetSyncSummary:
    """Tests for FeedAggregator.get_sync_summary()."""

    async def test_returns_empty_when_no_feeds_synced(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """No feed_state rows → empty dict."""
        agg = FeedAggregator([], db_path)
        assert agg.get_sync_summary() == {}

    async def test_returns_state_after_sync(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """After syncing, summary contains feed state."""
        feed = _MockFeed("test-feed", [_make_threat(id="t:1")])
        agg = FeedAggregator([feed], db_path)
        await agg.sync_all()

        summary = agg.get_sync_summary()
        assert "test-feed" in summary
        entry = summary["test-feed"]
        assert entry["status"] == "idle"
        assert entry["cursor"] is not None
        assert entry["last_sync"] is not None
        assert entry["error_message"] is None

    async def test_error_state_in_summary(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Failed feed shows error state in summary."""
        feed = _MockFeed("bad-feed", should_fail=True)
        agg = FeedAggregator([feed], db_path)
        await agg.sync_all()

        summary = agg.get_sync_summary()
        assert "bad-feed" in summary
        assert summary["bad-feed"]["status"] == "error"
        assert summary["bad-feed"]["error_message"] is not None

    async def test_multiple_feeds_in_summary(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Summary contains all synced feeds."""
        feed_a = _MockFeed("a", [_make_threat(id="a:1")])
        feed_b = _MockFeed("b", [])
        agg = FeedAggregator([feed_a, feed_b], db_path)
        await agg.sync_all()

        summary = agg.get_sync_summary()
        assert "a" in summary
        assert "b" in summary


# ---------------------------------------------------------------------------
# Tests: semaphore bounds concurrent calls
# ---------------------------------------------------------------------------


class TestSemaphore:
    """Tests that the semaphore bounds concurrent HTTP connections."""

    async def test_semaphore_limits_concurrency(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """With more feeds than MAX_CONCURRENT_FEEDS, not all run simultaneously."""
        # Reset class-level tracking
        _SemaphoreTrackingFeed._active = 0
        _SemaphoreTrackingFeed._max_active = 0

        feeds: list[FeedSource] = cast(
            list[FeedSource],
            [_SemaphoreTrackingFeed(f"feed-{i}", delay=0.05) for i in range(MAX_CONCURRENT_FEEDS + 5)],
        )
        agg = FeedAggregator(feeds, db_path)
        await agg.sync_all()

        # Max concurrent should not exceed the semaphore limit
        assert _SemaphoreTrackingFeed._max_active <= MAX_CONCURRENT_FEEDS

    async def test_feeds_complete_with_semaphore(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """All feeds complete even when concurrency is bounded."""
        feeds: list[FeedSource] = cast(
            list[FeedSource],
            [_MockFeed(f"feed-{i}", [_make_threat(id=f"{i}:1")]) for i in range(15)],
        )
        agg = FeedAggregator(feeds, db_path)
        summary = await agg.sync_all()

        assert len(summary) == 15
        for i in range(15):
            assert summary[f"feed-{i}"] == 1


# ---------------------------------------------------------------------------
# Tests: OSVFeedAdapter
# ---------------------------------------------------------------------------


class TestOSVFeedAdapter:
    """Tests for the OSVFeedAdapter wrapper."""

    def test_name(self) -> None:
        """Adapter name is 'osv'."""
        adapter = OSVFeedAdapter()
        assert adapter.name == "osv"

    def test_supports_incremental(self) -> None:
        """OSV adapter does not support incremental sync."""
        adapter = OSVFeedAdapter()
        assert adapter.supports_incremental is False

    async def test_fetch_delegates_to_osv_module(self) -> None:
        """fetch() calls fetch_from_dump and returns its results."""
        adapter = OSVFeedAdapter()
        mock_records = [_make_threat(id="osv:TEST-1")]

        with patch(
            "pkg_defender.intel.feeds.osv.fetch_from_dump",
            new_callable=AsyncMock,
            return_value=FeedFetchResult(records=mock_records, feed_metadata={}),
        ) as mock_fetch:
            result = await adapter.fetch(
                since=datetime(2025, 1, 1, tzinfo=UTC),
                ecosystems=["npm"],
            )
            mock_fetch.assert_called_once_with(ecosystems=["npm"], session=None, config=None, progress_callback=None)
            assert result.records == mock_records

    async def test_check_package_delegates_to_osv_module(self) -> None:
        """check_package() calls the OSV module's check_package function."""
        adapter = OSVFeedAdapter()
        mock_records = [_make_threat(id="osv:TEST-1")]

        with patch(
            "pkg_defender.intel.feeds.osv.check_package",
            new_callable=AsyncMock,
            return_value=mock_records,
        ) as mock_check:
            result = await adapter.check_package(
                package="lodash",
                version="4.17.20",
                ecosystem="npm",
            )
            mock_check.assert_called_once_with("npm", "lodash", "4.17.20", session=None)
            assert result.records == mock_records

    async def test_returns_zero_records_when_osv_returns_empty(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """OSVFeedAdapter integrates correctly with FeedAggregator."""
        adapter = OSVFeedAdapter()

        # Mock the OSV fetch to avoid actual network calls in tests
        with patch(
            "pkg_defender.intel.feeds.osv.fetch_from_dump",
            new_callable=AsyncMock,
            return_value=FeedFetchResult(records=[], feed_metadata={}),
        ):
            agg = FeedAggregator([adapter], db_path)
            summary = await agg.sync_all()

            assert summary == {"osv": 0}

            # No records should be written
            count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            assert count == 0


# ---------------------------------------------------------------------------
# Tests: incremental sync with cursor
# ---------------------------------------------------------------------------


class TestIncrementalSync:
    """Tests for incremental sync cursor behavior."""

    async def test_passes_cursor_as_since_for_incremental(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When a feed has a cursor in DB, it's used as the since parameter."""
        # Pre-populate feed state with a cursor
        cursor_time = datetime(2025, 6, 1, tzinfo=UTC)
        from pkg_defender.db.schema import update_feed_state

        update_feed_state(
            conn,
            "test-feed",
            cursor=cursor_time.isoformat(),
            status="idle",
        )

        # Track what `since` the feed receives
        received_since: list[datetime | None] = []

        class _TrackingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "test-feed"

            @property
            def supports_incremental(self) -> bool:
                return True

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                received_since.append(since)
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        feed = _TrackingFeed()
        agg = FeedAggregator([feed], db_path)
        await agg.sync_all()

        # The feed should have received the cursor time as since
        assert len(received_since) == 1
        assert received_since[0] == cursor_time

    async def test_non_incremental_feed_ignores_cursor(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """Non-incremental feeds receive the caller's since, not the cursor."""
        from pkg_defender.db.schema import update_feed_state

        update_feed_state(
            conn,
            "batch-feed",
            cursor="2025-06-01T00:00:00+00:00",
            status="idle",
        )

        received_since: list[datetime | None] = []

        class _TrackingFeed(FeedSource):
            @property
            def name(self) -> str:
                return "batch-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                received_since.append(since)
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: PKGDConfig | None) -> bool:
                return True

        caller_since = datetime(2025, 7, 1, tzinfo=UTC)
        feed = _TrackingFeed()
        agg = FeedAggregator([feed], db_path)
        await agg.sync_all(since=caller_since)

        # Non-incremental: should use caller-provided since
        assert received_since[0] == caller_since


# ---------------------------------------------------------------------------
# Tests: merge_records
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Tests for shared aiohttp.ClientSession handling."""

    async def test_creates_session_when_none_provided(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """sync_all creates and closes its own session when none is provided."""
        feed = _MockFeed("test", [_make_threat(id="t:1")])
        agg = FeedAggregator([feed], db_path)

        # Should not raise — session is managed internally
        summary = await agg.sync_all()
        assert summary["test"] == 1

    async def test_uses_provided_session(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """sync_all uses the caller-provided session without closing it."""
        feed = _MockFeed("test", [_make_threat(id="t:1")])
        agg = FeedAggregator([feed], db_path)

        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))
        try:
            summary = await agg.sync_all(session=session)
            assert summary["test"] == 1
            # Session should still be open (not closed by aggregator)
            assert not session.closed
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Tests: last_sync timestamp preservation on status changes
# ---------------------------------------------------------------------------


class TestLastSyncPreservation:
    """Tests that last_sync timestamp is preserved when feed status changes
    to non-success states (not_configured, error, circuit_open).

    Regression tests for bug: When a feed successfully synced at 10:00,
    then gets marked 'error' or 'not_configured' at 10:05, the last_sync
    timestamp was incorrectly overwritten to 10:05. It should preserve
    the 10:00 timestamp.
    """

    async def test_not_configured_preserves_last_sync(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When a configured feed is later marked not_configured, last_sync is preserved."""
        from pkg_defender.db.schema import get_feed_state, update_feed_state

        # Step 1: Simulate a successful sync at 10:00:00
        last_sync_time = "2026-04-07 10:00:00"
        update_feed_state(
            conn,
            "test-feed",
            cursor="2026-04-07T10:00:00+00:00",
            status="idle",
            update_last_sync=True,
        )
        # Manually set the last_sync to a known past time
        conn.execute(
            "UPDATE feed_state SET last_sync = ? WHERE feed_name = ?",
            (last_sync_time, "test-feed"),
        )
        conn.commit()

        # Verify initial state
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["last_sync"] == last_sync_time, "Initial last_sync should be set"
        assert state["status"] == "idle"

        # Step 2: Create a feed that is NOT configured
        class _UnconfiguredFeed(FeedSource):
            @property
            def name(self) -> str:
                return "test-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                # Return False to trigger not_configured status
                return False

        # Step 3: Trigger sync — should set status to "not_configured" but preserve last_sync
        feed = _UnconfiguredFeed()
        agg = FeedAggregator([feed], db_path)  # config=None to use defaults
        await agg.sync_all()

        # Step 4: Verify last_sync is preserved, NOT overwritten to current time
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["status"] == "not_configured", "Status should be not_configured"
        assert state["last_sync"] == last_sync_time, (
            f"last_sync should be preserved as {last_sync_time}, not overwritten"
        )

    async def test_error_preserves_last_sync(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When a feed sync fails, last_sync from previous successful sync is preserved."""
        from pkg_defender.db.schema import get_feed_state, update_feed_state

        # Step 1: Simulate a successful sync at 10:00:00
        last_sync_time = "2026-04-07 10:00:00"
        update_feed_state(
            conn,
            "test-feed",
            cursor="2026-04-07T10:00:00+00:00",
            status="idle",
            update_last_sync=True,
        )
        conn.execute(
            "UPDATE feed_state SET last_sync = ? WHERE feed_name = ?",
            (last_sync_time, "test-feed"),
        )
        conn.commit()

        # Verify initial state
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["last_sync"] == last_sync_time

        # Step 2: Create a feed that will fail on sync
        feed = _MockFeed("test-feed", should_fail=True, fail_exception=RuntimeError("API error"))
        agg = FeedAggregator([feed], db_path)

        # Step 3: Trigger sync — should fail and set status to "error"
        await agg.sync_all()

        # Step 4: Verify last_sync is preserved, NOT overwritten to current time
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["status"] == "error", "Status should be error"
        assert state["error_message"] is not None
        assert state["last_sync"] == last_sync_time, (
            f"last_sync should be preserved as {last_sync_time}, not overwritten"
        )

    async def test_circuit_open_preserves_last_sync(self, conn: sqlite3.Connection, db_path: Path) -> None:
        """When circuit breaker opens, last_sync from previous successful sync is preserved."""
        from pkg_defender.db.schema import get_feed_state, update_feed_state

        # Step 1: Simulate a successful sync at 10:00:00
        last_sync_time = "2026-04-07 10:00:00"
        update_feed_state(
            conn,
            "test-feed",
            cursor="2026-04-07T10:00:00+00:00",
            status="idle",
            update_last_sync=True,
        )
        conn.execute(
            "UPDATE feed_state SET last_sync = ? WHERE feed_name = ?",
            (last_sync_time, "test-feed"),
        )
        conn.commit()

        # Verify initial state
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["last_sync"] == last_sync_time

        # Step 2: Create a feed that is configured but has circuit breaker open
        # We'll simulate this by having the feed return True for is_configured
        # but the circuit breaker state being open
        # Note: The circuit breaker is checked in _sync_feed, so we need to set it up

        # First, set up the circuit breaker to be open (need to use CircuitState enum)
        from pkg_defender.intel.aggregator import CircuitState

        agg = FeedAggregator([], db_path)
        # Manually set circuit breaker to open state using internal _circuit_state
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.OPEN,
            "failure_count": 5,
            "graceful_failures": 0,
            "opened_at": datetime.now(UTC).timestamp(),
        }

        # Step 3: Create a mock feed that will be checked against circuit breaker
        class _CircuitOpenFeed(FeedSource):
            @property
            def name(self) -> str:
                return "test-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: PKGDConfig | None = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: PKGDConfig | None) -> bool:
                return True

        feed = _CircuitOpenFeed()
        agg._feeds = cast(list[FeedSource], [feed])

        # Step 4: Trigger sync — should set status to "circuit_open" but preserve last_sync
        await agg.sync_all()

        # Step 5: Verify last_sync is preserved, NOT overwritten to current time
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["status"] == "circuit_open", "Status should be circuit_open"
        assert state["last_sync"] == last_sync_time, (
            f"last_sync should be preserved as {last_sync_time}, not overwritten"
        )


# ---------------------------------------------------------------------------
# Tests: circuit breaker persistence across restarts (S18)
# ---------------------------------------------------------------------------


class TestCircuitBreakerPersistence:
    """Circuit breaker state is restored from DB on FeedAggregator construction."""

    def test_restores_circuit_open_from_db(self, db_path: Path) -> None:
        """Feed with circuit_open status in DB is restored to OPEN state."""
        # 1. Create a fresh DB and insert a circuit_open row
        _conn = init_db(db_path)
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute(
                    "INSERT INTO feed_state (feed_name, status) VALUES (?, ?)",
                    ("osv", "circuit_open"),
                )
                conn.commit()
            finally:
                conn.close()
        finally:
            _conn.close()

        # 2. Construct FeedAggregator — should restore circuit_open state
        agg = FeedAggregator([], db_path)

        # 3. Verify state was restored
        assert "osv" in agg._circuit_state
        assert agg._circuit_state["osv"]["state"] == CircuitState.OPEN
        assert agg._circuit_state["osv"]["failure_count"] == CIRCUIT_BREAKER_THRESHOLD
        assert agg._circuit_state["osv"]["opened_at"] is not None
        assert agg._is_circuit_open("osv") is True

    def test_no_circuit_open_restores_nothing(self, db_path: Path) -> None:
        """Feed with idle status is NOT restored to circuit breaker state."""
        # 1. Create a fresh DB and insert an idle row
        _conn = init_db(db_path)
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute(
                    "INSERT INTO feed_state (feed_name, status) VALUES (?, ?)",
                    ("osv", "idle"),
                )
                conn.commit()
            finally:
                conn.close()
        finally:
            _conn.close()

        # 2. Construct FeedAggregator — idle feed should not appear
        agg = FeedAggregator([], db_path)

        # 3. Verify no circuit state was restored
        assert "osv" not in agg._circuit_state

    def test_fresh_db_does_not_crash_on_restore(self, tmp_path: Path) -> None:
        """Constructing FeedAggregator without init_db does not raise."""
        db_path = tmp_path / "test.db"

        # Construct without calling init_db — feed_state table doesn't exist
        agg = FeedAggregator([], db_path)

        # No exception raised, circuit state is empty
        assert agg._circuit_state == {}


# ---------------------------------------------------------------------------
# Tests: circuit breaker state machine transitions
# ---------------------------------------------------------------------------


class TestCircuitBreakerTransitions:
    """Direct unit tests for circuit breaker state machine transitions.

    These tests operate on the in-memory ``_circuit_state`` dict directly.
    """

    def test_closed_to_open_at_threshold(self, db_path: Path) -> None:
        """Three failures opens the circuit (CLOSED -> OPEN)."""

        agg = FeedAggregator([], db_path)
        agg._record_failure("test-feed")  # 1
        agg._record_failure("test-feed")  # 2
        agg._record_failure("test-feed")  # 3 — open circuit

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.OPEN
        assert state["failure_count"] == 3
        assert state["opened_at"] is not None

    def test_stays_closed_below_threshold(self, db_path: Path) -> None:
        """Two failures does NOT open the circuit (boundary at threshold=3)."""

        agg = FeedAggregator([], db_path)
        agg._record_failure("test-feed")  # 1
        agg._record_failure("test-feed")  # 2 — still below threshold=3

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.CLOSED
        assert state["failure_count"] == 2
        assert state["opened_at"] is None

    def test_half_open_to_closed_on_success(self, db_path: Path) -> None:
        """Success in half-open state closes the circuit (HALF_OPEN -> CLOSED)."""

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.HALF_OPEN,
            "failure_count": 3,
            "graceful_failures": 0,
            "opened_at": None,
        }
        agg._record_success("test-feed")

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.CLOSED
        assert state["failure_count"] == 0

    def test_half_open_to_open_on_failure(self, db_path: Path) -> None:
        """Failure in half-open state reopens the circuit (HALF_OPEN -> OPEN)."""

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.HALF_OPEN,
            "failure_count": 3,
            "graceful_failures": 0,
            "opened_at": None,
        }
        agg._record_failure("test-feed")

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.OPEN
        assert state["opened_at"] is not None

    def test_record_success_resets_failure_count(self, db_path: Path) -> None:
        """Success in closed state resets failure count but stays closed."""

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.CLOSED,
            "failure_count": 2,
            "graceful_failures": 0,
            "opened_at": None,
        }
        agg._record_success("test-feed")

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.CLOSED
        assert state["failure_count"] == 0

    def test_record_success_noop_in_open(self, db_path: Path) -> None:
        """Success in open state does NOT close the circuit or reset counter."""

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.OPEN,
            "failure_count": 5,
            "graceful_failures": 0,
            "opened_at": 1234567890.0,
        }
        agg._record_success("test-feed")

        state = agg._circuit_state["test-feed"]
        assert state["state"] == CircuitState.OPEN  # unchanged
        assert state["failure_count"] == 5  # unchanged

    def test_is_circuit_open_returns_true(self, db_path: Path) -> None:
        """_is_circuit_open returns True when circuit is open and cooldown hasn't passed."""
        from datetime import UTC, datetime

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.OPEN,
            "failure_count": 5,
            "graceful_failures": 0,
            "opened_at": datetime.now(UTC).timestamp(),  # just opened
        }
        assert agg._is_circuit_open("test-feed") is True

    def test_is_circuit_open_returns_false(self, db_path: Path) -> None:
        """_is_circuit_open returns False when circuit is closed."""
        agg = FeedAggregator([], db_path)
        assert agg._is_circuit_open("test-feed") is False


# ---------------------------------------------------------------------------
# Tests: circuit breaker — graceful FAILED tracking (P1.19)
# ---------------------------------------------------------------------------


class TestGracefulFailureCircuitBreaker:
    """Tests for the graceful FAILED → circuit breaker integration.

    These tests verify that persistent FetchStatus.FAILED returns from a feed
    eventually open the circuit breaker, preventing infinite retries. The
    mechanism uses a separate ``graceful_failures`` counter (NOT
    ``failure_count``) and directly manipulates circuit state at threshold.
    """

    @pytest.mark.asyncio
    async def test_single_graceful_failure_no_effect(self, db_path: Path) -> None:
        """1 graceful FAILED does NOT open circuit (graceful_failures=1)."""

        _conn = init_db(db_path)
        try:
            feed = _MockFeed("test-feed", fail_status=True)
            agg = FeedAggregator([feed], db_path)

            await agg.sync_all()

            state = agg._circuit_state["test-feed"]
            assert state["state"] == CircuitState.CLOSED
            assert state["graceful_failures"] == 1
        finally:
            _conn.close()

    @pytest.mark.asyncio
    async def test_two_graceful_failures_no_effect(self, db_path: Path) -> None:
        """2 graceful FAILEDs keep circuit CLOSED (boundary below threshold=3)."""

        _conn = init_db(db_path)
        try:
            feed = _MockFeed("test-feed", fail_status=True)
            agg = FeedAggregator([feed], db_path)

            for _ in range(2):
                await agg.sync_all()

            state = agg._circuit_state["test-feed"]
            assert state["state"] == CircuitState.CLOSED
            assert state["graceful_failures"] == 2
        finally:
            _conn.close()

    @pytest.mark.asyncio
    async def test_three_graceful_failures_opens_circuit(
        self,
        db_path: Path,
    ) -> None:
        """Three consecutive graceful FAILED returns open the circuit (CLOSED→OPEN).

        This is the primary regression test for P1.19. It verifies that the
        direct state manipulation path opens the circuit when graceful_failures
        reaches CIRCUIT_BREAKER_THRESHOLD (3).
        """

        _conn = init_db(db_path)
        try:
            feed = _MockFeed("test-feed", fail_status=True)
            agg = FeedAggregator([feed], db_path)

            for _ in range(3):
                await agg.sync_all()

            state = agg._circuit_state["test-feed"]
            assert state["state"] == CircuitState.OPEN
            assert state["graceful_failures"] == 0  # Reset after opening
            assert state["opened_at"] is not None
        finally:
            _conn.close()

    @pytest.mark.asyncio
    async def test_graceful_failure_resets_on_success(
        self,
        db_path: Path,
    ) -> None:
        """A successful sync after graceful failures resets graceful_failures counter to 0."""
        from typing import cast

        _conn = init_db(db_path)
        try:
            # Step 1: 2 graceful failures
            feed = _MockFeed("test-feed", fail_status=True)
            agg = FeedAggregator([feed], db_path)

            for _ in range(2):
                await agg.sync_all()

            # Step 2: Swap to a success feed (same name, new instance)
            success_feed = _MockFeed("test-feed", [_make_threat(id="good:1")])
            agg._feeds = cast(list[FeedSource], [success_feed])

            await agg.sync_all()

            state = agg._circuit_state["test-feed"]
            assert state["graceful_failures"] == 0
            assert state["failure_count"] == 0
            assert state["state"] == CircuitState.CLOSED
        finally:
            _conn.close()

    @pytest.mark.asyncio
    async def test_graceful_failure_after_exception_resets(
        self,
        db_path: Path,
    ) -> None:
        """Exception resets graceful_failures counter to 0."""

        agg = FeedAggregator([], db_path)
        agg._circuit_state["test-feed"] = {
            "state": CircuitState.CLOSED,
            "failure_count": CIRCUIT_BREAKER_THRESHOLD - 1,
            "graceful_failures": 2,
            "opened_at": None,
        }

        # _record_failure from exception — graceful_failures should reset
        agg._record_failure("test-feed")

        state = agg._circuit_state["test-feed"]
        assert state["graceful_failures"] == 0
        assert state["state"] == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_graceful_failure_mixed_with_exception(
        self,
        db_path: Path,
    ) -> None:
        """Mix of graceful failures and exceptions: exception resets graceful_failures.

        After 2 graceful FAILEDs, a single exception resets graceful_failures to 0
        while incrementing failure_count to 1. Circuit stays CLOSED (below threshold).
        """
        from typing import cast

        _conn = init_db(db_path)
        try:
            # Step 1: 2 graceful failures (graceful_failures=2)
            feed = _MockFeed("test-feed", fail_status=True)
            agg = FeedAggregator([feed], db_path)

            for _ in range(2):
                await agg.sync_all()

            # Step 2: Feed throws exception — sync_all handles via return_exceptions=True
            exc_feed = _MockFeed(
                "test-feed",
                should_fail=True,
                fail_exception=RuntimeError("API down"),
            )
            agg._feeds = cast(list[FeedSource], [exc_feed])

            await agg.sync_all()

            state = agg._circuit_state["test-feed"]
            assert state["graceful_failures"] == 0  # Reset by exception
            assert state["failure_count"] == 1  # Exception incremented this
            assert state["state"] == CircuitState.CLOSED  # failure_count < threshold
        finally:
            _conn.close()


# ---------------------------------------------------------------------------
# Tests: feed_stats persistence (A-037)
# ---------------------------------------------------------------------------


class TestFeedStatsPersistence:
    """Tests for insert_feed_stats and get_feed_stats_history."""

    def test_insert_and_retrieve(self, conn: sqlite3.Connection) -> None:
        """Insert a feed_stats entry and retrieve it."""
        insert_feed_stats(conn, "test-feed", 42, 0.75)
        history = get_feed_stats_history(conn, "test-feed")
        assert len(history) == 1
        assert history[0]["feed_name"] == "test-feed"
        assert history[0]["record_count"] == 42
        assert history[0]["avg_confidence"] == 0.75
        assert history[0]["synced_at"] is not None
        assert history[0]["skipped_count"] == 0

    def test_multiple_entries(self, conn: sqlite3.Connection) -> None:
        """Insert multiple entries and verify DESC ordering."""
        # Use explicit staggered timestamps to avoid PRIMARY KEY collision
        # when inserting within the same second
        conn.execute(
            "INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence) "
            "VALUES (?, datetime('now', '-3 hours'), ?, ?)",
            ("test-feed", 10, 0.5),
        )
        conn.execute(
            "INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence) "
            "VALUES (?, datetime('now', '-2 hours'), ?, ?)",
            ("test-feed", 20, 0.6),
        )
        conn.execute(
            "INSERT INTO feed_stats (feed_name, synced_at, record_count, avg_confidence) "
            "VALUES (?, datetime('now', '-1 hours'), ?, ?)",
            ("test-feed", 30, 0.7),
        )
        conn.commit()
        history = get_feed_stats_history(conn, "test-feed")
        assert len(history) == 3
        # Should be ordered DESC by synced_at
        assert history[0]["record_count"] == 30
        assert history[0]["skipped_count"] == 0
        assert history[1]["record_count"] == 20
        assert history[1]["skipped_count"] == 0
        assert history[2]["record_count"] == 10
        assert history[2]["skipped_count"] == 0

    def test_empty_history(self, conn: sqlite3.Connection) -> None:
        """Querying for a feed with no entries returns empty list."""
        history = get_feed_stats_history(conn, "nonexistent-feed")
        assert history == []


# ---------------------------------------------------------------------------
# Tests: anomaly detection (A-037)
# ---------------------------------------------------------------------------


class TestAnomalyDetection:
    """Tests for _check_data_quality anomaly detection checks."""

    def test_zero_record_consecutive_no_warning_on_first(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No warning on first empty sync (boundary: consecutive threshold > 1)."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        agg._check_data_quality("test-feed", [])
        assert not any("zero_record" in r.getMessage() for r in caplog.records)

    def test_zero_record_consecutive_warning_on_second(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """WARNING on second consecutive empty sync."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        # First empty sync — no warning
        agg._check_data_quality("test-feed", [])
        # Second empty sync — should trigger warning
        agg._check_data_quality("test-feed", [])
        assert any("zero_record" in r.getMessage() for r in caplog.records)

    def test_confidence_collapse_detected(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """WARNING when avg confidence is below threshold."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        records = [_make_threat(id=f"collapse:{i}", confidence=0.01) for i in range(1000)]
        agg._check_data_quality("test-feed", records)
        assert any("confidence_collapse" in r.getMessage() for r in caplog.records)

    def test_volume_spike_detected(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """WARNING when current count > 5x historical average."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        # Current sync returns >5x the avg
        records = [_make_threat(id=f"spike:{i}", confidence=0.5) for i in range(1000)]
        history = [{"record_count": 100, "avg_confidence": 0.5}] * 2
        agg._check_data_quality("spike-feed", records, history)
        assert any("volume_spike" in r.getMessage() for r in caplog.records)

    def test_volume_drop_detected(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """ERROR when current count < 0.1x historical average."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        # Current sync returns <0.1x the avg
        records = [_make_threat(id="drop:1", confidence=0.5)]
        history = [{"record_count": 100, "avg_confidence": 0.5}] * 2
        agg._check_data_quality("drop-feed", records, history)
        assert any("volume_drop" in r.getMessage() for r in caplog.records)

    def test_no_anomaly_on_normal_sync(
        self,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No anomaly warnings on normal feed data."""
        caplog.set_level(logging.WARNING)
        agg = FeedAggregator([], db_path)
        records = [_make_threat(id="normal:1", confidence=0.85)]
        agg._check_data_quality("normal-feed", records)
        assert not any("Anomaly" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Tests: data quality guard (A-037)
# ---------------------------------------------------------------------------


class TestDataQualityGuard:
    """Tests that anomaly detection failures don't break feed ingestion."""

    async def test_dq_crash_does_not_break_feed_sync(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """Crash in _check_data_quality does NOT cancel feed sync."""
        feed = _MockFeed("test-feed", [_make_threat(id="guard:1")])
        agg = FeedAggregator([feed], db_path)
        mocker.patch(
            "pkg_defender.intel.aggregator.get_feed_stats_history_thread", side_effect=RuntimeError("DB error")
        )
        summary = await agg.sync_all()

        # Feed still syncs successfully
        assert summary["test-feed"] == 1

        # Record is in DB
        row = conn.execute("SELECT id FROM threats WHERE id = ?", ("guard:1",)).fetchone()
        assert row is not None

        # Feed state is idle (success)
        state = get_feed_state(conn, "test-feed")
        assert state is not None
        assert state["status"] == "idle"

    async def test_dq_crash_logged(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """Crash in _check_data_quality is logged via logger.error (traceback at debug)."""
        feed = _MockFeed("test-feed", [_make_threat(id="guard:2")])
        agg = FeedAggregator([feed], db_path)
        mocker.patch(
            "pkg_defender.intel.aggregator.get_feed_stats_history_thread", side_effect=RuntimeError("DB error")
        )
        mock_error = mocker.patch("pkg_defender.intel.aggregator.logger.error")
        await agg.sync_all()

        mock_error.assert_called_once()
        args, _ = mock_error.call_args
        assert "Data quality check failed" in args[0]


# ---------------------------------------------------------------------------
# Tests: anomaly detection wiring proof (A-037)
# ---------------------------------------------------------------------------


class TestAnomalyDetectionWiring:
    """Proves _check_data_quality is called from _sync_feed."""

    async def test_check_data_quality_called_from_sync_feed(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """_check_data_quality is called with correct args during sync_all."""
        feed = _MockFeed("wiring-feed", [_make_threat(id="wiring:1")])
        agg = FeedAggregator([feed], db_path)

        mock_check = mocker.patch.object(agg, "_check_data_quality", wraps=agg._check_data_quality)
        await agg.sync_all()

        mock_check.assert_called_once()
        args, kwargs = mock_check.call_args
        feed_name, records, call_history = args
        assert isinstance(feed_name, str)
        assert feed_name == "wiring-feed"
        assert isinstance(records, list)
        assert len(records) == 1
        assert isinstance(records[0], ThreatRecord)
        assert call_history is None or isinstance(call_history, list)


# ---------------------------------------------------------------------------
# Tests: PRAGMA synchronous is preserved as NORMAL on error paths
# ---------------------------------------------------------------------------


class _KeepAliveConnection:
    """Wraps a sqlite3.Connection, making close() a no-op.

    ``sqlite3.Connection.close`` is read-only in Python 3.13+ (C extension
    type). This wrapper lets us prevent the aggregator's ``conn.close()``
    call from destroying the connection before we can inspect PRAGMA state.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        object.__setattr__(self, "_real_conn", conn)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_real_conn"), name)

    def close(self) -> None:
        """No-op — keep the connection alive for post-sync inspection."""


class TestPragmaRestore:
    """PRAGMA synchronous=NORMAL is preserved through error paths.

    Regression test: When ``insert_threats_bulk()`` raises inside the
    transaction block, the connection must retain ``synchronous=NORMAL``
    (its default from ``get_connection()``) after the exception propagates.

    Without this guard, a future code change that sets ``synchronous=OFF``
    and fails to restore it would leave the connection in an unsafe state.
    """

    async def test_synchronous_restored_on_rollback(
        self,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """After insert_threats_bulk raises, PRAGMA synchronous remains NORMAL."""
        from pkg_defender.db.schema import SCHEMA_SQL

        # 1. Create a real connection with schema initialized
        # Use check_same_thread=False because _sync_feed_db_ops runs via
        # asyncio.to_thread() in a thread pool worker (different thread).
        real_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        # Simulate what get_connection() does: set synchronous=NORMAL
        real_conn.execute("PRAGMA synchronous=NORMAL")
        real_conn.executescript(SCHEMA_SQL)
        real_conn.commit()

        # 2. Wrap with no-op close so it stays inspectable after _sync_feed
        conn = _KeepAliveConnection(real_conn)

        # 3. Patch get_connection in the aggregator module to return our wrapper
        mocker.patch(
            "pkg_defender.intel.aggregator.get_connection",
            return_value=conn,
        )

        # 4. Make insert_threats_bulk raise to trigger the rollback path
        mocker.patch(
            "pkg_defender.intel.aggregator.insert_threats_bulk",
            side_effect=ValueError("bulk insert failed"),
        )

        # 5. Create aggregator with a mock feed that returns records
        feed = _MockFeed("pragma-test", [_make_threat(id="pragma:1")])
        agg = FeedAggregator([feed], db_path)

        # 7. Call _sync_feed — should raise due to mocked insert_threats_bulk
        session = aiohttp.ClientSession()
        try:
            with pytest.raises(ValueError, match="bulk insert failed"):
                await agg._sync_feed(
                    feed,
                    since=None,
                    ecosystems=None,
                    session=session,
                )
        finally:
            await session.close()

        # 8. Assert PRAGMA synchronous is NORMAL (1) on the wrapped connection
        sync_val = conn.execute("PRAGMA synchronous").fetchone()[0]
        assert sync_val == 1, f"Expected PRAGMA synchronous=1 (NORMAL), got {sync_val}"

        # Cleanup: close the real connection
        real_conn.close()


# ---------------------------------------------------------------------------
# Regression tests: Bug 2 — transaction atomicity for update_feed_state
# ---------------------------------------------------------------------------


class TestTransactionAtomicityRegression:
    """Regression tests for Bug 2: ``update_feed_state`` must share the
    transaction with ``insert_threats_bulk`` to prevent data leaks on feed
    state failure.

    **Root cause:** Before the fix, ``conn.commit()`` was called *before*
    ``update_feed_state()`` in ``aggregator.py:_sync_feed``
    (lines 494–525 pre-fix).  If ``update_feed_state()`` raised (e.g.
    database constraint violation, disk full), *threat data was already
    committed to the DB*, but ``sync_all()`` caught the exception and
    reported 0 threats synced — producing false "0 threats synced" output
    while data was persisted.

    **Fix:** ``update_feed_state()`` was moved *inside* the transaction
    (before ``conn.commit()``).  Both ``insert_threats_bulk`` and
    ``update_feed_state`` now share a single ``conn.commit()``.  If either
    fails, the transaction rolls *both* back.
    """

    async def test_update_feed_state_failure_rolls_back_threat_data(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When ``update_feed_state()`` raises inside the transaction,
        threat data must NOT leak to the DB.

        **Regression test for Bug 2:** This test FAILS before the fix
        (threats are committed despite the exception) and PASSES after
        (transaction rolls back both threat insert and feed state update).

        Scenario:
          - Feed returns 1 threat record.
          - ``update_feed_state`` is mocked to raise ``RuntimeError``.
          - ``sync_all()`` runs the feed.

        Expected:
          1. ``summary["bug2-feed"] == 0`` (exception propagated via
             ``return_exceptions=True``).
          2. ``threats`` table is EMPTY — no data leaked despite
             ``insert_threats_bulk`` having been called.
          3. ``feed_state`` has NO row for the feed — both the success
             state update (inside the transaction) AND the error state
             update (in the outer ``except`` handler) failed.
        """
        records = [_make_threat(id="osv:BUG2-LEAK-001")]
        feed = _MockFeed("bug2-feed", records)
        agg = FeedAggregator([feed], db_path)

        with patch(
            "pkg_defender.intel.aggregator.update_feed_state",
            side_effect=RuntimeError("feed state update failed"),
        ):
            summary = await agg.sync_all()

        # 1. Summary reports 0 for this feed
        assert summary == {"bug2-feed": 0}

        # 2. NO threats leaked — the transaction was rolled back
        count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 0, "Threat data should NOT be committed when update_feed_state fails"

        # 3. Feed state was NOT updated — both the success and error
        #    update_feed_state calls failed (mocked to raise), so no
        #    row exists in feed_state for this feed
        state = get_feed_state(conn, "bug2-feed")
        assert state is None, "Feed state should not exist after fully-rolled-back transaction"

    async def test_happy_path_commits_both_threats_and_feed_state(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """Happy path: both ``insert_threats_bulk`` AND
        ``update_feed_state`` succeed — threat data is committed, feed
        state is updated, and the count is correctly reported.

        This test verifies that the fix does not break the normal
        (non-error) code path.
        """
        records = [_make_threat(id="osv:HAPPY-BUG2-001")]
        feed = _MockFeed("happy-bug2-feed", records)
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all()

        # 1. Summary shows correct count
        assert summary == {"happy-bug2-feed": 1}

        # 2. Threat record is in the DB
        row = conn.execute(
            "SELECT id FROM threats WHERE id = ?",
            ("osv:HAPPY-BUG2-001",),
        ).fetchone()
        assert row is not None, "Threat record should be committed"

        # 3. Feed state was updated successfully
        state = get_feed_state(conn, "happy-bug2-feed")
        assert state is not None
        assert state["status"] == "idle"
        assert state["cursor"] is not None
        assert state["last_sync"] is not None


# ---------------------------------------------------------------------------
# Tests: C1 — Silent Threat Dropping (skip detection)
# ---------------------------------------------------------------------------


class TestSyncFeedSkipDetection:
    """Tests for skip detection in the sync pipeline (C1 fix).

    Verifies that invalid records are correctly counted as skipped,
    logged as warnings, and not included in the sync return value.
    """

    async def test_sync_feed_skips_invalid_records(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """Invalid records are excluded from sync_all() return value."""
        valid = _make_threat(id="valid:1", source="osv", source_id="CVE-001")
        valid2 = _make_threat(id="valid:2", source="osv", source_id="CVE-002")
        invalid = _make_threat(
            id="invalid:1",
            source="fake_source",  # Not in VALID_SOURCES
            source_id="BAD-001",
        )
        feed = _MockFeed("test-feed", [valid, valid2, invalid])
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all()

        # Only valid records counted
        assert summary == {"test-feed": 2}

        # Valid records in DB
        row1 = conn.execute("SELECT id FROM threats WHERE id = ?", ("valid:1",)).fetchone()
        assert row1 is not None
        row2 = conn.execute("SELECT id FROM threats WHERE id = ?", ("valid:2",)).fetchone()
        assert row2 is not None

        # Invalid record absent
        row3 = conn.execute("SELECT id FROM threats WHERE id = ?", ("invalid:1",)).fetchone()
        assert row3 is None

    async def test_sync_feed_logs_warning_on_skip(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """logger.warning is called with 'skipped' when records are skipped."""
        caplog.set_level(logging.WARNING)

        valid = _make_threat(id="warn:valid", source="osv", source_id="WARN-001")
        invalid = _make_threat(
            id="warn:invalid",
            source="fake_source",  # Not in VALID_SOURCES
            source_id="WARN-BAD",
        )
        feed = _MockFeed("test-feed", [valid, invalid])
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all()

        # Verify warning logged with "skipped" and feed name
        warning_messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("skipped" in msg and "test-feed" in msg for msg in warning_messages)

    async def test_sync_feed_all_invalid(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When all records are invalid, sync_all returns 0 for the feed."""
        invalid1 = _make_threat(
            id="allbad:1",
            source="fake_source",  # Not in VALID_SOURCES
            source_id="ALLBAD-001",
        )
        invalid2 = _make_threat(
            id="allbad:2",
            source="fake_source",
            source_id="ALLBAD-002",
        )
        feed = _MockFeed("test-feed", [invalid1, invalid2])
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all()

        assert summary == {"test-feed": 0}

        # No records inserted
        count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        assert count == 0


# ---------------------------------------------------------------------------
# Tests: error_callback behavior
# ---------------------------------------------------------------------------


class TestErrorCallback:
    """Tests for the error_callback parameter in sync_all / _sync_feed."""

    async def test_error_callback_called_on_exception(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When feed.fetch() raises, error_callback receives the exception."""
        from unittest.mock import MagicMock as MockMagicMock

        error_cb = MockMagicMock()
        feed = _MockFeed(
            "bad-feed",
            should_fail=True,
            fail_exception=ValueError("bad data"),
        )
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all(error_callback=error_cb)

        error_cb.assert_called_once()
        args = error_cb.call_args[0]
        assert args[0] == "bad-feed"
        assert isinstance(args[1], ValueError)
        assert str(args[1]) == "bad data"

    async def test_error_callback_called_on_failed_status(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When feed.fetch() returns FAILED status, error_callback receives FeedSyncError."""
        from unittest.mock import MagicMock as MockMagicMock

        from pkg_defender.exceptions import FeedSyncError

        error_cb = MockMagicMock()
        feed = _MockFeed("fail-feed", fail_status=True)
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all(error_callback=error_cb)

        error_cb.assert_called_once()
        args = error_cb.call_args[0]
        assert args[0] == "fail-feed"
        assert isinstance(args[1], FeedSyncError)
        assert args[1].feed_name == "fail-feed"
        assert args[1].message == "Simulated failure"

    async def test_error_callback_not_called_on_success(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When feed.fetch() succeeds, error_callback is NOT called."""
        from unittest.mock import MagicMock as MockMagicMock

        error_cb = MockMagicMock()
        feed = _MockFeed("good-feed", [_make_threat(id="g:1")])
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all(error_callback=error_cb)

        error_cb.assert_not_called()

    async def test_error_callback_not_called_not_configured(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When feed is not configured, error_callback is NOT called."""
        from unittest.mock import MagicMock as MockMagicMock

        error_cb = MockMagicMock()

        class _UnconfiguredFeed(FeedSource):
            @property
            def name(self) -> str:
                return "unconfigured"

            @property
            def supports_incremental(self) -> bool:
                return False

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return False

        feed = _UnconfiguredFeed()
        agg = FeedAggregator([feed], db_path)

        await agg.sync_all(error_callback=error_cb)

        error_cb.assert_not_called()

    async def test_error_callback_not_called_circuit_open(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When circuit breaker is open, error_callback is NOT called."""
        from unittest.mock import MagicMock as MockMagicMock

        error_cb = MockMagicMock()

        class _CircuitOpenFeed(FeedSource):
            @property
            def name(self) -> str:
                return "circuit-feed"

            @property
            def supports_incremental(self) -> bool:
                return False

            async def fetch(
                self,
                since: datetime | None = None,
                ecosystems: list[str] | None = None,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            async def check_package(
                self,
                package: str,
                version: str,
                ecosystem: str,
                session: aiohttp.ClientSession | None = None,
                config: Any = None,
            ) -> FeedFetchResult:
                return FeedFetchResult(records=[], feed_metadata={})

            def is_configured(self, config: Any) -> bool:
                return True

        feed = _CircuitOpenFeed()
        agg = FeedAggregator([], db_path)
        agg._circuit_state["circuit-feed"] = {
            "state": CircuitState.OPEN,
            "failure_count": CIRCUIT_BREAKER_THRESHOLD,
            "graceful_failures": 0,
            "opened_at": datetime.now(UTC).timestamp(),
        }
        agg._feeds = cast(list[FeedSource], [feed])

        await agg.sync_all(error_callback=error_cb)

        error_cb.assert_not_called()

    async def test_error_callback_default_none(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When error_callback is None (default), no AttributeError occurs."""
        feed = _MockFeed("test-feed", should_fail=True)
        agg = FeedAggregator([feed], db_path)

        # Should not raise — error_callback=None is the default
        summary = await agg.sync_all()
        assert summary["test-feed"] == 0

    async def test_error_callback_exception_does_not_mask_original(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
    ) -> None:
        """When error_callback raises, the original feed error is still recorded."""

        def _bad_callback(feed_name: str, error: Exception) -> None:
            raise RuntimeError("callback crashed")

        feed = _MockFeed(
            "bad-feed",
            should_fail=True,
            fail_exception=ValueError("original error"),
        )
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all(error_callback=_bad_callback)

        # Original feed error is still recorded
        assert summary["bad-feed"] == 0
        assert "bad-feed" in agg._failed_feeds
        assert "original error" in agg._failed_feeds["bad-feed"]

        # DB state is still updated
        state = get_feed_state(conn, "bad-feed")
        assert state is not None
        assert state["status"] == "error"

    async def test_error_callback_passed_through_sync_all(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """sync_all passes error_callback through to _sync_feed."""
        from unittest.mock import MagicMock as MockMagicMock

        error_cb = MockMagicMock()
        feed = _MockFeed("test-feed", should_fail=True)
        agg = FeedAggregator([feed], db_path)

        spy = mocker.patch.object(agg, "_sync_feed", wraps=agg._sync_feed)

        await agg.sync_all(error_callback=error_cb)

        # _sync_feed was called with error_callback kwarg
        spy.assert_called_once()
        _, kwargs = spy.call_args
        assert kwargs.get("error_callback") is error_cb


# ---------------------------------------------------------------------------
# Regression tests: exception handler ordering (Item 7)
# ---------------------------------------------------------------------------


class TestExceptionHandlerOrdering:
    """Regression tests for the exception handler cascade fix (Item 7).

    Verifies that DB error-state write completes BEFORE progress_callback(-1)
    fires, so persistent state is always consistent when the user sees the
    failure indicator.
    """

    async def test_exception_handler_state_before_notification(
        self,
        conn: sqlite3.Connection,
        db_path: Path,
        mocker: Any,
    ) -> None:
        """DB error-state write must complete BEFORE progress_callback(-1).

        Regression test for the exception handler reorder: if the ordering
        is wrong (state write after notification), the assertion fails.
        """
        call_order: list[str] = []

        def _tracking_update_feed_state(*args: Any, **kwargs: Any) -> None:
            call_order.append("db_write")

        def _tracking_progress(name: str, count: int) -> None:
            call_order.append("progress_callback")

        mocker.patch(
            "pkg_defender.intel.aggregator._update_feed_state_thread",
            side_effect=_tracking_update_feed_state,
        )

        feed = _MockFeed("fail-feed", should_fail=True)
        agg = FeedAggregator([feed], db_path)

        summary = await agg.sync_all(progress_callback=_tracking_progress)

        assert summary["fail-feed"] == 0
        # DB write must happen before progress callback
        assert call_order == ["db_write", "progress_callback"]
