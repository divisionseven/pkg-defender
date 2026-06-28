#!/usr/bin/env python3
"""Build the threat intelligence snapshot database.

This script is the canonical implementation used by the CI workflow.
It fetches threat data from Tier 1 sources (OSV, GHSA, npm advisory)
and produces the compressed snapshot database for distribution.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp

from pkg_defender.db.schema import insert_threat
from pkg_defender.intel.feeds.osv import download_ecosystem_dump
from pkg_defender.intel.ghsa import GHSAFeed
from pkg_defender.intel.npm_advisory import NpmAdvisoryFeed
from pkg_defender.models import ThreatRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Tier 1 sources only (per Phase 3 requirement)
TIER1_ECOSYSTEMS = ["npm", "pypi", "cargo", "rubygems", "go", "maven", "nuget", "packagist"]


async def fetch_all_tier1() -> list[ThreatRecord]:
    """Fetch records from all Tier 1 feeds concurrently."""
    records: list[ThreatRecord] = []

    # OSV bulk dumps (download per ecosystem)
    timeout = aiohttp.ClientTimeout(total=300)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for eco in TIER1_ECOSYSTEMS:
            try:
                vulns = await download_ecosystem_dump(eco, session)
                for vuln in vulns:
                    # Reuse OSV parsing logic - import here to avoid circular import
                    from pkg_defender.intel.feeds._osv_parser import _parse_osv_vuln

                    record = _parse_osv_vuln(vuln, ecosystem=eco)
                    records.append(record)
            except Exception as e:
                logger.warning("OSV dump failed for %s: %s", eco, e)

    # GHSA via REST API (fetch last year of advisories)
    ghsa = GHSAFeed()
    try:
        ghsa_records = await ghsa.fetch(
            since=datetime.now(UTC) - timedelta(days=365),
            session=None,  # Will create own session
        )
        records.extend(ghsa_records.records)
    except Exception as e:
        logger.warning("GHSA fetch failed: %s", e)

    # npm advisory via npm audit
    npm = NpmAdvisoryFeed()
    try:
        npm_records = await npm.fetch()
        records.extend(npm_records.records)
    except Exception as e:
        logger.warning("npm advisory fetch failed: %s", e)

    return records


def build_snapshot(output_path: Path) -> int:
    """Build snapshot database and save to output_path."""
    from pkg_defender.db.schema import init_db as init_db_schema

    conn = init_db_schema(output_path)

    # Fetch from all Tier 1 feeds
    logger.info("Fetching Tier 1 feeds...")
    records = asyncio.run(fetch_all_tier1())
    logger.info("Fetched %d records from feeds", len(records))

    if not records:
        logger.warning("No records fetched - database may be empty")

    # Insert in batches for performance
    batch_size = 500
    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        for record in batch:
            insert_threat(conn, record, commit=False)
        conn.commit()
        logger.info(
            "Inserted batch %d/%d (%d records)",
            i // batch_size + 1,
            (len(records) + batch_size - 1) // batch_size,
            len(batch),
        )

    # VACUUM to optimize storage
    logger.info("Running VACUUM to optimize storage...")
    conn.execute("VACUUM")
    conn.commit()

    # --- F1: PRAGMA integrity_check ---
    integrity_rows = conn.execute("PRAGMA integrity_check").fetchall()
    if not (len(integrity_rows) == 1 and integrity_rows[0][0] == "ok"):
        logger.error("PRAGMA integrity_check FAILED")
        for row in integrity_rows:
            logger.error("  Corruption: %s", row[0])
        conn.close()
        sys.exit(1)

    logger.info("PRAGMA integrity_check: ok")

    # Get final count
    count_row = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
    record_count = count_row[0] if count_row else 0

    # --- F3: Per-ecosystem minimum ---
    placeholders = ",".join("?" for _ in TIER1_ECOSYSTEMS)
    eco_query = f"SELECT COUNT(DISTINCT ecosystem) FROM threats WHERE ecosystem IN ({placeholders})"
    eco_count = conn.execute(eco_query, TIER1_ECOSYSTEMS).fetchone()[0]
    if eco_count < 3:
        logger.error("Insufficient Tier 1 ecosystems with data: %d (need >= 3)", eco_count)
        conn.close()
        sys.exit(1)

    # --- F2: Record count bounds check ---
    prev_row = conn.execute("SELECT value FROM db_metadata WHERE key = 'previous_record_count'").fetchone()

    if prev_row is not None:
        prev_count = int(prev_row[0])
        if record_count > 5 * prev_count:
            logger.error(
                "Record count %d is >5x previous count %d — suspicious inflation",
                record_count,
                prev_count,
            )
            conn.close()
            sys.exit(1)
        if record_count < 0.01 * prev_count:
            logger.error(
                "Record count %d is <0.01x previous count %d — suspicious drop",
                record_count,
                prev_count,
            )
            conn.close()
            sys.exit(1)
        logger.info(
            "Record count %d within bounds (previous: %d, ratio: %.2f)",
            record_count,
            prev_count,
            record_count / prev_count if prev_count else 0,
        )
    else:
        logger.info("No previous record count — skipping bounds check (first build)")

    # Store current count for next build
    conn.execute(
        "INSERT OR REPLACE INTO db_metadata (key, value) VALUES ('previous_record_count', ?)",
        (str(record_count),),
    )
    conn.commit()

    conn.close()

    logger.info("Snapshot built with %d records across %d ecosystems", record_count, eco_count)
    return record_count


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Build threat database snapshot")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("threats.db"),
        help="Output database path (default: threats.db)",
    )
    args = parser.parse_args()

    # Generate timestamped filename if default
    if args.output == Path("threats.db"):
        date_str = datetime.now(UTC).strftime("%Y%m%d")
        args.output = Path(f"threats-{date_str}.db")
        logger.info("Using dated output: %s", args.output)

    # Build the snapshot
    count = build_snapshot(args.output)
    print(f"Built snapshot with {count} records: {args.output}")


if __name__ == "__main__":
    main()
