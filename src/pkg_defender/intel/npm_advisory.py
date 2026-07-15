# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""npm advisory feed — wraps npm audit advisory data."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp

from pkg_defender.intel.base import FeedFetchResult, FeedSource, FetchStatus
from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

logger = logging.getLogger(__name__)


class NpmAdvisoryFeed(FeedSource):
    """Feed source for npm's built-in advisory data via ``npm audit --json``.

    Runs the ``npm audit --json`` command and parses the JSON output into
    ThreatRecord objects. Requires the ``npm`` CLI to be installed.

    Gracefully returns empty results if npm is not installed or the
    command fails for any reason.
    """

    @property
    def name(self) -> str:
        """Unique feed identifier."""
        return "npm_advisory"

    @property
    def supports_incremental(self) -> bool:
        """npm audit supports checking current project state."""
        return True

    def is_configured(self, config: PKGDConfig) -> bool:
        """Check if npm advisory feed is configured.

        Checks if npm advisory feed is enabled in config.

        Args:
            config: The current configuration object.

        Returns:
            True if npm_advisory_enabled is set.
        """
        return config.feeds.npm_advisory_enabled

    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Run ``npm audit --json`` and parse advisories into ThreatRecords.

        Uses asyncio.create_subprocess_exec() to avoid blocking the event loop.

        Args:
            since: Ignored — npm audit reports current advisory state.
            ecosystems: Ignored — npm advisory is npm-only.
            session: Ignored — uses subprocess, not HTTP.
            config: Ignored — no config needed for npm advisory.

        Returns:
            List of ThreatRecord objects for npm advisories found.
        """
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm",
                "audit",
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            if proc.returncode not in (0, 1):  # npm audit returns 1 if vulns found
                logger.debug("npm audit returned %d; no advisories", proc.returncode)
                return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
            data: dict[str, Any] = await asyncio.to_thread(json.loads, stdout.decode())
        except TimeoutError:
            logger.debug("npm audit timed out after 60 seconds", exc_info=True)
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
        except (json.JSONDecodeError, FileNotFoundError):
            logger.debug("npm audit failed or returned invalid JSON", exc_info=True)
            return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)

        records: list[ThreatRecord] = []
        now = datetime.now(UTC)
        advisories = data.get("vulnerabilities", {})
        for pkg_name, info in advisories.items():
            severity = info.get("severity", "unknown").upper()
            via = info.get("via", [])
            summary = ""
            if via and isinstance(via[0], dict):
                summary = via[0].get("title", "")
            elif via and isinstance(via[0], str):
                summary = via[0]

            records.append(
                ThreatRecord(
                    id=f"npm_advisory:{pkg_name}",
                    ecosystem="npm",
                    package_name=pkg_name,
                    severity=severity,
                    confidence=0.75,  # npm audit is authoritative
                    source="npm_advisory",
                    source_id=pkg_name,
                    summary=summary,
                    first_seen=now,
                    last_seen=now,
                    hit_count=1,
                    cvss_score=None,
                    published_at=now,
                    ingested_at=now,
                    is_malicious=False,
                    is_unverified=False,
                )
            )
        return FeedFetchResult(records=records, feed_metadata={}, status=FetchStatus.SUCCESS)

    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Point query — not supported by npm advisory (project-scoped).

        npm audit operates on the current project's dependency tree, not
        individual packages. Callers should use ``fetch()`` and look up
        results from the local DB.

        Args:
            package: Package name (ignored).
            version: Package version (ignored).
            ecosystem: Ecosystem (ignored).
            session: Session (ignored).
            config: Configuration object (injected by aggregator).

        Returns:
            FeedFetchResult with empty records (point query not supported).
        """
        return FeedFetchResult(records=[], feed_metadata={}, status=FetchStatus.FAILED)
