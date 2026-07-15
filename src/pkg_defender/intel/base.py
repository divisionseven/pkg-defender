# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Base class for intelligence feed sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

import aiohttp

from pkg_defender.models import ThreatRecord

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig


class FetchStatus(Enum):
    """Indicates whether a feed fetch operation succeeded or failed."""

    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class EcosystemResult:
    """Result for a single ecosystem within a feed."""

    ecosystem: str
    count: int
    url: str
    status: str  # "success" or "failed"
    error: str | None = None


@dataclass
class FeedFetchResult:
    """Result from a feed fetch operation with metadata."""

    records: list[ThreatRecord]
    feed_metadata: dict[str, Any]
    status: FetchStatus = FetchStatus.SUCCESS


class FeedSource(ABC):
    """Abstract base for all intelligence feed sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique feed identifier (e.g., 'osv', 'ghsa', 'socket')."""

    @property
    @abstractmethod
    def supports_incremental(self) -> bool:
        """Whether this feed supports incremental sync via cursor/since."""

    @property
    def is_experimental(self) -> bool:
        """Whether this feed provides experimental/unverified signals.

        Experimental feeds (e.g., social media) produce lower-confidence
        signals and may be less reliable than authoritative feeds.
        Default is False — override in subclasses that are experimental.
        """
        return False

    @abstractmethod
    def is_configured(self, config: PKGDConfig) -> bool:
        """Check whether this feed has required configuration/credentials.

        Args:
            config: The current configuration object.

        Returns:
            True if the feed is ready to use (credentials present, enabled, etc.).
        """

    @abstractmethod
    async def fetch(
        self,
        since: datetime | None = None,
        ecosystems: list[str] | None = None,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Fetch threat records from this feed.

        Args:
            since: Only fetch records modified after this time (if supported).
            ecosystems: Filter to specific ecosystems (npm, pypi, etc.).
            session: Shared aiohttp session (created if None).
            config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult containing records and fetch metadata.
        """

    @abstractmethod
    async def check_package(
        self,
        package: str,
        version: str,
        ecosystem: str,
        session: aiohttp.ClientSession | None = None,
        config: PKGDConfig | None = None,
    ) -> FeedFetchResult:
        """Point query: check a specific package version for threats.

        Args:
            package: Package name.
            version: Package version.
            ecosystem: Ecosystem (npm, pypi, etc.).
            session: Shared aiohttp session (created if None).
            config: Configuration object (injected by aggregator, or load_config() if None).

        Returns:
            FeedFetchResult containing matching ThreatRecord objects and metadata.
        """
