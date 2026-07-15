# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Shared exception classes for pkg-defender."""

from __future__ import annotations

import sqlite3


class DatabaseCorruptionError(sqlite3.DatabaseError):
    """Raised when PRAGMA quick_check detects database corruption.

    Extends sqlite3.DatabaseError so existing except sqlite3.Error
    and except sqlite3.DatabaseError handlers catch it automatically.
    """


class SecurityError(Exception):
    """Raised when a security check fails (e.g., SSRF domain allowlist violation).

    This is a defense-in-depth exception for URL domain validation failures.
    Callers should catch this to distinguish security violations from
    network errors or API failures.
    """


class FeedSyncError(Exception):
    """Wraps a failed-status feed error message for error_callback delivery.

    Used when feed.fetch() returns FetchStatus.FAILED with a string error
    message, providing a uniform Exception type for error_callback consumers.

    Args:
        feed_name: Name of the feed that failed.
        message: Error description from the feed.
    """

    def __init__(self, feed_name: str, message: str) -> None:
        self.feed_name = feed_name
        self.message = message
        super().__init__(f"{feed_name}: {message}")
