"""Shared exception classes for pkg-defender."""

from __future__ import annotations


class SecurityError(Exception):
    """Raised when a security check fails (e.g., SSRF domain allowlist violation).

    This is a defense-in-depth exception for URL domain validation failures.
    Callers should catch this to distinguish security violations from
    network errors or API failures.
    """
