# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Structured error types for fail-closed audit pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PipelineBlockError(Exception):
    """Base exception for pipeline blocking errors.

    All blocking errors include:
    - user_message: What the user sees (no traceback)
    - bypass: Explicit bypass option with warning
    - reason: Technical details for logging
    """

    title: str
    user_message: str
    bypass_command: str | None = None
    reason: Exception | None = None

    def __str__(self) -> str:
        return self.user_message


class NetworkError(PipelineBlockError):
    def __init__(
        self,
        registry: str,
        package: str,
        reason: Exception | None = None,
    ):
        title = f"Cannot reach {registry} registry"
        user_message = (
            f"PKG-Defender could not contact the {registry} registry to verify '{package}'.\n\n"
            f"This usually means:\n"
            f" • No internet connection\n"
            f" • {registry} is temporarily down\n"
            f" • Firewall or proxy is blocking access\n\n"
            f"Fix the underlying issue rather than bypassing security.\n\n"
            f"Bypass (NOT RECOMMENDED — disables ALL security checks):\n"
            f" Use 'pkgd bypass' to override the block."
        )
        super().__init__(
            title=title,
            user_message=user_message,
            reason=reason,
        )


class AdapterError(PipelineBlockError):
    def __init__(
        self,
        adapter: str,
        reason: Exception | None = None,
    ):
        title = f"{adapter} adapter unavailable"
        user_message = (
            f"PKG-Defender's {adapter} adapter could not be loaded.\n\n"
            f"This usually means:\n"
            f" • Required dependencies are missing\n"
            f" • Package installation is incomplete\n\n"
            f"Fix the underlying issue rather than bypassing security.\n\n"
            f"Bypass (NOT RECOMMENDED — disables ALL security checks):\n"
            f" Use 'pkgd bypass' to override the block."
        )
        super().__init__(
            title=title,
            user_message=user_message,
            reason=reason,
        )


class TimeoutError(PipelineBlockError):
    def __init__(
        self,
        registry: str,
        package: str,
        timeout_seconds: int,
        reason: Exception | None = None,
    ):
        title = f"Timeout contacting {registry}"
        user_message = (
            f"PKG-Defender timed out ({timeout_seconds}s) waiting for {registry} to respond.\n\n"
            f"This usually means:\n"
            f" • Slow network connection\n"
            f" • {registry} is overloaded\n\n"
            f"Fix the underlying issue rather than bypassing security.\n\n"
            f"Bypass (NOT RECOMMENDED — disables ALL security checks):\n"
            f" Use 'pkgd bypass' to override the block."
        )
        super().__init__(
            title=title,
            user_message=user_message,
            reason=reason,
        )


class DatabaseError(PipelineBlockError):
    def __init__(
        self,
        operation: str,
        reason: Exception | None = None,
    ):
        title = "Threat database unavailable"
        user_message = (
            f"PKG-Defender could not access the threat database for '{operation}'.\n\n"
            f"This usually means:\n"
            f" • Database file is corrupted\n"
            f" • Permission issues\n"
            f" • Database needs initialization (run: pkgd intel init)\n\n"
            f"Fix the underlying issue rather than bypassing security.\n\n"
            f"Bypass (NOT RECOMMENDED — disables ALL security checks):\n"
            f" Use 'pkgd bypass' to override the block."
        )
        super().__init__(
            title=title,
            user_message=user_message,
            reason=reason,
        )
