# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""User-friendly message templates for shell hook output.

These templates provide consistent, actionable error messages.
No tracebacks — only clear explanations with bypass options.
"""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

# Sources that can never block installs (informational only)
INFORMATIONAL_ONLY_SOURCES: frozenset[str] = frozenset({"mastodon", "reddit", "rss", "x_twitter"})
"""Social feed sources that can never block installs (informational only)."""


def informational_source_label(source: str) -> str:
    """Return an '(informational)' label if source is social/non-blocking.

    Social feed sources (mastodon, reddit, rss, x_twitter) can never
    cause a block — their maximum possible score is well below the
    0.3 threshold. This label makes it clear to users that these
    threats are advisory only.

    Args:
        source: The threat source identifier (e.g., 'mastodon', 'osv').

    Returns:
        ' (informational)' if source is non-blocking, empty string otherwise.
    """
    if source in INFORMATIONAL_ONLY_SOURCES:
        return " (informational)"
    return ""


def _get_console() -> Console:
    """Get console with stderr output for shell hook messages."""
    return Console(stderr=True)


def format_block_message(
    title: str,
    body: str,
    bypass_instructions: str | None = None,
) -> None:
    """Format and print a block message to stderr.

    Args:
        title: Error title
        body: Detailed explanation
        bypass_instructions: Optional bypass commands
    """
    console = _get_console()

    content = body

    if bypass_instructions:
        content = f"{body}\n\n---\n{bypass_instructions}"

    console.print(
        Panel(
            Markdown(content),
            title=f"[red]🔒 {title}[/red]",
            border_style="red",
            expand=False,
        )
    )


def network_unreachable(registry: str, package: str) -> None:
    """Message when registry is unreachable."""
    format_block_message(
        title="PKG-Defender Blocked: Registry Unreachable",
        body=(
            f"Cannot verify '{package}' because the {registry} registry is unreachable.\n\n"
            f"PKG-Defender failed to contact {registry} to verify this package. "
            f"For security, we block when we cannot verify package safety.\n\n"
            f"**What you can do:**\n"
            f"  1. Check your internet connection\n"
            f"  2. Try again in a few minutes\n"
            f"  3. If you need to proceed NOW, use the bypass below"
        ),
        bypass_instructions=(
            "**BYPASS (NOT RECOMMENDED — disables ALL security checks):**\n\n"
            " Use `pkgd bypass` to override the block.\n\n"
            " ⚠ **WARNING:** This bypasses ALL security checks. "
            "Fix the underlying issue instead of using this bypass."
        ),
    )


def registry_timeout(registry: str, package: str, timeout: int) -> None:
    """Message when registry times out."""
    format_block_message(
        title="PKG-Defender Blocked: Registry Timeout",
        body=(
            f"Cannot verify '{package}' because {registry} did not respond in {timeout} seconds.\n\n"
            f"PKG-Defender waits for registries to respond, but this one took too long. "
            f"For security, we block when verification cannot complete.\n\n"
            f"**What you can do:**\n"
            f"  1. Check if {registry} is having issues\n"
            f"  2. Try again later\n"
            f"  3. If you need to proceed NOW, use the bypass below"
        ),
        bypass_instructions=(
            "**BYPASS (NOT RECOMMENDED — disables ALL security checks):**\n\n"
            " Use `pkgd bypass` to override the block.\n\n"
            " ⚠ **WARNING:** This bypasses ALL security checks. "
            "Fix the underlying issue instead of using this bypass."
        ),
    )


def adapter_unavailable(adapter: str) -> None:
    """Message when adapter is unavailable."""
    format_block_message(
        title="PKG-Defender Blocked: Adapter Error",
        body=(
            f"Cannot verify this package because the {adapter} adapter is unavailable.\n\n"
            f"PKG-Defender needs the {adapter} adapter to verify packages. "
            f"It could not be loaded, so we cannot verify safety.\n\n"
            f"**What you can do:**\n"
            f"  1. Reinstall PKG-Defender: `pip install --upgrade pkg-defender`\n"
            f"  2. If you need to proceed NOW, use the bypass below"
        ),
        bypass_instructions=(
            "**BYPASS (NOT RECOMMENDED — disables ALL security checks):**\n\n"
            " Use `pkgd bypass` to override the block.\n\n"
            " ⚠ **WARNING:** This bypasses ALL security checks. "
            "Fix the underlying issue instead of using this bypass."
        ),
    )


def database_error(operation: str) -> None:
    """Message when database is unavailable."""
    format_block_message(
        title="PKG-Defender Blocked: Database Error",
        body=(
            f"Cannot verify this package because the threat database is unavailable.\n\n"
            f"PKG-Defender needs its threat database to verify package safety. "
            f"The database could not be accessed for: {operation}\n\n"
            f"**What you can do:**\n"
            f"  1. Initialize database: `pkgd intel init`\n"
            f"  2. Check file permissions in your config directory"
            f" (Linux: ~/.config/pkg-defender/, macOS: ~/Library/Application Support/pkg-defender/)\n"
            f"  3. If you need to proceed NOW, use the bypass below"
        ),
        bypass_instructions=(
            "**BYPASS (NOT RECOMMENDED — disables ALL security checks):**\n\n"
            " Use `pkgd bypass` to override the block.\n\n"
            " ⚠ **WARNING:** This bypasses ALL security checks. "
            "Fix the underlying issue instead of using this bypass."
        ),
    )


def version_resolution_failed(package: str, registry: str) -> None:
    """Message when version resolution fails."""
    format_block_message(
        title="PKG-Defender Blocked: Version Unresolved",
        body=(
            f"Cannot verify '{package}' because its version could not be determined.\n\n"
            f"PKG-Defender needs to know the exact version to check against the threat database. "
            f"Could not resolve version from {registry}.\n\n"
            f"**What you can do:**\n"
            f"  1. Specify version explicitly: `pip install {package}@1.0.0`\n"
            f"  2. Check if the package exists in {registry}\n"
            f"  3. If you need to proceed NOW, use the bypass below"
        ),
        bypass_instructions=(
            "**BYPASS (NOT RECOMMENDED — disables ALL security checks):**\n\n"
            " Use `pkgd bypass` to override the block.\n\n"
            " ⚠ **WARNING:** This bypasses ALL security checks. "
            "Fix the underlying issue instead of using this bypass."
        ),
    )
