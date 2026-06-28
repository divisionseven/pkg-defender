#!/usr/bin/env python3
"""
Extracts the release notes for a specific version from a CHANGELOG.md file
following the Keep a Changelog format (https://keepachangelog.com).

Usage:
    python3 .github/scripts/extract-changelog.py <version> [changelog-path]

Arguments:
    version         The version to extract (e.g. "1.2.3" or "v1.2.3")
    changelog-path  Path to changelog file (default: CHANGELOG.md)

Exit codes:
    0   Success — notes printed to stdout
    1   Usage error
    2   Changelog file not found
    3   Version not found in changelog — treated as a release gate failure
"""

import re
import sys
from pathlib import Path


def extract_notes(version: str, changelog_path: Path) -> tuple[str, int]:
    """Returns (notes, exit_code)."""
    if not changelog_path.exists():
        print(f"::error::Changelog not found at '{changelog_path}'.", file=sys.stderr)
        return "", 2

    content = changelog_path.read_text(encoding="utf-8")
    escaped = re.escape(version)

    # Matches: ## [1.2.3], ## [1.2.3] - 2024-01-15, ## [1.2.3-beta.1] - 2024-01-15
    pattern = rf"^## \[{escaped}\][^\n]*\n(.*?)(?=^## \[|\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

    if not match:
        print(
            f"::error::No changelog entry found for version [{version}].\n"
            f"         Add a '## [{version}]' section to CHANGELOG.md before releasing.",
            file=sys.stderr,
        )
        return "", 3

    notes = match.group(1).strip()

    if not notes:
        print(
            f"::warning::Changelog entry for [{version}] exists but has no content.",
            file=sys.stderr,
        )
        return f"_No changelog details recorded for `{version}`._", 0

    return notes, 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1

    version = sys.argv[1].lstrip("v")
    changelog_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("CHANGELOG.md")

    notes, code = extract_notes(version, changelog_path)

    if code == 0:
        print(notes)

    return code


if __name__ == "__main__":
    sys.exit(main())
