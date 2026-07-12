#!/usr/bin/env python3
"""
Smart-merge two Homebrew formula files, protecting version/url/sha256 in the target.

Reads a SOURCE formula (from the main repo's homebrew-tap/) and a TARGET formula
(from the subsidiary tap repo checkout), then writes a merged version to the
target path. Protected fields (version, url, sha256) are kept from the target;
all other lines come from the source.

Usage:
    python3 .github/scripts/sync-brew-formula.py <source_path> <target_path>
    python3 .github/scripts/sync-brew-formula.py <source_path> <target_path> --output <output_path>

Exit codes:
    0   Success — merged formula written to target path (silent)
    1   Error — message printed to stderr
"""

import argparse
import re
import sys
from pathlib import Path

# Matches indented Homebrew formula lines like:
#   version "1.0.3"
#   url "https://..."
#   sha256 "abc123..."
PROTECTED_RE = re.compile(r'^\s+(version|url|sha256)\s+"')


def _read_lines(path: Path, *, required: bool = False) -> list[str]:
    """Read file lines, preserving line endings.

    Args:
        path: Path to the file to read.
        required: If True, exit with error when the file cannot be read.

    Returns:
        List of lines with line endings preserved.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if required:
            print(f"::error::Required file not found: '{path}'", file=sys.stderr)
            sys.exit(1)
        return []
    except OSError as exc:
        print(f"::error::Failed to read '{path}': {exc}", file=sys.stderr)
        if required:
            sys.exit(1)
        return []
    return text.splitlines(keepends=True)


def _write_lines(path: Path, lines: list[str]) -> None:
    """Write a list of lines to the target path, preserving line endings."""
    try:
        path.write_text("".join(lines), encoding="utf-8")
    except OSError as exc:
        print(f"::error::Failed to write '{path}': {exc}", file=sys.stderr)
        sys.exit(1)


def _collect_protected(lines: list[str]) -> dict[str, list[str]]:
    """Collect protected lines (version, url, sha256) from a formula.

    Returns a dict mapping each field name to its lines in declaration order.
    """
    collected: dict[str, list[str]] = {"version": [], "url": [], "sha256": []}
    for line in lines:
        m = PROTECTED_RE.match(line)
        if m:
            field = m.group(1)
            collected[field].append(line)
    return collected


def merge_formulas(source_lines: list[str], target_lines: list[str]) -> list[str]:
    """Merge source and target formula lines, protecting target's version/url/sha256.

    For each protected field, the corresponding line(s) from *target* are emitted
    in place of the source line. If the target has fewer lines for a field than
    the source, the source line is used as a fallback.

    Args:
        source_lines: Lines from the source formula (monorepo).
        target_lines: Lines from the target formula (tap repo).

    Returns:
        Merged lines ready to write to the target path.
    """
    if not target_lines:
        return list(source_lines)

    target_protected = _collect_protected(target_lines)
    consumed: dict[str, int] = {"version": 0, "url": 0, "sha256": 0}

    result: list[str] = []
    for line in source_lines:
        m = PROTECTED_RE.match(line)
        if m:
            field = m.group(1)
            target_list = target_protected[field]
            idx = consumed[field]
            if idx < len(target_list):
                result.append(target_list[idx])
                consumed[field] = idx + 1
            else:
                # Target has fewer entries than source — fall back to source line
                result.append(line)
        else:
            result.append(line)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smart-merge two Homebrew formula files, protecting version/url/sha256 in the target.",
    )
    parser.add_argument("source_path", type=str, help="Path to the source formula (monorepo)")
    parser.add_argument(
        "target_path",
        type=str,
        help="Target formula file. Reads the current state for comparison. "
        "If --output is not provided, the merged result overwrites this file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for merged formula. Defaults to overwriting target.",
    )
    args = parser.parse_args()

    source_path = Path(args.source_path)
    target_path = Path(args.target_path)

    source_lines = _read_lines(source_path, required=True)
    target_lines = _read_lines(target_path)

    merged = merge_formulas(source_lines, target_lines)
    output_path = Path(args.output) if args.output else target_path
    _write_lines(output_path, merged)

    return 0


if __name__ == "__main__":
    sys.exit(main())
