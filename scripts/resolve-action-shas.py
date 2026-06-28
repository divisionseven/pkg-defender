#!/usr/bin/env python3
"""Resolve all GitHub Action ``uses:`` references to commit SHAs.

Parses every ``.github/workflows/*.yml`` file in the repository root, finds all
``uses: {owner}/{repo}@{ref}`` lines, deduplicates them, and resolves each ref
to a commit SHA via the ``gh`` CLI (must be authenticated).

Outputs:
    * Pretty-printed table to stdout (with Action, SHA, and Resolution columns).
    * Full JSON mapping to ``internal_documentation/action-sha-mapping.json``.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
OUTPUT_JSON = REPO_ROOT / "internal_documentation" / "action-sha-mapping.json"
GH_BINARY = Path("/opt/homebrew/bin/gh")

USES_PATTERN = re.compile(r"uses:\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(\S+)")

# ANSI escape codes for terminal highlighting
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


# ── Helpers ────────────────────────────────────────────────────────────────────


def _visible_len(text: str) -> int:
    """Return the length of ``text`` excluding ANSI escape codes."""
    return len(_ANSI_PATTERN.sub("", text))


def find_all_uses(workflow_dir: Path) -> OrderedDict[str, tuple[str, str]]:
    """Parse all ``*.yml`` files and return an ordered mapping of deduplicated actions.

    Returns an ``OrderedDict`` of ``{owner/repo@ref: (owner/repo, ref)}`` preserving
    the order of first appearance across all files.
    """
    unique: OrderedDict[str, tuple[str, str]] = OrderedDict()

    yml_files = sorted(workflow_dir.glob("*.yml"))
    if not yml_files:
        print(f"::warning:: No workflow files found in {workflow_dir}", file=sys.stderr)
        return unique

    for yml_path in yml_files:
        text = yml_path.read_text(encoding="utf-8")
        for match in USES_PATTERN.finditer(text):
            repo_spec = match.group(1)  # e.g. actions/checkout
            ref = match.group(2)  # e.g. v4
            key = f"{repo_spec}@{ref}"
            if key not in unique:
                unique[key] = (repo_spec, ref)

    return unique


def run_gh_api(endpoint: str) -> dict[str, Any] | None:
    """Call ``gh api <endpoint> --jq .`` and return the parsed JSON dict.

    Returns ``None`` on any failure (non-zero exit, parse error, etc.).
    Non-zero exit codes from ``gh`` (e.g. 404 for missing refs) are silently
    handled — callers interpret the ``None`` return with context-appropriate
    messages. Other errors (parse errors, timeouts, missing binary) are
    printed to stderr.
    """
    cmd = [str(GH_BINARY), "api", endpoint, "--jq", "."]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        print(f"  [ERROR] gh not found at {GH_BINARY}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"  [ERROR] Failed to parse JSON from {endpoint}: {exc}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"  [ERROR] Timeout calling {endpoint}", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"  [ERROR] Unexpected error calling {endpoint}: {exc}", file=sys.stderr)
        return None


def resolve_ref(repo_spec: str, ref: str) -> tuple[str | None, str]:
    """Resolve ``{repo_spec}@{ref}`` to a commit SHA.

    Returns ``(sha, resolution_type)`` where ``resolution_type`` is one of:
        * ``"tag"`` — resolved as an immutable tag
        * ``"branch"`` — resolved as a branch ref (expected for ``@release/v1`` style)
        * ``"branch-fallback"`` — tag didn't exist, fell back to branch (fragile)
        * ``"error"`` — could not resolve

    Resolution logic:
        1. If the ref contains ``/``, it is treated as a branch ref directly.
        2. Otherwise, the tag is tried first; if that fails, the branch is
           attempted as a fallback.
    """
    is_branch_ref = "/" in ref

    if is_branch_ref:
        # ── Expected branch ref (e.g. @release/v1) ─────────────────────────
        endpoint = f"repos/{repo_spec}/git/ref/heads/{ref}"
        ref_data = run_gh_api(endpoint)
        if ref_data is not None:
            return ref_data.get("object", {}).get("sha"), "branch"
        return None, "error"

    # ── Attempt 1: tag ─────────────────────────────────────────────────────
    endpoint = f"repos/{repo_spec}/git/ref/tags/{ref}"
    ref_data = run_gh_api(endpoint)

    if ref_data is not None:
        obj = ref_data.get("object", {})
        obj_type = obj.get("type", "")
        sha = obj.get("sha", "")

        if obj_type == "commit":
            return sha, "tag"

        if obj_type == "tag":
            # Annotated tag — fetch the tag object to find the commit SHA
            tag_endpoint = f"repos/{repo_spec}/git/tags/{sha}"
            tag_data = run_gh_api(tag_endpoint)
            if tag_data is not None:
                return tag_data.get("object", {}).get("sha"), "tag"

            print(
                f"  [WARN] Annotated tag object fetch failed for {repo_spec}@{ref}",
                file=sys.stderr,
            )
            return None, "error"

        print(
            f"  [WARN] Unexpected object type '{obj_type}' for tag {repo_spec}@{ref}",
            file=sys.stderr,
        )
        return None, "error"

    # ── Attempt 2: branch (fallback — tag didn't exist) ────────────────────
    endpoint = f"repos/{repo_spec}/git/ref/heads/{ref}"
    ref_data = run_gh_api(endpoint)
    if ref_data is not None:
        return ref_data.get("object", {}).get("sha"), "branch-fallback"

    print(
        f"  [ERROR] Failed to resolve {repo_spec}@{ref} as tag or branch",
        file=sys.stderr,
    )
    return None, "error"


def _display_resolution(resolution: str) -> str:
    """Return the resolution string, with ANSI yellow highlighting if fragile."""
    if resolution == "branch-fallback":
        return f"{_YELLOW}{resolution}{_RESET}"
    return resolution


def format_table(results: list[tuple[str, str | None, str]]) -> str:
    """Build a pretty-printed table with Action, SHA, and Resolution columns."""
    if not results:
        return "(no actions found)"

    # Determine column widths (strip ANSI codes for accurate visible width)
    max_action = max(len(r[0]) for r in results)
    res_displays = [_display_resolution(r[2]) for r in results]
    max_resolution = max(_visible_len(d) for d in res_displays)
    col_action = max(max_action, len("Action"))
    col_sha = 40
    col_resolution = max(max_resolution, len("Resolution"))

    sep = f"+{'-' * (col_action + 2)}+{'-' * (col_sha + 2)}+{'-' * (col_resolution + 2)}+"
    fmt = f"| {{:<{col_action}}} | {{:<{col_sha}}} | {{:<{col_resolution}}} |"

    lines = [
        sep,
        fmt.format("Action", "SHA", "Resolution"),
        sep,
    ]
    for action, sha, resolution in results:
        display_sha = sha if sha else "ERROR"
        display_res = _display_resolution(resolution)
        lines.append(fmt.format(action, display_sha, display_res))
    lines.append(sep)
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> None:
    # Step 1: Locate gh binary
    if not GH_BINARY.is_file():
        print(f"[FATAL] gh not found at {GH_BINARY}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Parse all workflow files
    print("Parsing workflow files...")
    actions = find_all_uses(WORKFLOW_DIR)
    if not actions:
        print("No actions found. Exiting.")
        sys.exit(0)
    print(f"  Found {len(actions)} unique actions across {len(list(WORKFLOW_DIR.glob('*.yml')))} files\n")

    # Step 3: Resolve each unique action
    results: list[tuple[str, str | None, str]] = []
    mapping: dict[str, str | None] = {}

    for idx, (key, (repo_spec, ref)) in enumerate(actions.items(), start=1):
        print(f"  [{idx}/{len(actions)}] Resolving {key} ... ", end="")
        sys.stdout.flush()

        sha, resolution = resolve_ref(repo_spec, ref)
        mapping[key] = sha

        if resolution == "tag":
            print("OK (tag)")
        elif resolution == "branch":
            print("expected branch ref, resolved OK")
        elif resolution == "branch-fallback":
            print(f"{ref} tag not found, found {ref} branch ({_YELLOW}fragile{_RESET})")

            # Special prominent warning for dependency-review-action
            if repo_spec == "actions/dependency-review-action":
                print()
                print(f"  {_BOLD}{_YELLOW}WARNING:{_RESET} {_BOLD}actions/dependency-review-action@{ref}{_RESET}")
                print(f"         has no '{ref}' tag (only v5.0.0).")
                print(f"         The '{ref}' branch resolves to {sha}.")
                print(f"         Suggest changing @{ref} to @v5.0.0 for an immutable tag reference.")
                print()
        else:
            print("FAILED")

        results.append((key, sha, resolution))

    # Step 4: Print table to stdout
    print("\n" + "=" * 70)
    print("GITHUB ACTION SHA MAPPING")
    print("=" * 70)
    print()
    table = format_table(results)
    print(table)
    print()

    # Summarise failures
    failed = [(a, s) for a, s, r in results if r == "error"]
    if failed:
        print(f"WARNING: {len(failed)} action(s) failed to resolve:")
        for action, _ in failed:
            print(f"  - {action}")
        print()

    # Step 5: Write JSON mapping
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    json_output: dict[str, str | None] = {}
    for key in actions:
        json_output[key] = mapping[key]

    OUTPUT_JSON.write_text(
        json.dumps(json_output, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"JSON mapping written to: {OUTPUT_JSON}")

    # Exit with error code if any resolutions failed
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
