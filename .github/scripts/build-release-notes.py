#!/usr/bin/env python3
"""
Assembles a complete, professionally formatted GitHub Release body including:
  • Centred project logo (with dark/light mode switching via <picture>)
  • Release title and date
  • Changelog section for this version
  • Collapsible commit history since the previous tag

Usage:
    python3 .github/scripts/build-release-notes.py \
        --version     1.2.3 \
        --repo        owner/repo \
        --project     "My Project" \
        --changelog   CHANGELOG.md \
        [--logo-light https://raw.githubusercontent.com/.../logo.png] \
        [--logo-dark  https://raw.githubusercontent.com/.../logo-dark.png] \
        [--logo-width 100]

Output: complete release body printed to stdout, suitable for use as the
        GitHub Release `body` field.

Exit codes:
    0   Success
    1   Usage / argument error
"""

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

# ── Git helpers ───────────────────────────────────────────────────────────────


def get_previous_tag(current_version: str) -> str | None:
    """Return the tag immediately before the current one, or None if this is the first."""
    try:
        result = subprocess.run(
            ["git", "tag", "--sort=-version:refname"],
            capture_output=True,
            text=True,
            check=True,
        )
        tags = [t.strip() for t in result.stdout.strip().splitlines() if t.strip()]
        # Tags are sorted newest→oldest. Find current tag, return the next one.
        current_tag = f"v{current_version}"
        for i, tag in enumerate(tags):
            if tag == current_tag or tag.lstrip("v") == current_version:
                return tags[i + 1] if i + 1 < len(tags) else None
        # If current tag not in list yet (pre-push scenario), take the first tag as prev
        return tags[0] if tags else None
    except subprocess.CalledProcessError:
        return None


def get_commits_since(prev_tag: str | None, repo: str) -> list[dict]:
    """Return commit metadata since prev_tag (or all commits if None)."""
    rev_range = f"{prev_tag}..HEAD" if prev_tag else "HEAD"
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                rev_range,
                "--pretty=format:%H%x00%h%x00%s%x00%an%x00%ae",
                "--no-merges",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        return []

    commits = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\x00")
        if len(parts) != 5:
            continue
        sha, short_sha, subject, author_name, author_email = parts

        # Skip GitHub Actions bot commits
        if "github-actions" in author_email or "[bot]" in author_name:
            continue

        commits.append(
            {
                "sha": sha,
                "short_sha": short_sha,
                "subject": subject,
                "author": author_name,
                "commit_url": f"https://github.com/{repo}/commit/{sha}",
            }
        )

    return commits


# ── Changelog extraction ───────────────────────────────────────────────────


def extract_changelog_notes(version: str, changelog_path: Path) -> str:
    if not changelog_path.exists():
        return "_No changelog available._"

    content = changelog_path.read_text(encoding="utf-8")
    escaped = re.escape(version)
    pattern = rf"^## \[{escaped}\][^\n]*\n(.*?)(?=^## \[|\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

    if not match:
        return f"_No changelog entry found for `{version}`._"

    return match.group(1).strip() or f"_No changelog details for `{version}`._"


# ── Body assembly ─────────────────────────────────────────────────────────


def build_logo_block(logo_light: str | None, logo_dark: str | None, width: int, project: str) -> str:
    if not logo_light and not logo_dark:
        return ""

    if logo_light and logo_dark:
        return f"""\
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="{logo_dark}">
  <img src="{logo_light}" width="{width}" alt="{project} Logo">
</picture>"""
    else:
        url = logo_light or logo_dark
        return f'<img src="{url}" width="{width}" alt="{project} Logo">'


def build_commits_section(commits: list[dict], prev_tag: str | None) -> str:
    if not commits:
        return ""

    since_label = f"since {prev_tag}" if prev_tag else "in this release"
    count = len(commits)

    rows = "\n".join(
        f"| [`{c['short_sha']}`]({c['commit_url']}) | {_escape_md(c['subject'])} | {_escape_md(c['author'])} |"
        for c in commits
    )

    return f"""\
<details>
<summary>📖 {count} Commit{"s" if count != 1 else ""} {since_label}</summary>
<br>

| Commit | Description | Author |
| --- | --- | --- |
{rows}

</details>"""


def _escape_md(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def build_body(
    version: str,
    project: str,
    repo: str,
    changelog: str,
    commits_section: str,
    logo_block: str,
    is_prerelease: bool,
) -> str:
    today = date.today().strftime("%B %-d, %Y")  # e.g. April 19, 2026
    version_display = f"v{version}"

    # ── Header ─────────────────────────────────────────────────────────────────
    header_parts = [logo_block] if logo_block else []
    header_parts.append(f"<h1>{project} {version_display}</h1>")
    header_parts.append(f"<p><em>Released {today}</em></p>")

    if is_prerelease:
        header_parts.append(
            "<p><strong>⚠️ Pre-release</strong> — "
            "may contain breaking changes or incomplete features. "
            "Not recommended for production use.</p>"
        )

    header = '<div align="center">\n\n' + "\n\n".join(header_parts) + "\n\n</div>"

    # ── Body sections ─────────────────────────────────────────────────────────
    sections = [header, "---", f"## What's Changed\n\n{changelog}"]

    if commits_section:
        sections.append("---")
        sections.append(commits_section)

    sections.append("---")
    sections.append(f"**[View Complete Changelog &rarr;](https://github.com/{repo}/blob/main/CHANGELOG.md)**")

    return "\n\n".join(sections) + "\n"


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a professional GitHub Release body.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", required=True, help="Version string, e.g. 1.2.3")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--project", required=True, help="Human-readable project name")
    parser.add_argument("--changelog", default="CHANGELOG.md")
    parser.add_argument("--logo-light", default=None, help="Logo URL for light mode")
    parser.add_argument("--logo-dark", default=None, help="Logo URL for dark mode")
    parser.add_argument("--logo-width", default=100, type=int)
    parser.add_argument("--prerelease", action="store_true")
    args = parser.parse_args()

    version = args.version.lstrip("v")

    # Gather all the pieces
    changelog_notes = extract_changelog_notes(version, Path(args.changelog))
    prev_tag = get_previous_tag(version)
    commits = get_commits_since(prev_tag, args.repo)
    commits_section = build_commits_section(commits, prev_tag)
    logo_block = build_logo_block(args.logo_light, args.logo_dark, args.logo_width, args.project)

    body = build_body(
        version=version,
        project=args.project,
        repo=args.repo,
        changelog=changelog_notes,
        commits_section=commits_section,
        logo_block=logo_block,
        is_prerelease=args.prerelease,
    )

    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
