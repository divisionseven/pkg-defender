#!/usr/bin/env python3
"""Add SPDX-License-Identifier and copyright headers to all Python source files.

Scans every ``.py`` file under ``src/pkg_defender/`` and inserts::

    # Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
    # SPDX-License-Identifier: Apache-2.0

Insertion rules (by file type):

- **Empty file** — header goes at the very beginning of the file,
  followed by a single newline (no blank-line separator needed).
- **All non-empty files** — header is the FIRST two lines of the file,
  followed by exactly one blank line, then the module docstring (if any)::

      # Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
      # SPDX-License-Identifier: Apache-2.0

      \"\"\"Module docstring...\"\"\"

Idempotent — files whose content already contains ``SPDX-License-Identifier``
are skipped without modification.
"""

from __future__ import annotations

import pathlib
import sys

HEADER_LINES = [
    "# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)",
    "# SPDX-License-Identifier: Apache-2.0",
]
SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "pkg_defender"
HEADER_BLOCK = "\n".join(HEADER_LINES)


def _header_is_present(content: str) -> bool:
    """Return ``True`` if the file already has an SPDX header."""
    return "SPDX-License-Identifier" in content


def add_header(file_path: pathlib.Path) -> bool:
    """Add the SPDX/copyright header to *file_path*.

    Inserts the header at the top of the file (position 0), followed by
    exactly one blank line, before any existing content (docstring, code,
    etc.).

    Returns ``True`` if the file was modified, ``False`` if skipped.
    """
    content = file_path.read_text(encoding="utf-8")
    if _header_is_present(content):
        return False  # Already has header

    new_content = HEADER_BLOCK + "\n" if not content.strip() else HEADER_BLOCK + "\n\n" + content

    file_path.write_text(new_content, encoding="utf-8")
    return True


def main() -> None:
    """Walk all ``.py`` files under ``src/pkg_defender/`` and add headers."""
    if not SRC_DIR.is_dir():
        print(f"ERROR: Source directory not found: {SRC_DIR}", file=sys.stderr)
        sys.exit(1)

    py_files = sorted(SRC_DIR.rglob("*.py"))
    total = len(py_files)
    modified = 0
    skipped_already = 0
    errors: list[str] = []

    for f in py_files:
        try:
            if add_header(f):
                modified += 1
            else:
                skipped_already += 1
        except Exception as exc:
            rel = f.relative_to(SRC_DIR.parent.parent)
            errors.append(f"{rel}: {exc}")

    print(f"Total .py files: {total}")
    print(f"Modified:        {modified}")
    print(f"Skipped (had):   {skipped_already}")
    if errors:
        print(f"Errors:          {len(errors)}")
        for err in errors:
            print(f"  ERROR: {err}")
    else:
        print("Errors:         0")

    # Post-verification
    missing_spdx: list[str] = []
    for f in py_files:
        content = f.read_text(encoding="utf-8")
        if "SPDX-License-Identifier" not in content:
            rel = f.relative_to(SRC_DIR.parent.parent)
            missing_spdx.append(str(rel))

    if missing_spdx:
        print(f"\nWARNING: {len(missing_spdx)} files still missing SPDX header:")
        for m in missing_spdx:
            print(f"  {m}")
        sys.exit(1)
    else:
        print("\n✓ All files verified: SPDX-License-Identifier present in every file.")


if __name__ == "__main__":
    main()
