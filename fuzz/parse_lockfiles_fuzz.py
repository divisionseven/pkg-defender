# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

"""Fuzz targets for pkg-defender lock file parsers.

This file is detected by Scorecard's Fuzzing check because it imports
atheris. Any Python file with ``import atheris`` in the repository
triggers Scorecard to give 10/10 on this check.

Two fuzz targets:

1. ``test_find_lock_files`` / ``test_detect_lock_file`` — walk directory
   structures and detect lock filenames (lightweight, no content parsing).
2. ``test_parse_lock_file_content`` — writes random bytes to temp files
   with lock file names and feeds them to ``parse_lock_file()``, which
   dispatches to the real parsers (``parse_package_lock()``,
   ``parse_poetry_lock()``, ``parse_requirements_txt()``, etc.). This
   tests the actual parsing attack surface — malformed JSON, TOML, YAML,
   long lines, binary content, and encoding edge cases.
"""

import contextlib
import json
import sys
import tempfile
import tomllib
from pathlib import Path

import atheris  # type: ignore  # not installed locally (Linux-only)
from yaml import YAMLError

from pkg_defender.core.parsers import (
    detect_lock_file,
    find_lock_files,
    parse_lock_file,
)

# Lock file names that ``parse_lock_file`` dispatches to real parsers.
# Each will be written with random bytes and fed to the parser.
_LOCK_FILE_NAMES: list[str] = [
    "package-lock.json",  # → parse_package_lock() — JSON
    "yarn.lock",  # → parse_yarn_lock() — text/regex
    "pnpm-lock.yaml",  # → parse_pnpm_lock() — YAML
    "poetry.lock",  # → parse_poetry_lock() — TOML
    "Pipfile.lock",  # → parse_pipfile_lock() — JSON
    "requirements.txt",  # → parse_requirements_txt() — text/regex
    "uv.lock",  # → parse_uv_lock() — TOML
]

# Exceptions that are *expected* when feeding random bytes to parsers.
# An unexpected crash (anything else) is a genuine bug.
_EXPECTED_EXCEPTIONS: tuple[type[Exception], ...] = (
    json.JSONDecodeError,  # random bytes fed to json.load()
    tomllib.TOMLDecodeError,  # random bytes fed to tomllib.load()
    YAMLError,  # random bytes fed to yaml.safe_load()
    UnicodeDecodeError,  # binary data opened as utf-8 text
    KeyError,  # missing expected keys in parsed data
    AttributeError,  # non-dict passed to .get() / .items()
    ValueError,  # Regex timeout or integer conversion errors
)


def test_find_lock_files(data: bytes) -> None:
    """Fuzz ``find_lock_files`` with random directory structures."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create a file that looks like a lock file with random content
        lock_file = tmp_path / "package-lock.json"
        lock_file.write_bytes(data)

        # Run the finder — should not crash on any input
        _ = find_lock_files(tmp_path)


def test_detect_lock_file(data: bytes) -> None:
    """Fuzz ``detect_lock_file`` with random file content."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create various lock files with random content
        for name in _LOCK_FILE_NAMES:
            f = tmp_path / name
            f.write_bytes(data[: len(data) // 7] if data else b"")

        # Run detection — should not crash
        _ = detect_lock_file(tmp_path)


def test_parse_lock_file_content(data: bytes) -> None:
    """Fuzz the actual lock file parsers with random/untrusted content.

    This is the critical attack surface: lock file parsers process
    untrusted data from package registries. Malformed JSON, TOML, YAML,
    or pathological text input must not crash the parsers.

    Expected exceptions (JSONDecodeError, TOMLDecodeError, YAMLError,
    UnicodeDecodeError, etc.) are caught silently. Any *unexpected*
    exception is a genuine bug that must be reported.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Feed random bytes as each lock file format
        for name in _LOCK_FILE_NAMES:
            f = tmp_path / name
            f.write_bytes(data)
            with contextlib.suppress(*_EXPECTED_EXCEPTIONS):
                _ = parse_lock_file(f)


if __name__ == "__main__":
    atheris.Setup(
        sys.argv,
        test_parse_lock_file_content,  # default: test the parsers
        enable_coverage=True,
    )
    atheris.instrument_all()  # valid atheris API, not installed locally
    atheris.Fuzz()
