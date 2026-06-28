"""Regression tests ensuring all subprocess.run() calls include timeout=.

These tests parse the source tree to verify that every subprocess.run() call
includes a timeout parameter, preventing indefinite hangs.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Generator

import pytest

SRC_ROOT = pathlib.Path(__file__).resolve().parents[4] / "src"


def _find_subprocess_run_calls() -> Generator[tuple[str, int, str, bool], None, None]:
    """Yield (file_path, line_number, call_source_snippet, has_timeout) for every subprocess.run() call."""
    for py_file in SRC_ROOT.rglob("*.py"):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match subprocess.run(...)
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                # Extract source snippet for the call
                lines = source.splitlines()
                start = node.lineno - 1
                # Find closing paren (approximate: up to 10 lines)
                end = min(start + 10, len(lines))
                snippet = "\n".join(lines[start:end])

                has_timeout = any(isinstance(kw, ast.keyword) and kw.arg == "timeout" for kw in node.keywords)
                yield str(py_file), node.lineno, snippet, has_timeout


@pytest.mark.parametrize(
    "file_path,line_number,snippet,has_timeout",
    list(_find_subprocess_run_calls()),
    ids=lambda val: str(val).split("/")[-1] if isinstance(val, str) and "/" in str(val) else str(val),
)
def test_subprocess_run_has_timeout(file_path: str, line_number: int, snippet: str, has_timeout: bool) -> None:
    """Every subprocess.run() call MUST include a timeout= parameter.

    This prevents indefinite hangs when external processes stall.
    See: plan_subprocess_timeouts_20260615.md
    """
    assert has_timeout, (
        f"subprocess.run() at {file_path}:{line_number} is missing timeout=. "
        f"All subprocess calls must include a timeout to prevent indefinite hangs.\n"
        f"Call snippet:\n{snippet}"
    )
