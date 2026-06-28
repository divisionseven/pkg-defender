"""Tests for the health command implementation (_health_impl)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import click
import pytest

from pkg_defender.cli.common import _health_impl


class TestHealthImpl:
    """Unit tests for _health_impl()."""

    def test_health_impl_handles_string_threat_count(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression test: _health_impl handles string COUNT(*) results.

        Some sqlite3 configurations (custom row_factory) return strings for
        numeric columns. This test verifies:
        1. No TypeError is raised from %d logging format (now %s).
        2. threat_count is always an int (enforced by int() cast).

        Before the fix (S04), this scenario would crash with:
            TypeError: %d format: a real number is required, not str
        """
        # --- Setup: create temp DB with threats table and a row ---
        db_path = tmp_path / "test.db"

        # Initialize schema and insert a threat
        from pkg_defender.db.schema import init_db

        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO threats (id, ecosystem, package_name, severity, confidence, "
            "source, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test-1", "npm", "bad-pkg", "HIGH", 0.9, "osv", "test threat"),
        )
        conn.commit()
        conn.close()

        # --- Setup: monkeypatch get_db_path and get_connection ---

        def _string_row_factory(
            cursor: sqlite3.Cursor,
            row: tuple[Any, ...],
        ) -> dict[int, Any]:
            """Return all columns as strings to simulate problematic sqlite3 config."""
            return {i: str(val) for i, val in enumerate(row)}

        def _mock_get_connection(_db_path: Path, **kwargs: Any) -> sqlite3.Connection:
            c = sqlite3.connect(str(db_path))
            c.row_factory = _string_row_factory
            return c

        monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda: db_path)
        monkeypatch.setattr(
            "pkg_defender.cli.common.get_connection",
            _mock_get_connection,
        )

        # --- Setup: capture click.echo for JSON output ---
        captured_json: list[str] = []
        monkeypatch.setattr(
            "pkg_defender.cli.common.click.echo",
            lambda msg, **kwargs: captured_json.append(str(msg) if msg is not None else ""),
        )

        # --- Setup: mock Click context ---
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {}

        # --- Execute ---
        try:
            asyncio.run(_health_impl(ctx, "json", False))
        except TypeError:
            pytest.fail("_health_impl raised TypeError – regression from %d logging format.")
        except SystemExit:
            pass  # Health check may fail in test env — JSON was already captured above

        # --- Assert: threat_count is an int ---
        assert len(captured_json) > 0, "Expected click.echo to be called with JSON health data"
        health_data = json.loads(captured_json[0])

        threat_count = health_data["checks"]["database"]["threat_count"]
        assert isinstance(threat_count, int), (
            f"Expected threat_count to be int, got {type(threat_count).__name__}: {threat_count!r}"
        )
