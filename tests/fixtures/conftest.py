"""Shared fixtures for test data files.

The canonical FIXTURES_DIR constant lives in tests/conftest.py.
This file re-exports it for any tests that import from here,
though most tests should use ``from tests.conftest import FIXTURES_DIR``.
"""

from pathlib import Path

# Path to the tests/fixtures/ directory — same value as tests/conftest.FIXTURES_DIR
FIXTURES_DIR = Path(__file__).parent
