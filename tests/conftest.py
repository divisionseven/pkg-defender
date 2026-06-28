"""Shared test fixtures for pkg-defender test suite."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

if TYPE_CHECKING:
    from pkg_defender.config.settings import PKGDConfig

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def runner() -> CliRunner:
    """Return a Click CliRunner.

    Note: mix_stderr parameter was removed in Click 8.2.0 (see
    https://github.com/pallets/click/issues/2522). In Click 8.2+,
    CliRunner always provides separate stdout/stderr access via
    result.stdout and result.stderr, making mix_stderr unnecessary.
    """
    return CliRunner()


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Redirect config and data dirs to tmp_path for test isolation."""
    db_path = tmp_path / "data" / "threats.db"
    config_path = tmp_path / "config" / "pkgd.toml"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Initialize the database tables
    from pkg_defender.db import init_db

    _conn = init_db(db_path)

    monkeypatch.setattr("pkg_defender.cli.main.get_db_path", lambda *args, **kwargs: db_path)
    monkeypatch.setattr(
        "pkg_defender.cli.main.get_default_config_path",
        lambda *args, **kwargs: config_path,
    )
    monkeypatch.setattr("pkg_defender.cli.common.get_db_path", lambda *args, **kwargs: db_path)
    monkeypatch.setattr(
        "pkg_defender.cli.common.get_default_config_path",
        lambda *args, **kwargs: config_path,
    )
    monkeypatch.setattr("pkg_defender.config.settings.get_db_path", lambda *args, **kwargs: db_path)
    monkeypatch.setattr(
        "pkg_defender.config.settings.get_default_config_path",
        lambda *args, **kwargs: config_path,
    )
    # Patch command module local bindings (module-level imports from cli.common)
    # These were resolved at module load time, so patching cli.common is not enough.
    for _module in (
        "intel",
        "status",
        "audit",
        "setup",
        "bypass",
        "audit_logs",
        "reset",
    ):
        monkeypatch.setattr(
            f"pkg_defender.cli.commands.{_module}.get_db_path",
            lambda *args, **kwargs: db_path,
        )
    for _module in ("setup", "reset", "config"):
        monkeypatch.setattr(
            f"pkg_defender.cli.commands.{_module}.get_default_config_path",
            lambda *args, **kwargs: config_path,
        )
    try:
        yield {"db_path": db_path, "config_path": config_path}
    finally:
        _conn.close()


@pytest.fixture
def project_version() -> str:
    """Read version from pyproject.toml (single source of truth)."""
    import tomllib

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        version: str = tomllib.load(f)["project"]["version"]
        return version


@pytest.fixture
def cli_version() -> str:
    """Get the CLI version from pkg_defender.__version__."""
    from pkg_defender import __version__

    return __version__


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create isolated temp HOME directory for all tests.

    This fixture:
    - Sets HOME to a temp directory for all tests
    - Prevents accidental modification of real RC files (.zshrc, .bashrc, etc.)
    - Verifies isolation after setup to catch any mocking failures

    This is a belt-and-suspenders safeguard. The individual test fixtures
    (in tests/unit/cli/test_hooks_command.py) also create temp directories, but this
    ensures isolation at the session level as a safety net.
    """

    # Create isolated temp home directory
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)

    # Set HOME to temp directory for the entire test session
    monkeypatch.setenv("HOME", str(home))

    # Verify isolation: Path.home() must resolve to within the isolated temp dir
    current_home = Path.home()
    if not str(current_home).startswith(str(home)):
        pytest.fail(
            f"Tests may be running in real home directory: {current_home}. "
            f"Expected HOME to be isolated to {home}. "
            "Ensure HOME is properly isolated to a temp directory."
        )

    return home


@pytest.fixture()
def db_conn(tmp_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Create a temporary SQLite DB with schema initialised."""
    from pkg_defender.db.schema import init_db

    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    yield conn
    conn.close()


@pytest.fixture()
def pq_binary(tmp_path: Path) -> Path:
    """Return a Path to a fake pkg-defender binary for service tests."""
    binary = tmp_path / "bin" / "pkgd"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    return binary


@pytest.fixture()
def mock_config() -> PKGDConfig:
    """Return a properly configured PKGDConfig with safe defaults.

    Use this instead of MagicMock() for config mocking. The default
    PKGDConfig has database.path=None, which prevents the MagicMock
    file leak bug where auto-generated truthy mock attributes cause
    sqlite3.connect() to create junk files with MagicMock repr names.

    Returns:
        PKGDConfig instance with default values.
    """
    from pkg_defender.config.settings import PKGDConfig

    return PKGDConfig()


@pytest.fixture(autouse=True)
def _reset_quiet_mode() -> Generator[None, None, None]:
    """Reset quiet mode after each test to prevent test pollution.

    The --quiet CLI flag sets a module-level _quiet_mode variable in
    pkg_defender.display. Without cleanup, a test that uses --quiet
    leaves _quiet_mode=True for all subsequent tests in the same
    worker, silently suppressing all Rich output.
    """
    yield
    from pkg_defender.display import set_quiet_mode

    set_quiet_mode(False)


@pytest.fixture(autouse=True)
def _cleanup_logging_handlers() -> Generator[None, None, None]:
    """Clear root logger handlers after each test to prevent handler accumulation.

    Tests that call setup_logging() add StreamHandler and RotatingFileHandler
    to the root logger. Without cleanup, subsequent tests inherit stale handlers,
    causing duplicate output and IndexError when accessing [0] on handler list.
    """
    yield
    import logging

    for handler in logging.getLogger().handlers[:]:
        handler.close()
    logging.getLogger().handlers.clear()


@pytest.fixture(autouse=True, scope="session")
def _cleanup_magicmock_files():
    """Remove any leaked MagicMock-named SQLite files after test session.

    Safety net: if any test creates a file with a MagicMock repr name
    (e.g., '<MagicMock name=...>.db'), this fixture cleans it up.
    This prevents junk files from accumulating in the project directory.
    Only targets files in the project root directory (not subdirectories),
    and only files ending in '.db' or containing '<' (MagicMock repr
    files always contain '<'). Uses glob patterns '*MagicMock*' and
    '*__truediv__*' — does NOT use '*mock*' (too broad).
    """
    yield  # Run all tests first

    import contextlib
    import glob as glob_mod

    # Clean up any files matching MagicMock repr patterns
    project_root = Path(__file__).parent.parent
    for pattern in ["*MagicMock*", "*__truediv__*"]:
        for path_str in glob_mod.glob(str(project_root / pattern)):
            path = Path(path_str)
            if path.is_file() and (path.suffix == ".db" or "<" in path.name):
                with contextlib.suppress(OSError):
                    path.unlink()
