# Tests for pkg-defender

This directory contains the test suite for pkg-defender. The suite uses
**pytest** with a structured `unit/`/`integration/`/`fixtures/` layout.

---

## Isolation Strategy

Tests run in complete isolation from your real home directory and
configuration. This prevents accidental modification of real RC files
(.zshrc, .bashrc, etc.) or use of real config/database files during testing.

### How Isolation Works

1. **`isolated_home` fixture (autouse)**: Defined in `tests/conftest.py:110-140`.
   Sets `HOME` to a temporary directory (`tmp_path/home`) for every test.
   After setup, it verifies that `Path.home()` resolves to within the isolated
   directory — failing the test if isolation is broken.

2. **`isolated_env` fixture**: Defined in `tests/conftest.py:40-88`. Patches
   `get_db_path()` and `get_default_config_path()` across all command modules
   to redirect config and database paths to `tmp_path`. Use this for tests that
   exercise CLI commands with real database or config access.

3. **Path redirection, not blanket mocking**: Tests use `tmp_path` (pytest's
   built-in temp directory) combined with `monkeypatch` and `unittest.mock` to
   redirect specific paths. There is no blanket "mock all file I/O" — instead,
   individual tests and fixtures redirect **which paths are used**.

### Key Fixtures (all in `tests/conftest.py`)

| Fixture                                         | Scope             | Description                                                             |
| ----------------------------------------------- | ----------------- | ----------------------------------------------------------------------- |
| `isolated_home` (`conftest.py:110`)             | autouse, function | Sets `HOME` to `tmp_path/home`; verifies isolation                      |
| `isolated_env` (`conftest.py:40`)               | function          | Patches `get_db_path` / `get_default_config_path` across modules        |
| `runner` (`conftest.py:28`)                     | function          | Returns a Click `CliRunner` for CLI command invocation                  |
| `db_conn` (`conftest.py:143`)                   | function          | Creates a temporary SQLite DB with schema initialized                   |
| `mock_config` (`conftest.py:164`)               | function          | Returns a `PKGDConfig` with safe defaults (avoids MagicMock file leaks) |
| `pq_binary` (`conftest.py:154`)                 | function          | Creates a fake `pkgd` binary for daemon/service tests                   |
| `_reset_quiet_mode` (`conftest.py:181`)         | autouse, function | Resets `--quiet` mode flag after each test                              |
| `_cleanup_logging_handlers` (`conftest.py:196`) | autouse, function | Clears root logger handlers after each test                             |
| `_cleanup_magicmock_files` (`conftest.py:210`)  | autouse, session  | Removes leaked MagicMock-named `.db` files after test session           |

The `tests/unit/conftest.py` and `tests/integration/conftest.py` both
re-export the global fixtures via `from tests.conftest import *`.

---

## ⚠️ Important: Development Safety

### Don't Run `pkgd` CLI Commands in the Project Directory

When developing on pkg-defender, **do not** run `pkgd` commands directly in
the project directory (or any directory where your real RC files are loaded).
This is because:

1. `pkgd setup` installs shell completion scripts, which is a write operation
2. If `HOME` is set to your real home directory, completion installation could
   affect your actual shell configuration
3. Development environments run without isolation safeguards that CI provides

**Note on `pkgd hooks`:** The `pkgd hooks` command (`src/pkg_defender/cli/commands/hooks.py`)
is **read-only output** — it prints shell function instructions to stdout and tells
users to add them manually to their RC files. It does NOT modify `.zshrc`,
`.bashrc`, or any other RC file. The write-behavior concern applies to
`pkgd setup`, which installs shell completions.

### If You Need to Test Hook-Related Features

The `isolated_home` fixture is `autouse=True`, so `HOME` is already isolated
for every test. No additional setup is needed. If a test requires specific
config or database path redirection, use `isolated_env`:

```python
def test_my_hook_feature(isolated_env: dict[str, Path]) -> None:
    """Test hook feature in isolated environment."""
    # isolated_env provides db_path and config_path
    # HOME is already isolated by isolated_home (autouse)
    ...
```

---

## Running Tests

```bash
# Run all tests
pytest tests/

# Run unit tests only
pytest tests/unit/

# Run integration tests only
pytest tests/integration/

# Run a specific test file
pytest tests/unit/cli/test_hooks_command.py

# Run with verbose output
pytest tests/ -v

# Run with coverage (90% threshold)
pytest --cov=src/pkg_defender --cov-fail-under=90
```

### CI Test Configuration

CI (`.github/workflows/ci.yml:128`) runs:
```bash
pytest --tb=short -q --cov=src/pkg_defender --cov-report=xml --cov-fail-under=90
```

An e2e gate (`.github/workflows/ci.yml:90`) runs first:
```bash
uv run pytest tests/integration/test_smoke_e2e.py --tb=short -q
```

### Configuration (from `pyproject.toml:79-92`)

| Setting            | Value                                                                  |
| ------------------ | ---------------------------------------------------------------------- |
| Parallel execution | `-n auto` with `--dist loadgroup`                                      |
| Timeout            | 300 seconds per test                                                   |
| `asyncio_mode`     | `auto`                                                                 |
| Custom markers     | `slow`, `network`, `smoke`, `unit`, `integration`, `xdist_group(name)` |

### Test Dependencies

Defined in `pyproject.toml:56-64`:
- `pytest>=8.0`
- `pytest-xdist>=3.8`
- `pytest-asyncio>=0.24`
- `pytest-cov>=7.1.0`
- `pytest-mock>=3.15.1`
- `pytest-timeout>=2.3.0`
- `aioresponses>=0.7`
- `coverage[toml]>=7.0`

Install with: `uv sync --dev` or `pip install -e ".[test]"`

---

## Test Organization

```
tests/
├── conftest.py          — Global fixtures, constants, cleanup (234 lines)
├── unit/                — Unit tests (~140 files)
│   ├── conftest.py      — Re-exports global fixtures
│   ├── audit/           — Auditor, bypass, doc audit regression tests
│   ├── cli/             — CLI commands, Click integration, UX, exit codes
│   ├── commands/        — CLI command subpackage tests
│   ├── config/          — Config loading, split-brain detection
│   ├── core/            — Core logic: display, checker, CI mode, param types
│   ├── daemon/          — Background daemon battery/scheduler tests
│   ├── db/              — Database layer tests
│   ├── intel/           — Intelligence source tests (OSV, NPM, PyPI, RSS, etc.)
│   ├── managers/        — Package manager coverage/compatibility tests
│   ├── models/          — Data model: aggregator, scorer, timezone handling
│   ├── registry/        — Package registry adapters (~35 files, all ecosystems)
│   ├── shells/          — Shell detection and installation tests
│   └── ...              — Top-level unit test files
├── integration/         — Integration tests (11 files)
│   ├── conftest.py                 — Re-exports global fixtures
│   ├── test_integration.py         — End-to-end integration tests (963 lines)
│   ├── test_smoke_e2e.py           — E2E smoke gate (CI block-on-fail gate)
│   ├── test_daemon.py              — Daemon integration tests
│   ├── test_scoring_e2e.py         — Scoring pipeline end-to-end
│   ├── test_first_run_flow.py      — First-run UX flow tests
│   ├── test_fail_closed_install.py — Fail-closed install scenario
│   └── docs/            — Doc audit integration test files
├── fixtures/            — Test data files
│   ├── conftest.py      — Re-exports `FIXTURES_DIR`
│   └── lock_files/      — Lock file samples (package-lock, yarn.lock, etc.)
└── README.md            — This file
```

---

## Coverage

- Coverage is measured with `pytest-cov` targeting `src/pkg_defender`
- **Current threshold: 90%** (`pyproject.toml:108`, CI enforces at `ci.yml:128`)
- Branch coverage is enabled (`pyproject.toml:103`)
- Coverage is uploaded to Codecov for the `ubuntu-24.04 / Python 3.12` matrix entry
