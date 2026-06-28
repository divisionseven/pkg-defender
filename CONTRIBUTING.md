# Contributing to PKG-Defender

Thank you for your interest in contributing to PKG-Defender. Every contribution — whether it's a bug report, feature suggestion, documentation improvement, or code change — helps make the tool better for everyone.

This document explains how to contribute effectively. Please read it before opening issues or submitting pull requests.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Your First Contribution](#your-first-contribution)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Config Generation](#config-generation)
- [Man Page Workflow](#man-page-workflow)
- [Testing](#testing)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Questions?](#questions)

---

## Code of Conduct

This project follows a [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you agree to uphold it.
Please report unacceptable behavior to the maintainer via the contact details in that document.

---

## Ways to Contribute

You don't have to write code to contribute meaningfully to PKG-Defender:

- 🐛 **Report bugs** using the [bug report template](https://github.com/divisionseven/pkg-defender/issues/new?template=bug_report.yml)
- 🚀 **Suggest features** using the [feature request template](https://github.com/divisionseven/pkg-defender/issues/new?template=feature_request.yml)
- 📖 **Improve documentation** — fix typos, clarify explanations, add examples
- 🧪 **Write tests** — especially for edge cases or untested code paths
- 🔍 **Triage issues** — help reproduce bugs, confirm behavior, or suggest labels
- 💬 **Answer questions** in [Discussions](https://github.com/divisionseven/pkg-defender/discussions)
- 📣 **Spread the word** — write about PKG-Defender, give a talk, or recommend it

---

## Reporting Bugs

Before reporting a bug:

1. Search [existing issues](https://github.com/divisionseven/pkg-defender/issues) to avoid duplicates
2. Make sure you're using the [latest release](https://github.com/divisionseven/pkg-defender/releases)
3. Check the [documentation](https://github.com/divisionseven/pkg-defender/blob/main/docs/index.md) — the behavior may be intentional

**For security vulnerabilities**, do NOT open a public issue. See [SECURITY.md](./SECURITY.md).

Use the [bug report template](https://github.com/divisionseven/pkg-defender/issues/new?template=bug_report.yml) to submit your report.

---

## Suggesting Features

Use the [feature request template](https://github.com/divisionseven/pkg-defender/issues/new?template=feature_request.yml).

Good feature requests include:
- A clear description of the **problem** you're trying to solve
- Your **proposed solution** and what it would look like in practice
- Why existing behavior or workarounds are insufficient

If you're unsure whether a feature is a good fit, start a [Discussion](https://github.com/divisionseven/pkg-defender/discussions) first.

---

## Your First Contribution

New to open source or to this project? Start with issues labelled [`good first issue`](https://github.com/divisionseven/pkg-defender/labels/good%20first%20issue) or [`help wanted`](https://github.com/divisionseven/pkg-defender/labels/help%20wanted).

**Before starting work on anything significant**, please comment on the issue to let the maintainer know you're working on it. This prevents duplicate effort. For new features without an existing issue, open one first and wait for a response before investing time in implementation.

---

## Development Setup

### Prerequisites

- Python 3.11 or later
- [pipx](https://pipx.pypa.io/) (recommended for installing `pkgd` itself during development)
- Git

### 1. Fork and Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/pkg-defender.git
cd pkg-defender
```

### 2. Install with uv (recommended)

```bash
uv sync --dev
```

This installs PKG-Defender in editable mode along with all development dependencies (pytest, ruff, mypy, pre-commit, python-dateutil). Requires [uv](https://docs.astral.sh/uv/getting-started/installation/) to be installed.

### 3. Install Pre-Commit Hooks (Required)

After setting up your environment, install the pre-commit hooks:

```bash
pre-commit install
```

This configures Git to automatically run linting (`ruff check --fix`), formatting (`ruff format`), type checking (`mypy`), and other quality checks before every commit. Hooks that fail will block the commit until fixed.

<details>
<summary>Alternative: pip-based setup</summary>

```bash
python -m venv .venv
source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate         # Windows (PowerShell)
pip install -e ".[test,lint]"
pre-commit install
```

</details>

### 4. Verify the Setup

```bash
pkgd --version
pytest --tb=short
ruff check .
mypy src/pkg_defender --strict
```

All commands should pass without errors on a fresh clone of `main`.

For full verification (including tests and build), run the manual check script:

```bash
./scripts/pre-commit-check.sh
```

---

## Project Structure

```
pkg-defender/
├── src/
│   └── pkg_defender/
│       ├── __init__.py
│       ├── _http.py            # Shared HTTP client
│       ├── audit/              # Cooldown engine, bypass service, reporter
│       ├── cli/                # Click command definitions
│       ├── config/             # Configuration system (dataclasses)
│       ├── core/               # Threat query pipeline (auditor, checker, parsers, scorer)
│       ├── daemon/             # Background daemon
│       ├── db/                 # Threat database schema (SQLite)
│       ├── display.py          # Terminal output formatting
│       ├── exceptions.py       # Custom exception types
│       ├── intel/              # Threat intelligence feed adapters
│       ├── logging_filter.py   # Log filtering utilities
│       ├── models/             # Data models
│       ├── py.typed            # PEP 561 marker
│       ├── registry/           # 29 registry adapters (npm, PyPI, apt, brew, cargo, etc.)
│       ├── shells/             # Shell hook generation
│       └── version.py          # Package version
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── fixtures/               # Lock files, repodata fixtures
│   ├── integration/            # End-to-end integration tests
│   └── unit/                   # Unit tests (mirrors src/ structure)
├── docs/                       # Diátaxis documentation
│   ├── examples/
│   ├── explanation/
│   ├── guides/
│   ├── man/
│   ├── reference/
│   └── tutorials/
├── .github/                    # CI/CD and contribution workflows
├── Formula/                    # Homebrew formula
├── scripts/                    # Development and CI automation
├── pyproject.toml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── ruff.toml
└── SECURITY.md
```

---

## Development Workflow

### Branching Strategy

| Branch            | Purpose                                                              |
| ----------------- | -------------------------------------------------------------------- |
| `main`            | Stable, released code. Never commit directly.                        |
| `develop`         | Integration branch for work-in-progress. Base your branches on this. |
| `feat/<name>`     | New features                                                         |
| `fix/<name>`      | Bug fixes                                                            |
| `docs/<name>`     | Documentation changes                                                |
| `chore/<name>`    | Maintenance, dependencies, CI                                        |
| `security/<name>` | Security fixes                                                       |

```bash
# Create a feature branch from develop
git checkout develop
git pull origin develop
git checkout -b feat/my-feature-name
```

### Keeping Your Fork in Sync

```bash
git remote add upstream https://github.com/divisionseven/pkg-defender.git
git fetch upstream
git rebase upstream/develop
```

---

## Code Standards

PKG-Defender enforces code quality with automated tools. All checks must pass before a PR can be merged.

### Style and Formatting — Ruff

```bash
ruff check .                  # Lint
ruff check . --fix            # Lint and auto-fix
ruff format .                 # Format
ruff format --check .         # Check formatting without modifying
```

### Type Checking — mypy (Strict Mode)

All public functions and methods must have complete type annotations.

```bash
mypy src/pkg_defender --strict
```

### General Guidelines

- Write clear, self-documenting code. Prefer explicit over implicit.
- Keep functions small and focused on a single responsibility.
- Add docstrings to all public modules, classes, and functions.
- Avoid adding new dependencies without prior discussion in an issue.
- When modifying CLI output, consider the `--json` flag and ensure JSON output remains stable.
- Exit codes must follow the conventions defined in `src/pkg_defender/cli/_exit_codes.py`.

---

## Config Generation

The TOML configuration system uses [tomlkit](https://github.com/sdispater/tomlkit) for
comment-preserving TOML generation and editing.

### Architecture

| Component                     | Location                              | Responsibility                                                                                                                    |
| ----------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `_generate_config_template()` | `src/pkg_defender/cli/common.py`      | Builds a fully-commented TOML document. Comments are hardcoded here — this is the single source for TOML formatting and comments. |
| `_write_config_toml()`        | `src/pkg_defender/cli/common.py`      | Atomic TOML string writer. Validates with `tomllib.loads()`, writes via temp file + `os.replace()`.                               |
| `PKGDConfig` dataclass        | `src/pkg_defender/config/settings.py` | Single source of truth for default VALUES (not comments).                                                                         |
| `tomlkit.parse()`             | Used in config commands               | Parse existing TOML while preserving comments for round-trip editing.                                                             |

### Workflows

- **`pkgd setup --init`**: Calls `_generate_config_template()` → `tomlkit.dumps()` → `_write_config_toml()`. Produces a beautiful, commented TOML file.
- **`pkgd setup` (re-run)**: Calls `_generate_config_template()` → parses existing config with `tomlkit.parse()` → overlays existing values onto template → `tomlkit.dumps()` → `_write_config_toml()`. Preserves user values while refreshing structure/comments.
- **`pkgd config set <key> <value>`**: Parses existing config with `tomlkit.parse()` → navigates to key → sets value → `tomlkit.dumps()` → `_write_config_toml()`. Preserves ALL user-added comments.
- **`pkgd config set-secret <key>`**: Same as `config set` but prompts for hidden input.

### What to Update When

| Change                          | Action                                                                                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Change a default value          | Update the dataclass field in `PKGDConfig` / section config in `settings.py` ONLY. The template reads values at runtime.                                                                             |
| Add a new config field          | Add dataclass field in `settings.py` + add field with comments to `_generate_config_template()` in `common.py`.                                                                                      |
| Change TOML comments/formatting | Update `_generate_config_template()` ONLY.                                                                                                                                                           |
| Sample file consistency         | `docs/examples/config/pkgd.toml` should be kept approximately in sync with the template output. Not enforced by CI, but maintainers should update it when the template format changes significantly. |

## Man Page Workflow

The man page is maintained as a **markdown source of truth** that is converted to troff at build time. Both files are committed to the repository so contributors without `pandoc` installed can still ship changes.

### Source of Truth

- **Markdown source** (human-edited): `docs/man/pkgd.1.md`
- **Generated troff** (committed, regenerated by `make man`): `docs/man/pkgd.1`

The generated `docs/man/pkgd.1` is what ships in the wheel at `share/man/man1/pkgd.1` — see `pyproject.toml:98-99` for the hatchling `wheel` target's `force-include` mapping.

### Tooling

| Tool     | Purpose                     | Required?                                                                                                                       |
| -------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `pandoc` | Markdown → troff conversion | **Required** for regenerating `docs/man/pkgd.1`. Install via `brew install pandoc` (macOS) or `apt-get install pandoc` (Linux). |
| `mandoc` | Man page syntax linter      | **Required in CI**, optional locally. Install via `brew install mandoc` (macOS) or `apt-get install mandoc` (Linux).            |

### Regenerating the Man Page

After editing `docs/man/pkgd.1.md`, regenerate the troff file:

```bash
make man
```

This runs:

1. `pandoc --standalone --to=man docs/man/pkgd.1.md -o docs/man/pkgd.1`
2. `mandoc -Tlint docs/man/pkgd.1` — fails the build if the generated man page has syntax errors

The `mandoc -Tlint` step is **also** run in CI (see `.github/workflows/ci.yml`, the `lint` job) so a broken man page will block PRs.

### CI Verification

The CI pipeline (`.github/workflows/ci.yml`) performs two man-page checks:

1. **Lint** (`lint` job, after `Type check (mypy)`) — runs `mandoc -Tlint docs/man/pkgd.1`. Fails the build on any man-page syntax error.
2. **Wheel packaging** (`e2e-gate` job, after the blocking pipeline test) — builds the wheel and asserts the man page is in `zipfile.ZipFile.namelist()`. Catches the failure mode where `pyproject.toml` is misconfigured and the man page silently fails to ship.

### When to Regenerate

You **must** regenerate `docs/man/pkgd.1` (by running `make man` and committing the result) whenever any of the following change:

- A command is added, removed, or renamed
- An option, argument, or env var is added, removed, or has its default changed
- An exit code is added, removed, or has its semantics changed
- A subcommand (e.g., `logs follow`, `db snapshot`) is added or has its options changed
- A new package manager is added to `UNIFIED_MANAGER_REGISTRY` or `MANAGER_NAMES`
- A new feed is added to `intel sync` or any feed's enable/disable default changes

The CI lint and wheel-packaging checks will fail if the generated file is stale relative to the markdown source — but **not** the other way around. Run `make man` before opening a PR.

### How to Add a New Command to the Man Page

1. Open `docs/man/pkgd.1.md` in your editor.
2. Add a new `**command_name**` line under the appropriate `##` section (`## Common Commands`, `## Management Commands`, `## Other Commands`, or `## Package Manager Commands`).
3. For subcommands, use the indented definition list syntax (term on one line, `:` indented on the next).
4. Run `make man` to regenerate the troff file.
5. Commit **both** `docs/man/pkgd.1.md` and `docs/man/pkgd.1` in the same commit.

Example — adding a new subcommand `pkgd foo bar`:

```markdown
**foo bar** [**\--baz** *NAME*]
:   Description of the bar subcommand.
```

If your new command introduces a new env var, exit code, or global option, also update the relevant section (`# ENVIRONMENT`, `# EXIT STATUS`, `# GLOBAL OPTIONS`).

## Testing

PKG-Defender uses `pytest`. All changes must include appropriate test coverage.

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src/pkg_defender --cov-report=term-missing

# Run a specific test file
pytest tests/unit/audit/test_cooldown.py

# Run tests matching a keyword
pytest -k "test_cooldown"
```

### Test Guidelines

- Unit tests go in `tests/unit/` — mock external dependencies (network, filesystem, registry).
- Integration tests go in `tests/integration/` — test real interactions where necessary.
- Use Click's `CliRunner` for testing CLI commands.
- Do not make real network requests in unit tests.
- Test both success paths and failure/edge cases.
- Aim for high coverage of the cooldown engine and feed ingestion logic, as these are security-critical.

#### Coverage Gate

The CI pipeline has two coverage gates:

1. **End-to-end blocking test** (`e2e-gate` job) — runs `tests/integration/test_smoke_e2e.py`
   on ubuntu-24.04 / Python 3.12. This gate catches functional regressions in the core
   threat-checking, cooldown, and blocking pipeline. It fails fast, before the full test matrix.

2. **Line-rate coverage threshold** (`--cov-fail-under=90`) — enforced across all 9 matrix
   entries. Prevents overall coverage drift. A commit that breaks threat checking will fail
   gate 1 even if gate 2 passes.

---

## Commit Message Format

PKG-Defender follows the [Conventional Commits](https://www.conventionalcommits.org/) specification.

```
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | When to Use                                |
| ---------- | ------------------------------------------ |
| `feat`     | A new feature                              |
| `fix`      | A bug fix                                  |
| `docs`     | Documentation changes only                 |
| `style`    | Formatting, whitespace (no logic changes)  |
| `refactor` | Code restructuring (no functional changes) |
| `perf`     | Performance improvements                   |
| `test`     | Adding or updating tests                   |
| `build`    | Build system or dependency changes         |
| `ci`       | CI/CD configuration changes                |
| `chore`    | Maintenance, tooling, minor tasks          |
| `revert`   | Reverting a previous change                |

---

## Pull Request Process

### Submitting a Pull Request

1. **Fork** the repository and create a branch following the
   [branching strategy](#branching-strategy):
   - `feat/<name>` for new features
   - `fix/<name>` for bug fixes
   - `docs/<name>` for documentation changes
   - `chore/<name>` for maintenance, dependencies, CI
   - `security/<name>` for security fixes
2. **Target `develop`** for all branches except hotfixes (which target `main`).
3. **Write Conventional Commits** — every commit must follow the
   [format](#commit-message-format). The PR title must also follow this format.
4. **Update `CHANGELOG.md`** — add a brief entry under `[Unreleased]` describing
   your change.
5. **Open the PR** using the [PR template](https://github.com/divisionseven/pkg-defender/blob/main/.github/PULL_REQUEST_TEMPLATE.md).

### PR Requirements

Before a PR can be merged, **all** of the following must pass:

| Gate       | Command                                      | Description                    |
| ---------- | -------------------------------------------- | ------------------------------ |
| Lint       | `ruff check .`                               | Code style and error detection |
| Format     | `ruff format --check .`                      | Formatting consistency         |
| Type check | `mypy src/pkg_defender --strict`             | Type safety                    |
| Tests      | `pytest`                                     | All tests pass                 |
| Coverage   | `pytest --cov-fail-under=90`                 | 90% minimum line coverage      |
| E2E gate   | `pytest tests/integration/test_smoke_e2e.py` | Core pipeline smoke test       |
| Man page   | `mandoc -Tlint docs/man/pkgd.1`              | Man page syntax validity       |

Run the pre-commit check script to verify all gates locally:

```bash
./scripts/pre-commit-check.sh
```

### Review Process

1. A maintainer will review your PR for correctness, test coverage, and
   adherence to the project's code standards.
2. **CI runs automatically** on every push — lint, type check, test matrix
   (9 entries), and e2e gate. All must pass before review.
3. **Dependency review** runs automatically on PRs to `main`/`develop` via
   `.github/workflows/dependency-review.yml`. It blocks PRs with CVSS ≥ 7.0
   vulnerabilities or GPL-3.0/AGPL-3.0 licenses.
4. Address review feedback by pushing additional commits (do not force-push
   during review — it breaks comment threads).
5. Once approved and all checks pass, a maintainer will merge the PR.

---

## Release Process

### How Releases Are Triggered

Releases are **fully automated** and triggered by pushing a version tag:

```bash
git tag v1.2.3
git push origin v1.2.3
```

For pre-releases:

```bash
git tag v1.2.3-beta.1
git push origin v1.2.3-beta.1
```

The tag **must** match the version in `pyproject.toml` and there **must** be a
corresponding entry in `CHANGELOG.md`. Both are validated before any build
artifacts are produced.

### Who Can Trigger Releases

Only repository maintainers with push access to tags can trigger a release.
The release workflow runs in the GitHub Actions environment and requires no
manual intervention beyond the tag push.

### What the CI/CD Pipeline Does

The release pipeline (`.github/workflows/release.yml`) runs 8 jobs in
dependency order:

```
 Trigger: Push a version tag — v1.2.3, v2.0.0-beta.1, etc.

 Pipeline (jobs run in dependency order):

   validate ───► ci ─┬┬─► build ───► prep-gh-release ─┬─► publish ──► smoke-test
                     ││                               │
                     ││                               └─► update-homebrew-tap
                     │└─► build-binaries                  (if stable release)
                     │    (linux, macOS, Windows)
                     │
                     └──► build-docker-image & run-trivy-scan
```

| Job                | What It Does                                                                                                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **validate**       | Verifies the tag version matches `pyproject.toml` and `CHANGELOG.md` has an entry for this version. Extracts changelog notes as a release artifact.                                                                      |
| **ci**             | Runs the full CI pipeline (lint, type check, 9-entry test matrix) as a reusable workflow call.                                                                                                                           |
| **build**          | Builds sdist + wheel (`python -m build`), generates a CycloneDX SBOM. All artifacts uploaded.                                                                                                                            |
| **build-docker**   | Builds the Docker image and runs Trivy vulnerability scanning against it. Fails the release if Trivy detects critical or high severity vulnerabilities.                                                                   |
| **build-binaries** | Builds standalone PyInstaller binaries for 4 platforms: `pkgd-linux-amd64`, `pkgd-darwin-amd64`, `pkgd-darwin-arm64`, `pkgd-windows-amd64.exe`. Each binary gets a SHA256 checksum.                                      |
| **github-release** | Assembles release body from changelog notes, creates a GitHub Release, and attaches all artifacts (sdist, wheel, binaries, SBOM).                                                                                        |
| **publish**        | Downloads the built sdist/wheel and publishes to PyPI using trusted publishing (`pypa/gh-action-pypi-publish`).                                                                                                          |
| **smoke-test**     | Installs the published package from PyPI into a fresh venv, verifies `pkgd --help` works, checks version matches the tag, and runs a threat-blocking smoke test. Retries with polling (up to 120s) for PyPI propagation. |

> **Trivy vulnerability scanning:** The `build-docker` job scans the built
> Docker image with Trivy before the release proceeds. `CRITICAL` and `HIGH`
> severity findings cause the workflow to fail, preventing vulnerable images
> from being published.

### Release Artifacts

Each release includes:

| Artifact                              | Description                          |
| ------------------------------------- | ------------------------------------ |
| `pkg_defender-X.Y.Z.tar.gz`           | Source distribution                  |
| `pkg_defender-X.Y.Z-py3-none-any.whl` | Python wheel                         |
| `pkgd-linux-amd64`                    | Linux binary (x86_64)                |
| `pkgd-darwin-amd64`                   | macOS binary (Intel)                 |
| `pkgd-darwin-arm64`                   | macOS binary (Apple Silicon)         |
| `pkgd-windows-amd64.exe`              | Windows binary (x86_64)              |
| `sbom.json`                           | CycloneDX Software Bill of Materials |
| `*.sha256`                            | SHA256 checksums for each binary     |

### Preparing a Release

Before pushing a tag:

1. Update `pyproject.toml` with the new version number.
2. Add a changelog entry in `CHANGELOG.md` under the version heading, following
   [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
3. Ensure all CI checks pass on `develop`.
4. Merge `develop` into `main` (or ensure the tag is on a commit that has passed
   CI).
5. Push the version tag.

---

## Questions?

If you have questions about contributing, open a
[Discussion](https://github.com/divisionseven/pkg-defender/discussions) or
comment on the relevant issue. For security vulnerabilities, see
[SECURITY.md](./SECURITY.md).
