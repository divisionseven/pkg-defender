# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- CI workflow (`.github/workflows/ci.yml`): added `develop` branch to `push` and `pull_request` triggers.
- Release notes generator (`.github/scripts/build-release-notes.py`): removed bold markdown formatting from `since {prev_tag}` label in commits section.
- Modified snapshot release body markdown template
- `github-action/`: validate inputs in `shouldFailOnThreat()`, use `Math.max()` for exit code comparison, fix singular/plural grammar in summary

### Removed

- `github-action/README.md`: remove legacy inputs from table, correct fail-on documentation
- `github-action/action.yml`: remove `value` from outputs (composite action syntax, invalid for node20 actions), remove unused `ecosystems`, `db-snapshot`, `token` inputs
- Remove Homebrew tap command unavailability notice from root `README.md` now that the Homebrew tap is officially published.

### Fixed

- `github-action/` release workflow (`release.yml`): `actions/upload-artifact@v4` strips the `dist/` prefix from single-file uploads, causing the release step's artifact glob to fail — changed upload path to directory form, removed orphaned changelog-notes upload/download steps.
- OSSF Malicious Packages feed (`ossf_malicious.py`): GitHub Git Trees API response truncates above ~7MB / 100k entries, silently returning incomplete data — the `ossf/malicious-packages` repository has outgrown this limit. Replaced the Trees API + per-file raw fetch architecture with a single streamed tarball download from `codeload.github.com` and a lightweight commit-SHA change-detection check (`GITHUB_COMMIT_URL`) to skip redundant downloads. Added `_get_latest_commit_sha()`, `_download_and_extract()`, `_extract_and_parse()` methods; changed caching key from `ossf_malicious_tree_sha` to `ossf_malicious_commit_sha`; progress callback now emits heartbeat `(n, n)` every 500 files. Removed `BATCH_SIZE`, `DEFAULT_CONCURRENCY`, `UNAUTHENTICATED_CONCURRENCY`, `GITHUB_TREE_URL`, `GITHUB_RAW_BASE` constants. Tests rewritten to match: Tree API mock helpers replaced with `_make_tarball()` fixture; `TestOSSFMaliciousFeedFetch` expanded from 13 to 19 tests; `TestTreeSHACaching` → `TestCommitSHACaching` (6 tests); 3 heartbeat progress tests in `TestProgressReporting`; 8 constants tests in `TestConstants`. All 37 existing helper function tests preserved unchanged. Validated against the real ossf/malicious-packages repository: 228,192 records parsed in 24.7 seconds with zero failures. The old Trees API approach was both truncated (response capped at ~7MB / 100k entries) and slow (~20 minutes).
- `github-action/tests/validate.sh`: reduce REQUIRED_INPUTS from 5 to 2 (fail-on, lock-files)
- `github-action/LICENSE`: add Apache-2.0 license file for standalone publication
- `github-action/package-lock.json`: regenerate with Apache-2.0 license
- `.gitignore`: anchor `dist/` to `/dist/` so `github-action/dist/` is no longer ignored
- `github-action/package.json`: license ISC→Apache-2.0, author empty→divisionseven, add `private: true`
- Update local `homebrew-tap/Formula/pkg-defender.rb` Homebrew formula with latest published version from `divisionseven/homebrew-pkg-defender` tap repository to maintain consistency between local and tap repo.

## [1.0.3] - 2026-07-05

### Fixed

- Release pipeline: Homebrew tap validated a stale formula because `brew tap <path>` / `git clone <path>` copies only committed state — `sed -i` modifications to the formula were applied to the working tree but never committed, so the `brew tap`/`git clone` pair silently discarded them. The tap name `divisionseven/tap` also pointed to the wrong GitHub repository (`divisionseven/homebrew-tap`). Added a `git commit` step before `brew tap` to persist formula changes; corrected tap name to `divisionseven/pkg-defender`; PR creation now uses `git commit --amend` for proper commit messages (`release.yml`). Regression test: `brew audit`, `brew install`, and `brew test` now run against the committed formula as Homebrew actually sees it.
- Release pipeline: PyInstaller binary missing all 14 CLI commands due to a circular import — when PyInstaller loads `main.py` as `__main__`, command modules do `from pkg_defender.cli.main import cli` but since `__main__` ≠ `pkg_defender.cli.main`, Python creates a second `cli` object; all commands register on the second object while `run_cli()` uses the first (empty) one. Added `src/pkg_defender/__pkgd_entry__.py` — a thin wrapper that imports `run_cli` from the canonical module path, ensuring a single `cli` object with all commands. Updated `scripts/build_binary.sh` and `release.yml` to use the wrapper entry point. Regression test: `pkgd --help` and `pkgd status --json` in smoke test now exercise all commands through the frozen binary.

## [1.0.2] - 2026-07-04

### Fixed

- Smoke test only tested the pip-installed package, never the PyInstaller binary — version mismatches or broken CLI commands passed CI undetected. Added `build-binaries` to smoke-test `needs`; downloads `linux-amd64` binary artifact; verifies `--version` matches the release tag; verifies `--help` and `status --json` respond correctly (`release.yml`). Regression test: binary version mismatch now fails CI.
- PyInstaller frozen binary always reported `1.0.0` because the hardcoded version fallback at `__init__.py:25` (Tier 4) was never updated beyond v1.0.0. Added Tier 3.5 fallback — CI generates `src/pkg_defender/_build_version.py` at build time with the actual release version, bundled into the binary via the import graph (`__init__.py:18-23`). The import uses `# type: ignore[import-not-found]` to accommodate mypy since the file is generated post-check. Falls through to `"1.0.0"` only if all prior methods fail (`release.yml`, `.gitignore`). Regression test: `pkgd --version` in the PyInstaller binary now reports the correct version.
- `check-version.py` regex `^__version__` with `re.MULTILINE` required `__version__` at column 0, but all assignments in `__init__.py` are indented inside try/except blocks — version validation was silently skipped for indented files. Changed regex to `^\s*__version__` to allow leading whitespace (`check-version.py:167`). Regression test: old regex returns `None` on indented `__version__`; new regex correctly captures the version.
- Homebrew formula `desc` was 107 characters (max 80) and started with "The" — caused `brew audit --new --formula pkg-defender` to fail. Shortened `desc` to 69 characters with no leading article; Regression test: `brew audit --new --formula pkg-defender` now passes.
- Release pipeline Homebrew tap update job failed on `ubuntu-latest` (24.04) runners because Homebrew is pre-installed at `/home/linuxbrew/.linuxbrew/bin` but excluded from `$PATH` (actions/runner-images#6283). Added a `Set up Homebrew PATH` step that writes the path to `$GITHUB_PATH` before the first `brew` invocation (`release.yml`).

## [1.0.1] - 2026-07-03

### Fixed

- Fix release pipeline: binary artifacts for non-Windows platforms were not published in v1.0.0 due to a GitHub Actions artifact-naming collision
- Fix smoke test schema mismatch.

## [1.0.0] - 2026-07-03 PKG-Defender Initial Public Release

### Added

- `pkgd audit` — Lock file scanner for threats and cooldown violations across 7 lock file formats
- `pkgd audit-logs` — Audit event log queries with filtering and aggregate statistics
- `pkgd bypass` — Create targeted bypass entries for cooldown and threat checks (development environments only)
- `pkgd completion` — Shell tab-completion script generation for bash, zsh, fish, PowerShell, and Nushell
- `pkgd config` — Full configuration management with 7 subcommands (view, list, options, set, set-secret, get, reset)
- `pkgd daemon` — Background daemon with process management and system service installation
- `pkgd db` — Database snapshot management with SHA256 verification and integrity checking
- `pkgd health` — System diagnostic checks for config, database, feed sync, API tokens, and disk space
- `pkgd hooks` — Shell function generation for intelligent, transparent package manager command wrapping
- `pkgd intel` — Intelligence feed management with sync, search, and threat reporting
- `pkgd logs` — Log viewer with tail-follow capability
- `pkgd reset` — Complete tool state reset (threat database, config, logs, daemon state)
- `pkgd setup` — Interactive first-run wizard with shell detection, config creation, and initial feed sync
- `pkgd status` — Overview of feed health, active bypasses, and threat summary by severity
- Registry adapters for 18+ ecosystems — npm, PyPI, Homebrew, Cargo, RubyGems, APT, DNF, YUM, Bun, Bundler, Composer, Conda, Pipenv, pnpm, Poetry, uv, Yarn, and Gem
- Unified registry adapter protocol with batch operations, search, and dependency resolution
- OSV.dev feed — Open Source Vulnerability database synchronization
- GitHub Security Advisories (GHSA) — Curated security advisory feed
- npm Advisory — npm-specific security advisory feed
- OpenSSF Malicious Packages — Community-reported malicious package feed
- Socket.dev — Real-time package risk assessment API
- RSS feed ingestion — Configurable RSS security feed support
- Social intelligence feeds — Mastodon, Reddit, and X/Twitter threat monitoring
- Concurrent feed aggregator — Parallel sync across all intelligence sources
- Lock file auditor — Scans package-lock.json, poetry.lock, requirements.txt, yarn.lock, pnpm-lock.yaml, uv.lock, and Pipfile.lock
- Cooldown engine — Time-based package age enforcement with configurable windows and per-package overrides
- Threat scorer — Confidence-weighted scoring with severity multipliers and recency decay
- Pre-install checker — Real-time threat database querying before package installation
- Background daemon with PID file management and heartbeat monitoring
- Platform service generators — launchd (macOS), systemd (Linux), and Task Scheduler (Windows) support
- TOML-based configuration with layered precedence (defaults to file to environment variables)
- PKGD\_ prefix environment variable overrides for all configuration settings
- SQLite-powered threat database with WAL mode for concurrent access
- Database snapshot downloads from GitHub Releases with cryptographic verification
- Shell detection and completion script installation for bash, zsh, fish, PowerShell, and Nushell
- Async HTTP client with connection pooling and automatic retry logic
- Rich terminal output formatting with color-coded severity indicators
- Structured logging with rotation, CI-friendly modes, and log level controls
- XML external entity (XXE) protection via defusedxml for safe XML parsing
- Zstandard decompression support for compressed RPM repodata
- Docker multi-stage build (python:3.11-alpine, non-root user)
- GitHub Action for CI/CD pipeline integration
- Homebrew formula for macOS installation
- Man page with full command reference
- Pre-built binary distribution for macOS (arm64, amd64), Linux (amd64), and Windows (amd64)
