# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.7] - 2026-07-23

### Fixed

- `pip install` with `--hash=<sha>` CLI flag rejected by pip ≥26.1.2 — root
  cause: `--hash` is a per-requirement option valid only inside pip requirements
  files, not as a CLI flag. Moved `--hash` into a temp requirements file
  (`printf '%s\n' 'uv==0.5.1 --hash=...' > /tmp/uv-requirements.txt && pip
  install -r /tmp/uv-requirements.txt --require-hashes`) in
  `.clusterfuzzlite/build.sh` and `.github/workflows/release.yml`, preserving
  SHA256 pinning and OpenSSF Scorecard Pinned-Dependencies compliance.

## [1.0.6] - 2026-07-21

### Added

- ClusterFuzzLite fuzzing integration — `.clusterfuzzlite/Dockerfile` and `.clusterfuzzlite/build.sh` for OSS-Fuzz compatible continuous fuzzing infrastructure
- Atheris fuzz test for lock file parsing — `fuzz/parse_lockfiles_fuzz.py` with `atheris>=2.3.0` under `[fuzz]` optional dependencies
- `GOVERNANCE.md` — project governance document defining roles, decision-making, and conflict resolution processes
- Secure design principles statement in `docs/explanation/security-model.md`
- Property-based fuzzing tests using hypothesis — 6 invariants verified
  for threat scoring logic (`tests/unit/core/test_scoring_properties.py`)
- hypothesis>=6.0 dependency added to test profile
- Trigger improvements: Both sync workflows now support `workflow_dispatch` (manual trigger from GitHub UI) and a weekly `schedule` (Monday 6am UTC) as safety nets, in addition to the push-based path trigger. This ensures changes are synced even when the push path filter misses them (e.g., when changes span multiple commits and only the HEAD commit matches the path filter, or diff timeouts/limits are hit).
- Explicit content-based sync detection: Both sync workflows now use `diff -q` / `diff -rq` for file comparison instead of `git status --porcelain`. This provides:
- Clear per-file match/mismatch logging in workflow output
- True content comparison (not timestamp-based) with no reliance on git commit history
- Two-phase detection-then-apply: files are compared before any are copied
- A safety-net verification step after apply to catch any discrepancies
- `sync-brew-formula.py` now supports `--output` flag for two-phase formula detection, enabling the merge result to be inspected before overwriting the target.
- Cross-repo sync workflows: Two new GitHub Actions workflows and a Python merge script that automatically sync the `homebrew-tap/` and `github-action/` source-of-truth directories to their respective subsidiary repos (`divisionseven/homebrew-pkg-defender` and `divisionseven/pkg-defender-action`) whenever files in those directories change on `main`.
- `.github/workflows/sync-homebrew-tap.yml` — Syncs `homebrew-tap/` → `homebrew-pkg-defender` via PR. Uses a smart-merge script to preserve `version`/`url`/`sha256` from the target formula (set by the release pipeline) while applying all other structural changes (desc, caveats, test block, etc.) from source.
- `.github/workflows/sync-github-action.yml` — Syncs `github-action/` → `pkg-defender-action` via full directory rsync, excluding `node_modules/`, `plans/`, and `internal_documentation/`.
- `.github/scripts/sync-brew-formula.py` — Standalone Python script for section-aware Homebrew formula merging, preserving only version/URL/SHA256 from the target.
- CodeQL SAST scanning workflow (`.github/workflows/codeql.yml`) — runs on push/PR to main/develop and weekly schedule for Python code analysis
- OpenSSF Scorecard analysis workflow (`.github/workflows/scorecard.yml`) — evaluates repository security posture, pushes results to Scorecard API and uploads SARIF to code scanning
- SLSA Build Level 3 provenance generation in release pipeline via `slsa-github-generator` — provides verifiable build integrity attestations for all release artifacts
- Binary artifact attestations via `actions/attest-build-provenance` — cryptographically links release binaries to their build workflow
- Docker image provenance attestation with push-to-registry in release pipeline
- SPDX license and copyright headers (`# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)` and `# SPDX-License-Identifier: Apache-2.0`) added to all 113 source files under `src/pkg_defender/`
- `scripts/add_spdx_headers.py` — automated script for managing SPDX and copyright headers across the codebase

### Changed

- `tests/fixtures/lock_files/osv-scanner.toml` added with `[[PackageOverrides]] ignore = true` to suppress 20 OSV-Scanner false positives from test fixture lock files — fixes OpenSSF Scorecard Vulnerabilities check scoring 0/10
- `idna>=3.15` constraint added to `[project.dependencies]` — resolves PYSEC-2026-215 (idna 3.11 vulnerable); `uv.lock` upgraded idna from 3.11 to 3.18
- `github-action/` dev dependencies refreshed via `npm audit fix`: `@babel/core` 7.29.0→7.29.7 (GHSA-4x5r-pxfx-6jf8), `js-yaml` 3.14.2→3.15.0 (GHSA-h67p-54hq-rp68)
- `aiohttp` dependency updated from `>=3.9,<3.14` to `>=3.14.1,<4.0` — resolves 21 CVEs in the HTTP client
- `github-action/` dependencies refreshed: `@actions/core` bumped to 2.x, `undici` overridden to 6.27.0 — fixes 3 HIGH severity CVEs
- SLSA provenance job now sets `upload-assets: true` so `*.intoto.jsonl` attestation artifacts appear in GitHub Release assets
- Replaced all `pip install` commands with SHA256-pinned `uv` equivalents in CI workflows (ci.yml, release.yml, github-action/ci.yml) for reproducible dependency installation
- `python:3.11-alpine` Docker image base pinned to SHA256 digest for immutable builds
- `CONTRIBUTING.md` — added Developer Certificate of Origin (DCO) requirement with sign-off instructions
- `docs/explanation/security-model.md` — added Secure Design Principles section covering fail-closed, least privilege, defense in depth, secure defaults, and input validation
- `README.md` — added OpenSSF Scorecard and OpenSSF Best Practices (placeholder) badges to header
- Downstream workflow commits (`release.yml`, `sync-homebrew-tap.yml`, `sync-github-action.yml`) now authored as `Division 7` with `Co-authored-by: github-actions[bot]` instead of pure bot authorship for traceability
- `.github/workflows/release.yml` token permissions scoped from `contents: write` to `contents: read` with per-job overrides, following the least-privilege principle

### Fixed

- PyPI publish rejected with "400 File too large. Limit is 100 MB" — root
  cause: Hatchling's default VCS mode bundled all git-tracked files into the
  sdist, including 3 demo GIFs (152 MB total) in `docs/assets/demo/`. Added
  `[tool.hatch.build.targets.sdist]` with `exclude` patterns for 12 dev-only
  directories. sdist reduced from ~150 MB to 1.9 MB.
- Release pipeline: PyPI publish job no longer fails with `uv: command not found` — added `astral-sh/setup-uv` step and switched to `uv publish dist/*` (replacing twine-based publish). Binary build no longer crashes with `ModuleNotFoundError: No module named 'click'` in Homebrew — switched from `uv tool run pyinstaller` to `uv run pyinstaller` so PyInstaller can see all project dependencies. Added `pyinstaller>=6.21.0` as a dev dependency.
- Release pipeline `build-docker` job failed with "Resource not accessible by integration" when calling the GitHub Attestations API — root cause: the job's `permissions` block was missing `attestations: write` and `artifact-metadata: write`, so the `GITHUB_TOKEN` could not authorize the attestation call. Added both permissions to the `build-docker` job (`release.yml`). Verified by the full test suite passing (4,481 tests).
- SLSA provenance generator failed with a ref-format error when `release.yml` is pinned to a commit SHA — root cause: `slsa-github-generator`'s `builder-fetch.sh` requires a `refs/tags/vX.Y.Z` ref but received a bare SHA, so the script could not resolve the generator source. Added `compile-generator: true` to the `provenance` job, which bypasses `builder-fetch.sh` and compiles the generator from source instead. This keeps the workflow SHA-pinned and maintains OpenSSF Scorecard Pinned-Dependencies compliance (`release.yml`). Verified by the full test suite passing (4,481 tests).
- `actions/attest-build-provenance` was pinned to v2.4.0, which internally uses Node.js 20 — root cause: Node.js 20 reached end-of-life on the GitHub Actions runners, causing the attestation step to fail with a Node.js deprecation error. Updated `actions/attest-build-provenance` to v4.1.1 (SHA `0f67c3f4856b2e3261c31976d6725780e5e4c373`), which uses Node.js 24. Also updated `docker/build-push-action` from v7.0.0 to v7.3.0 (SHA `53b7df96c91f9c12dcc8a07bcb9ccacbed38856a`) to pick up bugfixes in the Docker build step (`release.yml`).
- Docker build failure: replace unsupported `uv pip install --user` with `uv pip install --system` to fix compatibility with newer uv versions
- Update GitHub Actions to Node.js 24-compatible versions to prevent deprecation failures across 10 workflow files
- Downstream repo checkout in `release.yml`, `sync-homebrew-tap.yml`, and `sync-github-action.yml` failed because `actions/checkout` rejects `/tmp/` paths outside the workspace. Replaced `actions/checkout` with `git clone` using the GitHub App token for all downstream repo checkouts
- Sync workflow commits to downstream repos were unsigned, triggering GitHub's "unsigned commit" security alerts on `homebrew-pkg-defender` and `pkg-defender-action`. Replaced manual `git commit`/`git push` operations with `peter-evans/create-pull-request@v8` and `actions/create-github-app-token@v3` in `sync-homebrew-tap.yml`, `sync-github-action.yml`, and `release.yml` — all downstream commits are now signed by the GitHub App identity
- GitHub Action CI failed on Ubuntu 24.04 runners due to PEP 668 blocking system-wide Python package installs (`externally-managed-environment`). Replaced `python3 -c "import yaml..."` YAML validation in `validate.sh` with Node.js `require('yaml')` and removed the now-unnecessary `setup-uv` + `uv pip install --system pyyaml` steps from the action's CI and release workflows
- `aiohttp>=3.14.1,<4.0` constraint — the requirement was
  incorrectly constrained to `aiohttp<3.14` during aiohttp 3.14/`aioresponses`
  0.7.9 compatibility investigation. Added a temporary patching fixture in
  `tests/conftest.py` that defaults `ClientResponse.__init__`'s required
  `stream_writer` argument to `Mock(output_size=0)` when omitted by
  `aioresponses._build_response()`. The fixture is session-scoped and
  autouse; it auto-disables on aiohttp < 3.14. To be removed when
  `aioresponses >= 0.8.0` ships [upstream PR #288](https://github.com/pnuckowski/aioresponses/pull/288).
- `sync-github-action` workflow no longer destroys the target downstream repo's `.git/` directory during rsync sync

### Security

- Update `actions/checkout` from v4 to v7.0.1
- Update `actions/setup-python` from v5 to v6.3.0
- Update `actions/upload-artifact` from v4 to v7.0.1
- Update `actions/download-artifact` from v4 to v8.0.1
- Update `github/codeql-action` from v3 to v4
- Update `docker/build-push-action` from v6 to v7
- Update `codecov/codecov-action` from v5 to v6.0.0
- Update `actions/stale` from v9 to v10.4.0
- Update `softprops/action-gh-release` from v2 to v3.0.2
- Update `EndBug/label-sync` to v2.3.3
- Token-Permissions: All 7 workflow files (ci.yml, snapshot.yml, dependency-review.yml, stale.yml, label-sync.yml, scorecard.yml, release.yml) scoped to `contents: read` at top level with job-level write overrides where required
- Pinned-Dependencies: Docker base image pinned to SHA256 digest; all CI `pip install` replaced with SHA256-pinned `uv` commands for reproducible dependency resolution
- Signed-Releases: SLSA provenance job now publishes `*.intoto.jsonl` attestation artifacts to GitHub Release assets via `upload-assets: true`
- Vulnerabilities: `aiohttp` bumped from `>=3.9,<3.14` to `>=3.14.1,<4.0` (21 CVEs fixed); `github-action/` dependencies updated (`@actions/core` to 2.x, `undici` overridden to 6.27.0 — 3 HIGH CVEs fixed)
- Fuzzing: ClusterFuzzLite integration with Atheris-based lock file parser fuzz test (`fuzz/parse_lockfiles_fuzz.py`)
- Hypothesis property-based fuzzing tests added for threat scoring invariants
- CodeQL SAST scanning workflow (`.github/workflows/codeql.yml`) — runs on push/PR to main/develop and weekly schedule for Python code analysis
- OpenSSF Scorecard analysis workflow (`.github/workflows/scorecard.yml`) — evaluates repository security posture, pushes results to Scorecard API and uploads SARIF to code scanning
- SLSA Build Level 3 provenance generation in release pipeline via `slsa-github-generator` — provides verifiable build integrity attestations for all release artifacts
- Binary artifact attestations via `actions/attest-build-provenance` — cryptographically links release binaries to their build workflow
- Docker image provenance attestation with push-to-registry in release pipeline
- SPDX license and copyright headers (`# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)` and `# SPDX-License-Identifier: Apache-2.0`) added to all 113 source files under `src/pkg_defender/`
- `scripts/add_spdx_headers.py` — automated script for managing SPDX and copyright headers across the codebase

## [1.0.5] - 2026-07-07

### Added

- Timing instrumentation in pre-install check: Phase-level timing logging via `time.monotonic()` in `_run_pre_install_check_async` for instant diagnosis of future timeout issues.

### Changed

- Feed sync error handling: added `FeedSyncError` exception class and `error_callback` parameter to `sync_all()` — callers can now handle per-feed errors without relying solely on the progress callback.
- Added `retry_on_busy` decorator with exponential backoff for SQLite `OperationalError: database is locked` — retries up to 3 times with jittered delays (1 s, 2 s, 4 s) before failing.
- DB corruption detection: replaced the soft `PRAGMA integrity_check` warning with a fatal `DatabaseCorruptionError` exception — corrupted databases are now rejected immediately rather than silently serving stale/partial data.
- Removed `sub_feed_progress` parameter from OSSF feed progress reporting; replaced `click.echo` with `console.print` for consistent Rich-formatted output.
- Setup wizard: replaced the OSSF feed skip/exclusion menu with a GHSA token recommendation. When no GitHub token is configured, the wizard now warns about slower GHSA sync (~2–5 min vs ~1–2 sec), recommends daemon setup (`pkgd daemon start`), and offers another chance to add the token. OSSF feed now syncs in ~25 seconds via tarball regardless of token status.

### Fixed

- `PRAGMA quick_check` on every connection open (root cause of timeout bugs): `get_connection()` executed `PRAGMA quick_check` on every call, running 5–7 times per `pip install` check against the 668 MB database — cumulative overhead of 30–84 s, exhausting the command timeout budget. Fixed by caching the quick_check result per database path within a process.
- Dead, never-used connection in cache-write path: `dispatcher.py` opened a second connection in `write_threat` that was never actually used. Removed the unused connection.
- Cache-write `busy_timeout` now 1 s (was 30 s): Cache-write connections are documented as best-effort; a 30-second busy wait was inconsistent with that contract. Shortened to 1 s to match the best-effort semantics.
- Snapshot retrieval system used stale release tag URL construction from previous system design: `fetch_latest_release()` queried `/releases/latest` instead of `/releases/tags/snapshot-latest` via a fragile `git remote` subprocess — `--latest` displayed `N/A` and `0` for real metadata. Fixed by replacing the subprocess approach with hardcoded repo constants and querying the correct tag endpoint.
- Feed sync progress callback emitted a misleading "completed" message (`(feed_name, 0)`) on error paths — changed to emit `-1` as a sentinel; `handle_feed_complete` now checks for `-1` and reports the failure without claiming zero threats found.
- Stack trace leakage: `logger.error(exc_info=result)` printed full tracebacks at ERROR level for expected failures (e.g., network timeouts, rate limits). Split into a short ERROR message for the user and a DEBUG-level message with the full exception info for operators.
- Exception handler cascade in `intel sync`: reordered handlers so `KeyboardInterrupt` is caught before the generic `Exception` block, preventing tracebacks on Ctrl+C; downgraded error-state write failure from ERROR to WARNING since it's non-critical.

## [1.0.4] - 2026-07-06

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
