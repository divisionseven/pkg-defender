# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Fixed

- Replaced `@actions/glob` with `fast-glob@3.3.x` to remediate two HIGH-severity
  denial-of-service vulnerabilities in `brace-expansion`:
  GHSA-3jxr-9vmj-r5cp (CVE-2026-13149, exponential-time expansion) and
  GHSA-mh99-v99m-4gvg (unbounded expansion causing OOM crash). Updated glob API
  usage in `index.js`, mocks in `tests/action.test.js` (12 regression tests
  added), dependency check in `validate.sh`, and rebuilt `dist/index.js`.
- CI failed on Ubuntu 24.04 runners due to PEP 668 blocking
  system-wide Python package installs (`externally-managed-environment`).
  Replaced `python3 -c "import yaml..."` YAML validation in `validate.sh` with
  Node.js `require('yaml')` and removed the now-unnecessary `setup-uv` +
  `uv pip install --system pyyaml` steps from the action's CI and release
  workflows. All tests pass.

## [1.0.0] - 2026-07-06

### Added

- CI workflow: new `.github/workflows/ci.yml` runs tests on every push/PR to
  `main`
- Initial release of the PKG-Defender GitHub Action
- `fail-on` input to control workflow failure threshold (critical, high, medium,
  low, none)
- `lock-files` input to configure glob pattern for lock file discovery
- `findings`, `summary`, and `exit-code` outputs for downstream workflow steps
- Thin CLI wrapper that installs `pkg-defender` via pip and runs `pkgd audit`
- Automatic lock file discovery for npm, PyPI, Cargo, and RubyGems ecosystems
- Smart `--fail-on-threat` flag passthrough matching pkgd's CRITICAL/HIGH
  threshold
- Graceful handling of missing lock files, empty results, and malformed output
- Comprehensive test suite with 39 unit tests
- Input validation with warnings for invalid `fail-on` values
