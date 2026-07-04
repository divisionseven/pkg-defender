# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
