<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_transparent.svg">
    <img src="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_light_mode.svg" alt="PKG-Defender Logo" width="500">
  </picture>

# PKG-Defender (PKGD) — Github Action

### Stop supply chain attacks *before* they reach your machine or CI pipeline

[![Release][github-binary-releases-badge]][github-binary-releases-link]
[![Snapshot][github-snapshot-releases-badge]][github-snapshot-releases-link]
[![License][license-badge-icon]][license-badge-link]
[![Python][python-badge-icon]][pypi-badge-link]
[![Downloads][pypi-downloads-badge-icon]][pypi-badge-link]
[![Codecov][codecov-badge-icon]][codecov-badge-link]
[![Build][ci-badge-icon]][ci-badge-link]

[![Languages][language-pkgs-badge-icon]][ecosystems-badge-link]
[![Systems][system-pkgs-badge-icon]][ecosystems-badge-link]
[![Platforms][platforms-badge-icon]][github-binary-releases-link]

</div>

## Highlights

> ***The supply chain attack defense CLI — Cooldown gates, multi-source threat
> intelligence, command wrappers, CI/CD interception, and lock file dependency
> auditing for all major package managers.***

- **Unified Command Wrapper**: `pkgd [OPTIONS] MANAGER SUBCOMMAND [PACKAGE...] [MANAGER_OPTIONS...]`
  - Wrap any [supported][supported-commands] *"dangerous"* package manager
    command (`pkgd pip install requests`, `pkgd npm install express`,
    `pkgd brew upgrade tree`, etc.)
  - *"Dangerous Commands"* are defined as any package manager command that has
    the potential to put software **on** your machine (`install`, `update`,
    `download`, `add`, `sync`, etc.)
- **Auto-Detect Manager**: automatically detects package manager from project
  files or system packages
- **Version Detection**: `get_installed_version()` for all 18 package managers
  across 10 ecosystems enables version comparison
- **Fail-Closed Security**: any failure blocks installation with warning and
  options for informed manual override
- **Alternative PM Coverage**: `python -m pip`, `pipx`, `yarn`, `pnpm` and other
  alt manager calls all [supported][supported-commands]
- **Cooldown Gates**: configurable time-since-release hold window with
  per-package, tracked and auditable overrides (ships with a default of 7
  days)
- **Multi-source Threat Intelligence**: OSV.dev, GHSA, Socket.dev, npm
  advisories, and more all synced and stored locally (with automatic staleness
  detection)
- **Social Intelligence Feeds**: Mastodon, Reddit, RSS, X/Twitter - free sources
  shipped / B.Y.O.K. options available (informational only — non-blocking)
- **Lock File Auditing**: all major formats: `package-lock.json`, `poetry.lock`,
  `requirements.txt`, `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `Pipfile.lock`
  ([currently supported formats][targeted-managers])
- **Background Daemon**: automated background intelligence feed sync with
  OS-native launchd / systemd / Task Scheduler
- **CI/CD Integration**: `--fail-on-threat` exits on CRITICAL/HIGH for secure
  pipeline gating

[See Full Documentation Index &rarr;][docs-index]

## PKG-Defender Github Action

### Basic Usage

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        uses: divisionseven/pkg-defender-action@v1
```

### With Custom Settings

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        uses: divisionseven/pkg-defender-action@v1
        with:
          fail-on: high
          lock-files: "**/package-lock.json,**/yarn.lock"
```

### Full Example with Outputs

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        id: audit
        uses: divisionseven/pkg-defender-action@v1
        with:
          fail-on: critical
      - name: Get results
        if: always()
        run: |
          echo "Findings: ${{ steps.audit.outputs.findings }}"
          echo "Summary: ${{ steps.audit.outputs.summary }}"
          echo "Exit code: ${{ steps.audit.outputs.exit-code }}"
```

## How It Works

This action is a **thin CLI wrapper** around the `pkgd` CLI. It works as
follows:

1. Installs `pkg-defender` via `pip install pkg-defender`
2. Sets up the threat database via `pkgd --ci setup`
3. Resolves your `lock-files` glob pattern using `@actions/glob`
4. Runs `pkgd audit --json --fail-on-threat` for each matched lock file
5. Parses the JSON output and creates GitHub Action annotations
6. Fails the workflow if threats are found (exit code 4)

### CI/CD Usage

[![PKGD Github Action Release][pkgd-action-release-badge-icon]][pkgd-action-release-badge-link]
[![PKGD Action CI][pkgd-action-ci-badge-icon]][pkgd-action-ci-badge-link]
[![PKGD Snapshot Build][snapshot-action-badge-icon]][snapshot-action-badge-link]

PKG-Defender integrates into automated pipelines via non-interactive CI mode:

```bash
# Use --ci flag to skip all prompts
pkgd --ci pip install axios

# Or set the environment variable
export PKGD_CI=1
pkgd pip install axios
```

#### GitHub Action

The [pkg-defender-action](https://github.com/divisionseven/pkg-defender-action)
is the easiest way to add threat auditing to GitHub Actions workflows. It's a
thin wrapper that installs `pkgd`, discovers lock files, and runs the audit.

**Inputs:**

| Input        | Default                               | Description                                                                                                   |
| ------------ | ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `fail-on`    | `high`                                | Minimum severity to fail: `critical`, `high`, `medium`, `low`, `none`. CRITICAL and HIGH trigger exit code 4. |
| `lock-files` | `**/package-lock.json,**/yarn.lock,…` | Glob pattern for lock files to scan (default covers all 7 supported formats).                                 |

**Outputs:**

| Output      | Description                                                          |
| ----------- | -------------------------------------------------------------------- |
| `findings`  | JSON array of threats with package, version, ecosystem, and severity |
| `summary`   | Human-readable summary (e.g., "3 threats found: 1 CRITICAL, 2 HIGH") |
| `exit-code` | Exit code from `pkgd audit` (0 = pass, 4 = threat detected)          |

**Minimal usage:**

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: divisionseven/pkg-defender-action@v1
```

**With custom threshold and lock file filter:**

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: divisionseven/pkg-defender-action@v1
    with:
      fail-on: critical
      lock-files: "**/package-lock.json"
```

The action passes `--fail-on-threat` to `pkgd audit` when `fail-on` is
`critical` or `high`. For `medium`, `low`, or `none`, the audit runs
informational-only (exit always 0).

[See PKGD Action Repository &rarr;](https://github.com/divisionseven/pkg-defender-action)

#### Manual CI Setup (all CI platforms)

For non-GitHub CI platforms (GitLab CI, Azure Pipelines, Jenkins, CircleCI,
etc.) or when you need full control over the install, use `pkgd` directly.

The CLI offers two approaches to prepare the threat database:

| Approach         | Command                       | Time    | Freshness    | Best for                           |
| ---------------- | ----------------------------- | ------- | ------------ | ---------------------------------- |
| **Fast path**    | `pkgd db snapshot --download` | ~5–10s  | Up to 6h old | Frequent CI runs, cache-friendly   |
| **Current path** | `pkgd intel sync`             | ~30–60s | Always fresh | One-off audits, post-deploy checks |

```bash
# Fast path: download pre-built snapshot (cacheable)
pkgd db snapshot --download
pkgd audit --fail-on-threat --output json

# Current path: sync from all threat feeds (always fresh)
pkgd intel sync
pkgd audit --fail-on-threat --output json
```

Use the fast path for routine PR checks where ~6-hour-old threat data is
acceptable. Use the current path for release gates or post-deployment
verification where the absolute latest intelligence matters.

#### How Snapshots Work

A *"snapshot"* is a pre-built threat intelligence database published to
[GitHub Releases: `snapshot-latest`](https://github.com/divisionseven/pkg-defender/releases/tag/snapshot-latest)
every 6 hours. It contains known threats from our Tier 1 feeds — **OSV.dev**,
**GitHub Security Advisories (GHSA)**, and **OSSF Malicious Packages** —
covering npm, PyPI, Cargo, RubyGems, Go, Maven, NuGet, and Packagist.

**Safety guarantees:**

- **SHA256 verification** — Every snapshot ships with a `.sha256` checksum
  file; `pkgd db snapshot --download` verifies the hash before use
- **Integrity check** — The snapshot CI pipeline runs `PRAGMA integrity_check`
  on the database before publishing
- **Anomaly detection** — Record count is compared against the previous build;
  suspicious inflation (>5x) or drops (<0.01x) abort the publish

The snapshot is built by a scheduled GitHub Actions workflow
(`.github/workflows/snapshot.yml`, cron `0 */6 * * *`) that runs
`scripts/build_snapshot.py`. The result is an always-available download
that's safe to use in automated pipelines.

#### How Everything Works Together

The CI/CD integration has three layers:

1. **Threat intelligence feeds → Snapshot builder** — Tier 1 feeds (OSV, GHSA,
   OSSF) are synced every 6 hours by a scheduled GitHub Actions workflow
   (`scripts/build_snapshot.py`), producing a compressed, verified SQLite
   database published to GitHub Releases.
2. **Snapshot → CI pipeline** — Each CI run (via the GitHub Action or manual
   setup) downloads the latest snapshot, verifies its SHA256, and uses it as
   the local threat database for `pkgd audit`.
3. **pkgd CLI → Audit results** — The CLI scans discovered lock files against
   the local database, produces JSON or rich output, and exits with code 4 if
   threats exceed the `--fail-on-threat` threshold.

```
┌─────────────────────────────────────────────────────────────────┐
│                     CI/CD USAGE ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PATH A: divisionseven/pkg-defender-action@v1                   │
│      │                                                          │
│      ├──▶ read inputs (fail-on, lock-files)                     │
│      │                                                          │
│      ├──▶ pip install pkg-defender                              │
│      │                                                          │
│      ├──▶ pkgd --ci setup                                       │
│      │        │                                                 │
│      │        ├──▶ write config file                            │
│      │        ├──▶ initialize threat DB                         │
│      │        └──▶ intel_sync -- ALL 9 feeds, LIVE              │
│      │                  (snapshot release not used)             │
│      │                                                          │
│      ├──▶ glob lock files                                       │
│      │        └──▶ none found? exit 0 (empty findings)          │
│      │                                                          │
│      ├──▶ for each lock file:                                   │
│      │        └──▶ pkgd --ci audit <file> --json                │
│      │                  [--fail-on-threat if high/critical]     │
│      │                  └──▶ merge findings into one array      │
│      │                                                          │
│      ├──▶ set outputs (findings, summary, exit-code)            │
│      │                                                          │
│      └──▶ any non-zero evit code? ──▶ core.setFailed()          │
│                                                                 │
│ ······························································· │
│                                                                 │
│  PATH B: pkgd CLI (compatible with any CI platform)             │
│      │                                                          │
│      ├──▶ SNAPSHOT PATH (~5-10s, cacheable)                     │
│      │        └──▶ pkgd db snapshot --download                  │
│      │                  ├──▶ fetch db.gz + .sha256              │
│      │                  └──▶ verify SHA256 (64KB chunks)        │
│      │                            ├──▶ FAIL: return False       │
│      │                            └──▶ MATCH: atomic DB swap    │
│      │                                                          │
│      ├──▶ FEED SYNC PATH (~30-60s, always fresh)                │
│      │        └──▶ pkgd intel sync -- ALL 9 feeds, LIVE         │
│      │                                                          │
│      └──▶ pkgd audit --fail-on-threat                           │
│                ├──▶ CRITICAL/HIGH found? exit 4                 │
│                └──▶ clean? exit 0                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
         │                                             ▲
         │          GitHub Snapshot Releases           │
         │      ┌───────────────────────────────┐      │
         └─────▶│  threats-latest.db.gz         │──────┘
                │  threats-latest.db.gz.sha256  │
                └───────────────────────────────┘
                                ▲
             Published          │    Fetched
             every 6 hours      │    only by PATH B
             (GitHub Actions)   │    (fastest path)
                                │

       ⚠  PATH A never reaches this release — it always
          live-syncs all 9 feeds directly for latest data

┌─────────────────────────────────────────────────────────────────┐
│                  SNAPSHOT BUILD & DISTRIBUTION                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ GH Action cron: "0 */6 * * *"  (always running, independent)    │
│     │                                                           │
│     └──▶ build_snapshot.py                                      │
│               │                                                 │
│               ├──▶ fetch Tier 1 feeds                           │
│               │        ├──▶ OSV.dev        (7 ecosystems)       │
│               │        ├──▶ GHSA           (last 365 days)      │
│               │        └──▶ OSSF Malicious Packages             │
│               │                                                 │
│               ├──▶ run safety checks (ALL must pass)            │
│               │        ├──▶ F1  integrity_check == "ok"         │
│               │        ├──▶ F3  >= 3 ecosystems have data       │
│               │        └──▶ F2  count within 0.01x-5x prior     │
│               │                                                 │
│               └──▶ gzip + sha256sum ──▶ publish                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

*Fig 1: End-to-end data flow from threat feeds through snapshot distribution to CI pipeline audit.*

#### Environment Variables

| Variable                    | Description                                                                                |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `PKGD_CI`                   | Enable non-interactive CI mode (`1` to enable)                                             |
| `PKGD_GITHUB_TOKEN`         | GHSA API token for higher rate limits; alternatively set `feeds.ghsa_token` in `pkgd.toml` |
| `PKGD_FEEDS_SOCKET_API_KEY` | Socket.dev API key for real-time threat signals                                            |
| `PKGD_DATABASE_PATH`        | Custom path for the threat database (overrides default data directory)                     |
| `PKGD_CONFIG_FILE`          | Alternative name for `PKGD_CONFIG_PATH` — path to config file override                     |

[See Full CI/CD Guide &rarr;][ci-cd-guide]

### Contributing

This action repository contains only the GitHub action source for
PKG-Defender. For feature requests, bug reports, or contributions to the tool
itself, please visit the
[main project repository](https://github.com/divisionseven/pkg-defender) and
review its
[contributing guide](https://github.com/divisionseven/pkg-defender/blob/main/CONTRIBUTING.md).

### License

This action is licensed under the Apache License, Version 2.0. See
[LICENSE][license] for the full license text. The main `pkg-defender` repository
is also Apache-2.0 licensed, [see license here][pkgd-repo-license].

---

<div align="center">

<strong>Last Updated: 2026-07-06</strong></br>

<em><small>Thank you for supporting PKG-Defender!</small></em></br>
<em><small>— Division 7</small></em>

</div>

---

<!-- Header Badge Icons -->

[license-badge-icon]: https://img.shields.io/badge/license-Apache_2.0-blue?style=plastic&logo=apache&color=black&logoColor=white&label=License
[python-badge-icon]: https://img.shields.io/pypi/pyversions/pkg-defender?style=plastic&logo=python&color=black&logoColor=white&label=Python
[pypi-downloads-badge-icon]: https://img.shields.io/pepy/dt/pkg-defender?style=plastic&logo=pypi&color=black&logoColor=white&label=Downloads
[github-binary-releases-badge]: https://img.shields.io/github/v/release/divisionseven/pkg-defender?filter=v*&style=plastic&color=black&logo=git&logoColor=white&label=Release
[github-snapshot-releases-badge]: https://img.shields.io/github/v/tag/divisionseven/pkg-defender?filter=snapshot-latest&style=plastic&logo=sqlite&logoColor=white&color=black&label=Threat%20DB
[codecov-badge-icon]: https://img.shields.io/codecov/c/github/divisionseven/pkg-defender?logo=codecov&style=plastic&color=black&logoColor=white&label=Codecov
[ci-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender/ci.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=Build
[language-pkgs-badge-icon]: https://img.shields.io/badge/Language_Packages-npm_%7C_PyPI_%7C_Cargo_%7C_RubyGems_%7C_Packagist-black?style=plastic
[system-pkgs-badge-icon]: https://img.shields.io/badge/System_Packages-Homebrew_%7C_APT_%7C_Yum_%7C_DNF_%7C_Conda-black?style=plastic
[platforms-badge-icon]: https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-black?style=plastic

<!-- Header Badge Links -->

[license-badge-link]: https://opensource.org/licenses/Apache-2.0
[pypi-badge-link]: https://pypi.org/project/pkg-defender/
[github-binary-releases-link]: https://github.com/divisionseven/pkg-defender/releases
[github-snapshot-releases-link]: https://github.com/divisionseven/pkg-defender/releases/tag/snapshot-latest
[codecov-badge-link]: https://app.codecov.io/gh/divisionseven/pkg-defender
[ci-badge-link]: https://github.com/divisionseven/pkg-defender/actions/workflows/ci.yml
[ecosystems-badge-link]: https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/package-managers.md

<!-- Body Badge Icons -->

[pkgd-action-release-badge-icon]: https://img.shields.io/github/v/release/divisionseven/pkg-defender-action?filter=v*&style=plastic&color=black&logo=git&logoColor=white&label=PKGD%20GitHub%20Action%20Release
[pkgd-action-ci-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender-action/ci.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=PKGD%20GitHub%20Action%20Build
[snapshot-action-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender/snapshot.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=PKGD%20Snapshot%20Build

<!-- Body Badge Links -->

[pkgd-action-release-badge-link]: https://github.com/divisionseven/pkg-defender-action/releases
[pkgd-action-ci-badge-link]: https://github.com/divisionseven/pkg-defender-action/actions/workflows/ci.yml
[snapshot-action-badge-link]: https://github.com/divisionseven/pkg-defender/actions/workflows/snapshot.yml

<!-- Internal Documentation Links -->

[docs-index]: https://github.com/divisionseven/pkg-defender/blob/main/docs/index.md
[ci-cd-guide]: https://github.com/divisionseven/pkg-defender/blob/main/docs/guides/ci-cd.md
[supported-commands]: https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/package-managers.md
[targeted-managers]: https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/package-managers.md
[pkgd-repo-license]: https://github.com/divisionseven/pkg-defender/blob/main/LICENSE
[license]: LICENSE
