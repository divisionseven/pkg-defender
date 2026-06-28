<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_transparent.svg">
    <img src="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_fill.svg" alt="pkg-defender" width="500">
  </picture>

# PKG-Defender (PKGD)

### Stop supply chain attacks *before* they reach your machine or CI pipeline

[![License][license-badge-icon]][license-badge-link]
[![Python][python-badge-icon]][pypi-badge-link]
[![Codecov][codecov-badge-icon]][codecov-badge-link]
[![Version][github-releases-badge]][github-releases-link]
[![Build][ci-badge-icon]][ci-badge-link]

[![Ecosystems][ecosystems-badge-icon]][ecosystems-badge-link]
[![Systems][systems-badge-icon]][ecosystems-badge-link]
[![Platforms][platforms-badge-icon]][platforms-badge-link]

</div>

## Highlights

> **The supply chain attack defense CLI — Cooldown gates, multi-source threat
> intelligence, command wrappers, CI/CD interception, and lock file dependency
> auditing for all major package managers.**

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

[Full Documentation Index &rarr;][docs-index]

## Why It Exists

The **overwhelming** frequency of recent supply chain attacks have shown how quickly
malicious packages can spread. The threat landscape has **changed significantly**.
Four of the most significant open-source supply chain attacks ever recorded all
happened within the last few months of writing:

- **[TanStack Router][tanstack-attack]** (*May 2026*): A self-propagating worm
  compromised 42 `@tanstack/*` packages and spread to 160+ others across npm and
  PyPI. The malicious versions carried *valid SLSA Build Level 3 provenance
  attestations*, meaning the supply chain controls that the industry spent years
  building offered zero protection.
- **[Axios][axios-attack]** (*March 2026*): A North Korea-linked threat actor
  compromised the lead maintainer's account of the most popular JavaScript HTTP
  client (~100M weekly downloads) and published a cross-platform RAT targeting
  macOS, Windows, and Linux. The poisoned versions were live for under 3 hours.
  Thousands of installs happened anyway.
- **[LiteLLM][litellm-attack]** (*March 2026*): Using tokens stolen via the
  Trivy compromise, attackers published backdoored releases of a widely-deployed
  AI gateway (~95M monthly downloads). The payload ran a three-stage attack:
  harvest SSH keys, AWS/GCP/Azure credentials, and Kubernetes secrets → move
  laterally across clusters → install a persistent systemd backdoor.
- **[Trivy][trivy-attack]** (*March 2026*): The world's most popular container
  security scanner was weaponized. Attackers spoofed maintainer commits, pushed
  a malicious release, and used Trivy's own CI/CD runner access to steal
  publishing tokens from every downstream project that scanned with it — kicking
  off a cascade of follow-on attacks.

These incidents succeed because fresh packages are often installed based on
trust alone. PKG-Defender adds a practical and secure defense layer: **local
threat intelligence** and **dependency auditing** combined with a configurable
**cooldown window** to catch the latest threats *before* they land on your
machine, your dependency tree, or your production pipelines.

## Installation

### From PyPI

```bash
# Recommended with uv
uv pip install pkg-defender

# Alternative with pip
pip install pkg-defender
```

### From Homebrew (macOS/Linux)

```bash
brew tap divisionseven/pkg-defender
brew install pkg-defender
```
**Tap Trust (Homebrew 6.0.0+)**

Non-official taps require explicit trust. Users will need to run:

```bash
brew trust divisionseven/pkg-defender
```

> [!Note]
> Homebrew installation is not yet available. The formula currently exists at
> `Formula/pkg-defender.rb` and will be activated upon release by being added to
> a separate homebrew tap repo. SHA256 checksums will be updated per-release.
> Once published, this note will be removed and the above commands will work as shown.

### From Binary (macOS/Linux/Windows)

Pre-built standalone binaries are attached to every
[GitHub Release](https://github.com/divisionseven/pkg-defender/releases):

- **macOS (arm64):** `pkgd-darwin-arm64`
- **macOS (x86_64):** `pkgd-darwin-amd64`
- **Linux (x86_64):** `pkgd-linux-amd64`
- **Windows (x86_64):** `pkgd-windows-amd64.exe`

Each binary has a matching `.sha256` checksum file. Download, verify, and run:

```bash
# Example for macOS arm64
curl -LO https://github.com/divisionseven/pkg-defender/releases/latest/download/pkgd-darwin-arm64
curl -LO https://github.com/divisionseven/pkg-defender/releases/latest/download/pkgd-darwin-arm64.sha256
shasum -a 256 -c pkgd-darwin-arm64.sha256
chmod +x pkgd-darwin-arm64
./pkgd-darwin-arm64 --help
```

### From Source

```bash
git clone https://github.com/divisionseven/pkg-defender
cd pkg-defender

# Using uv (recommended)
uv sync --dev

# Using pip
pip install -e ".[test,lint]"
```

[Full installation guide &rarr;][install-guide]

## Quick Start

```bash
# Simple setup wizard to configure settings,
# add optional secrets, sync intelligence feeds
pkgd setup

# Use the command wrapper pattern to intercept supported commands:
pkgd pip install requests
pkgd npm install express
pkgd brew install tree
# ...and so on
```

[Complete quick start &rarr;][quick-start]

### CI/CD Usage

[![Github Action Snapshot][snapshot-action-badge-icon]][snapshot-action-badge-link]

`pkg-defender` is also designed for use in automated pipelines with
non-interactive CI mode:

```bash
# Use --ci flag to skip all prompts
pkgd --ci pip install axios

# Or set the environment variable
export PKGD_CI=1
pkgd pip install axios
```

#### In CI pipelines:

```bash
# Quick audit with snapshots (faster)
pkgd db snapshot --download
pkgd audit --fail-on-threat -o json

# Or sync for most current data
pkgd intel sync
pkgd audit --fail-on-threat --output json
```

#### Environment setup:

| Variable                    | Description                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------- |
| `PKGD_CI=1`                 | Enable non-interactive mode                                                              |
| `PKGD_GITHUB_TOKEN`         | GHSA API token (higher rate limits); alternatively set `feeds.ghsa_token` in `pkgd.toml` |
| `PKGD_FEEDS_SOCKET_API_KEY` | Socket.dev API key (legacy: `PKGD_TWITTER_API_KEY`)                                      |

#### GitHub Actions CI Integration Example Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Example CI Pipeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   divisionseven/pkg-defender-action@v1                          │
│         │                                                       │
│         ├──▶ Check Cache (GitHub Actions)                       │
│         │         │                                             │
│         │         ├──▶ HIT: Use cached DB (<6 hours old)        │
│         │         │                                             │
│         │         └──▶ MISS: Download fresh snapshot            │
│         │                   │                                   │
│         │                   └──▶ SHA256 Verify  ◀︎─┐             │
│         │                             │           │             │
│         │                             ├──▶ FAIL: Rebuild        │
│         │                             │                         │
│         │                             └──▶ SUCCESS: Use DB      │
│         │                                                       │
│         ├──▶ Run pkgd audit                                     │
│         │         │                                             │
│         │         └──▶ Find vulnerabilities?                    │
│         │                   │                                   │
│         │                   ├──▶ YES: Create PR annotations     │
│         │                   │         │                         │
│         │                   │         └──▶ Exit 4 (fail-on)     │
│         │                   │                                   │
│         │                   └──▶ NO: Exit 0 (pass)              │
│         │                                                       │
│         └──▶ Done                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
        │                                             ▲
        │               GitHub Releases               │
        │      ┌───────────────────────────────┐      │
        └─────▶│  threats-latest.db.gz         │──────┘
               │  threats-20260417.db.gz       │
               │  threats-latest.db.gz.sha256  │
               └───────────────────────────────┘
                                ▲
            Published           │
            Every 6 Hours       │
            (GitHub Actions)    │
                                │
                ┌───────────────┴──────────────┐
                │                              │
                │       build_snapshot.py      │
                │               │              │
                │      ┌────────┼────────┐     │
                │      │        │        │     │
                │     OSV      GHSA     npm    │
                │                              │
                │     (Tier 1 Sources Only)    │
                │                              │
                ├──────────────────────────────┤
                │     PKG-Defender GitHub      │
                └──────────────────────────────┘
```

[Full CI/CD guide &rarr;][ci-cd-guide]

## How It Works

1. **Intercept** — Command wrappers (`pkgd pip install`, `pkgd npm install`)
   wrap package manager commands across 18 package managers in 10 ecosystems.
2. **Check** — `check_package()` queries the local SQLite threat database (zero
   network I/O).
3. **Inform** — social intelligence feeds add community-sourced early warnings
   (never blocks).
4. **Cooldown** — Package age is checked against the configured window (default:
   7 days).
5. **Decide** — Threats scoring ≥ 0.3 are blocked; social feed findings are
   informational only.
6. **Sync** — Background daemon periodically refreshes threat intelligence from
   9 feeds.

[Threat scoring concepts &rarr;][threat-scoring]

### Threat Intelligence

`pkg-defender` syncs from 9 feeds: 6 structured (OSV.dev, GHSA, npm advisory,
OSSF Malicious Package List, RSS, Homebrew) and 3 social (Mastodon, Reddit,
X/Twitter). Socket.dev is also available as a point-query source (not bulk
sync). Structured feeds can block installs; social feeds are informational only.
Feeds sync on configurable intervals with staleness detection.

[Full threat feed guide &rarr;][threat-feeds]

### Auditing

Scan 7 lock file formats for known threats and cooldown-pending packages. Output
in rich terminal, JSON, or CSV. Use `--fail-on-threat` for CI/CD pipeline gating
(exits 4 on CRITICAL/HIGH only).

[Auditing guide &rarr;][auditing-guide]

### Tab Completion

Automatic tab completion for `pkgd` commands in bash, zsh, and fish. Generated
via `pkgd completion generate`.

> [!Note]
> PowerShell and Nushell are accepted as CLI arguments for consistency
> with other shell commands, but Click's built-in completion only supports bash,
> zsh, and fish natively. Custom completion scripts for PowerShell/Nushell will
> be added in a future release if demand is proven.

```sh
# Bash (one of):
pkgd completion generate bash > /etc/bash_completion.d/pkgd  # system-wide
pkgd completion generate bash > ~/.local/share/bash-completion/completions/pkgd  # user

# Zsh
pkgd completion generate zsh > ~/.zsh/completions/_pkgd

# Fish
pkgd completion generate fish | source
```

Restart your shell after installation to enable completion.

[Tab completion guide &rarr;][completion-guide]

## Configuration

### Config Loading Order

Configuration is loaded in this order (later sources override earlier):

   1. [Built-In Defaults][config-ref]
   2. System Config (`/etc/pkgd/pkgd.toml`) — loaded first, can be overridden
   3. User Config (`~/.config/pkg-defender/pkgd.toml`, platform equivalent) — overrides system
   4. Project Config (`./pkgd.toml` or nearest parent) — highest file priority
   5. `PKGD_CONFIG_PATH` environment variable — only consulted if `config_path param` is `None`
   6. `PKGD_*` environment variable overrides — highest priority, always applied

### Config TOML File

Default *global* config file with all values — automatically generated during `pkgd setup` for
effortless customization. Generated at *project-level* with `cd path/to/project && pkgd setup --init`

```toml
[cooldown]

# Minimum age in days before a new package version is allowed.
# Default: 7
default_days = 7

# Whether cooldown checking is active. Set false to disable entirely.
# Default: True
enabled = true

# If True, audit exits non-zero when threats are found during cooldown enforcement.
# If False, audit exits zero even with threats (weakened security posture).
# Default: True
strict_mode = true

# If True, a reason must be provided when bypassing the cooldown.
# Default: True
bypass_require_reason = true

# Number of days to retain bypass audit log entries.
# Note: Displayed in config listings only — no auto-prune enforcement code.
# Default: 90
bypass_log_retention_days = 90

[cooldown.overrides]
# Per-package cooldown days override (package name → days).
# Package names must be quoted to avoid TOML parsing errors.
# Examples:
#   "react" = 14
#   "@babel/core" = 21
#   "some-package" = 7

[cooldown.per_ecosystem]
# Per-ecosystem cooldown window overrides (ecosystem → days).
# Examples:
#   npm = 7
#   pypi = 14

# …continued
```

[Full configuration reference &rarr;][config-ref]

## Command Reference

| Base Command Group       | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| `pkgd audit`             | Scan lock files for threats and cooldown-pending packages |
| `pkgd status`            | Show recent threats, bypasses, and feed state             |
| `pkgd bypass`            | Create bypass for a blocked package                       |
| `pkgd health`            | Check system health                                       |
| `pkgd reset`             | Reset all data (database, config, feeds)                  |
| `pkgd setup`             | Interactive first-run setup wizard                        |
| `pkgd audit-logs`        | Query and manage audit event logs                         |
| `pkgd logs`              | View and manage pkg-defender logs                         |
| `pkgd completion`        | Generate shell completion scripts                         |
| `pkgd hooks`             | Generate shell functions for wrapped manager commands     |
| `pkgd intel sync`        | Sync all threat intelligence feeds                        |
| `pkgd intel search`      | Search local threat database                              |
| `pkgd intel report`      | Threat intelligence dashboard                             |
| `pkgd config view`       | Display current configuration                             |
| `pkgd config list`       | List all configuration values with sources                |
| `pkgd config set`        | Set a config value (dot notation)                         |
| `pkgd config set-secret` | Set a secret configuration value with hidden input        |
| `pkgd config get`        | Get a specific configuration value                        |
| `pkgd config reset`      | Reset to defaults                                         |
| `pkgd config options`    | List all configurable options with descriptions           |
| `pkgd daemon`            | Background daemon for periodic sync                       |
| `pkgd db snapshot`       | Download/verify database snapshots                        |
| `pkgd db verify`         | Verify local database integrity and report summary        |

### Global Flags

These flags apply to every `pkgd` command:

| Flag(s)                     | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| `--version`, `-V`           | Show version information                                 |
| `--help`                    | Show help message and exit                               |
| `--config`, `-c`            | Path to configuration file (default: platform-dependent) |
| `--quiet`, `-q`             | Suppress all non-error output                            |
| `--verbose`, `-v`           | Increase verbosity (`-v`=INFO, `-vv`=DEBUG)              |
| `--no-verbose`              | Disable verbose output (overrides `PKGD_OUTPUT_VERBOSE`) |
| `--debug`, `-d`             | Show full tracebacks for unexpected errors               |
| `--no-color`                | Disable colored terminal output                          |
| `--ascii`                   | Force ASCII-only output (useful on Windows or CI)        |
| `--yes`, `-y`               | Auto-confirm all prompts                                 |
| `--force`, `-f`             | Force operations (skip confirmations, overwrite files)   |
| `--dry-run`, `-n`           | Show what would happen without making changes            |
| `--ci`, `--non-interactive` | Run in non-interactive CI/CD mode (reads `PKGD_CI`)      |
| `--explain`                 | Show detailed explanation of why packages were blocked   |
| `--json`                    | Output results as JSON                                   |

### Command-Specific Flags

| Command                 | Flag(s)                  | Description                                                                    |
| ----------------------- | ------------------------ | ------------------------------------------------------------------------------ |
| `pkgd audit`            | `--deep`, `-d`           | Perform deep scan (include cooldown status checks)                             |
| `pkgd audit`            | `--fail-on-threat`, `-f` | Exit with code 4 if CRITICAL or HIGH threats detected (CI/CD)                  |
| `pkgd audit`            | `--since`                | Only flag threats seen within duration (e.g., `7d`, `24h`)                     |
| `pkgd audit`            | `--output`, `-o`         | Output format: `rich`, `json`, `csv` (default: `rich`)                         |
| `pkgd status`           | `--feeds`                | Show per-feed health status                                                    |
| `pkgd health`           | `--output`, `-o`         | Output format: `rich`, `json` (default: `rich`)                                |
| `pkgd setup`            | `--init`, `-i`           | Create `pkgd.toml` with defaults                                               |
| `pkgd setup`            | `--shell`, `-s`          | Override auto-detected shell                                                   |
| `pkgd bypass`           | `--manager`, `-m`        | Package manager (default: `npm`)                                               |
| `pkgd bypass`           | `--reason`               | Reason for bypass (required)                                                   |
| `pkgd bypass`           | `--expires`              | Bypass expiry duration (e.g., `24h`, `7d`, `30m`)                              |
| `pkgd intel sync`       | `--exclude-feed`         | Exclude a specific feed (repeatable)                                           |
| `pkgd logs view`        | `--lines`, `-n`          | Number of lines to show (default: 100)                                         |
| `pkgd db snapshot`      | `--download`, `-d`       | Download latest threat intelligence snapshot                                   |
| `pkgd db snapshot`      | `--verify`, `-v`         | Verify local database integrity                                                |
| `pkgd reset`            | `--teardown`, `-t`       | Full teardown (remove database and config)                                     |
| `pkgd audit-logs query` | `--ecosystem`            | Filter audit log entries by ecosystem                                          |
| `pkgd audit-logs query` | `--verdict`              | Filter by verdict (`PASS`, `PARTIAL_PASS`, `FAIL`, `BLOCKED`, `WARN`, `ERROR`) |

### Environment Variables

| Variable              | Affects             | Description                                            |
| --------------------- | ------------------- | ------------------------------------------------------ |
| `PKGD_DRY_RUN`        | `--dry-run` default | When set to `1`, enables dry-run mode by default       |
| `PKGD_OUTPUT_VERBOSE` | `--no-verbose`      | Override verbose output at the environment level       |
| `PKGD_CI`             | `--ci` mode         | When set to `1`, forces CI mode (non-interactive)      |
| `PKGD_CONFIG_PATH`    | Config loading      | Path to configuration file (alternative to `--config`) |

[Full CLI reference &rarr;][cli-ref]

## Supported Ecosystems

> #### Ecosystem Coverage Tier Key:
>
> The ecosystem's package publication timestamp source/availability (for use in cooldown calculation) determines the tier assignment:
>
> - `FULL`: Threat check runs, cooldown check runs, *verified* publish timestamps available
> - `PARTIAL`: Threat check runs, cooldown check runs, *proxied* publish timestamps available
> - `AUDIT`: Threat check runs, cooldown check is SKIPPED (no reliable registry publish timestamp source available)
>
> `FULL` and `PARTIAL` are functionally identical in terms of what checks run. The difference is in the *quality* of the timestamp source:
>
> - `FULL` means the timestamps are cryptographically verified/authoritative (PyPI native API, npm registry, etc.)
> - `PARTIAL` means they're proxied/approximate but still usable for cooldown (GitHub Releases/Tags API, Libraries.io, etc.)

| Ecosystem | Manager                       | Registry Adapter | Coverage Tier      | Lock File                                            | Wrapper |
| --------- | ----------------------------- | ---------------- | ------------------ | ---------------------------------------------------- | ------- |
| npm       | npm, yarn, pnpm, bun          | Yes              | `FULL` / `PARTIAL` | package-lock.json, yarn.lock, pnpm-lock.yaml         | Yes     |
| PyPI      | pip, pipx, poetry, pipenv, uv | Yes              | `FULL` / `PARTIAL` | requirements.txt, poetry.lock, Pipfile.lock, uv.lock | Yes     |
| Cargo     | cargo                         | Yes              | `FULL`             | —                                                    | Yes     |
| RubyGems  | gem, bundler                  | Yes              | `FULL` / `PARTIAL` | —                                                    | Yes     |
| Packagist | composer                      | Yes              | `FULL`             | —                                                    | Yes     |
| Homebrew  | brew                          | Yes              | `PARTIAL`          | —                                                    | Yes     |
| APT       | apt                           | Yes              | `AUDIT`            | —                                                    | Yes     |
| Yum       | yum                           | Yes              | `AUDIT`            | —                                                    | Yes     |
| DNF       | dnf                           | Yes              | `AUDIT`            | —                                                    | Yes     |
| Conda     | conda                         | Yes              | `FULL`             | —                                                    | Yes     |

[Full ecosystem guide &rarr;][ecosystems]

## Dependencies

> [!NOTE]
> Each dependency below includes a pre-crafted audit link: a
> Google-dorking search query scoped to supply chain attacks, compromises, and
> security advisories for that package, filtered to the past year.
>
> **This is intentional**. PKG-Defender exists because developers install
> packages on trust alone; we think that habit should stop, including with tools
> like ours. Before installing PKG-Defender in a sensitive environment, we
> encourage you to click through and do a 30-second check on each of our
> dependencies. That's exactly the kind of scrutiny this project was built to
> promote.

| PyPI Link                        | Purpose                                       | Audit Link                            |
| -------------------------------- | --------------------------------------------- | ------------------------------------- |
| [aiohttp][dep-aiohttp]           | Async HTTP for feed sync and registry lookups | [AUDIT ME &rarr;][audit-aiohttp]      |
| [click][dep-click]               | CLI framework                                 | [AUDIT ME &rarr;][audit-click]        |
| [defusedxml][dep-defusedxml]     | Safe XML parsing for RPM repodata             | [AUDIT ME &rarr;][audit-defusedxml]   |
| [feedparser][dep-feedparser]     | Atom/RSS feed parsing                         | [AUDIT ME &rarr;][audit-feedparser]   |
| [packaging][dep-packaging]       | Python version spec parsing                   | [AUDIT ME &rarr;][audit-packaging]    |
| [platformdirs][dep-platformdirs] | Platform-appropriate config/data directories  | [AUDIT ME &rarr;][audit-platformdirs] |
| [pyyaml][dep-pyyaml]             | YAML parsing for pnpm-lock.yaml lock files    | [AUDIT ME &rarr;][audit-pyyaml]       |
| [rich][dep-rich]                 | Terminal output formatting                    | [AUDIT ME &rarr;][audit-rich]         |
| [tomlkit][dep-tomlkit]           | TOML config file read/write (setup wizard)    | [AUDIT ME &rarr;][audit-tomlkit]      |
| [zstandard][dep-zstandard]       | Zstandard decompression for RPM repodata      | [AUDIT ME &rarr;][audit-zstandard]    |

[See current dependency list &rarr;][pyproject]

## Contributing

### Makefile

For common development tasks, you can use the Makefile:

| Command          | Description                    |
| ---------------- | ------------------------------ |
| `make install`   | Install all dependencies       |
| `make lint`      | Check code style               |
| `make typecheck` | Type checking                  |
| `make test`      | Run tests                      |
| `make check`     | Run lint, typecheck, and tests |
| `make build`     | Build the package              |
| `make clean`     | Clean build artifacts          |

### Direct

Use uv directly:

```bash
uv run pytest
uv build
# continued...
```

See [CONTRIBUTING.md &rarr;][contributing]

## Support & Community

[![GitHub Issues][gh-issues-badge-icon]][gh-issues-badge-link]
[![GitHub Discussions][gh-discussions-badge-icon]][gh-discussions-badge-link]

- [Report Issues &rarr;][gh-issues-badge-link]
- [Join Discussions &rarr;][gh-discussions-badge-link]

## Security

> [!Important]
> While PKG-Defender aims to provide practical defense against
> supply chain threats, no tool can ever guarantee complete protection. Threats
> may evolve faster than intelligence feeds, and sophisticated attacks may evade
> public detection. This tool is intended to be used as one layer of a broader
> security strategy — not as a silver bullet.
>
> PKG-Defender is in active development and we strive to continually evolve in
> response to the modern threat landscape.

See [SECURITY.md &rarr;][security]

See [DISCLAIMER.md &rarr;][disclaimer]

## Known Limitations (v1)

PKG-Defender v1 is our first public release and we have been deliberate about
scope. The following features are **not** in v1:

- **No transitive dependency resolution** — `pkgd audit` inspects top-level
  packages only. Transitive dependency scanning is planned for a future release.
- **Audit trail timing** — Audit trail records are written before command
  execution. The `runtime_ms` field reflects pre-execution processing time;
  post-execution duration is not captured in v1.
- **Scoring threshold is a tunable heuristic** — The block threshold (score ≥
  0.3, defined in `src/pkg_defender/core/checker.py`) has been conservatively
  chosen but not empirically validated against real-world supply-chain attack
  data. Blocking decisions use a linear scoring model (`severity` × `source confidence`
  × `corroboration` × `recency`) that may not capture all threat
  scenarios. Advanced users can adjust the threshold via pkgd configuration.

## Security Model Limitations

PKG-Defender is a practical defense layer, not a guarantee. Understanding its
architectural boundaries helps you calibrate expectations and deploy it where it
adds the most value.

### Interactive CLI Only

PKG-Defender protects interactive `pip install`, `npm install`, and similar CLI
commands by wrapping package manager invocations via shell functions. It does
**not** protect:

- **Dockerfiles / container builds** — `RUN pip install` inside a Dockerfile
  does not pass through pkgd.
- **CI/CD scripts** — Unless explicitly configured to use `pkgd <manager>`
  instead of the bare manager command.
- **Automated / headless installs** — Scripts, Makefiles, or system package
  operations that call the package manager directly.

After clearing a command, `os.execvp()` replaces the pkgd process with the real
package manager, leaving zero runtime overhead.

### Post-Execution Audit Gap

PKG-Defender records its pre-install assessment in the audit log — the verdict,
config state, and threat analysis at decision time. However, because
`os.execvp()` replaces the process, pkgd **cannot** verify whether the install
actually succeeded or whether the package manager encountered an error. To
confirm outcomes, cross-reference pkgd's audit log (`pkgd audit-logs`) with your
package manager's actual installed state.

### AUDIT-Tier Managers Have Minimal Protection

Package managers on the `AUDIT` coverage tier (apt, yum, dnf) receive
threat-detection-only protection — the threat database IS queried, but cooldown
verification is skipped (these ecosystems lack reliable publish timestamps).

### Scoring Threshold Is a Tunable Heuristic

The block threshold (0.3 in `checker.py`) is a starting value chosen through
reasoned defaults, not empirical validation against real-world attack data. It
may produce false positives (blocking legitimate packages) or false negatives
(allowing malicious packages whose threat signals don't reach the threshold).
Users deploying in sensitive environments should test and adjust this value.

### Pre-Existing Attacks

PKG-Defender cannot protect against attacks that are already in motion at
install time — for example, a compromised package that executes malicious code
during its installation script. The tool assesses threat signals from
intelligence feeds, not runtime behavior.

### Signal-Based Cooldown

The v1 release provides signal-based cooldown escalation where threat severity
can dynamically extend cooldown windows. Verified advisories trigger an
immediate block, and Tier 3 social signals extend the cooldown window. However,
users cannot configure per-signal thresholds or escalation policies directly;
the behavior is hard-coded in the `step_check_cooldown()` pipeline.

## License

PKG-Defender is distributed under [Apache-2.0 &rarr;][license]

## Acknowledgements

PKG-Defender would not be possible without the following external projects,
services, data sources, libraries, and tools. Thank you for your contributions.

### Threat Intelligence Data Sources

- [OSV.dev][osv-dev] — Open Source Vulnerability database (Google)
- [GitHub Security Advisories][ghsa] — GHSA database
- [Socket.dev][socket-dev] — Supply chain security signals
- [OpenSSF Malicious Packages][ossf-malicious] — OpenSSF malicious package database

### Package Registries

- [npm][reg-npm] — npm registry (npm, Inc.)
- [PyPI][reg-pypi] — Python Package Index (Python Software Foundation)
- [RubyGems][reg-rubygems] — Ruby gem server
- [crates.io][reg-crates] — Rust package registry
- [Packagist][reg-packagist] — PHP/Composer package repository
- [Homebrew][reg-homebrew] — macOS/Linux package manager (formulae.brew.sh)
- [Anaconda][reg-anaconda] — Python/R data science distribution (Anaconda Inc.)
- [conda-forge][reg-condaforge] — Community-led conda package channel

### Timestamp Resolution Services

- [libraries.io][ts-librariesio] — Package metadata and release timestamps
- [Fedora Koji][ts-koji] — Fedora build system hub
- [Fedora Bodhi][ts-bodhi] — Fedora updates system
- [Ubuntu Archive][ts-ubuntu] — Ubuntu package archive
- [Debian Snapshot Archive][ts-debian] — Debian snapshot archive

### Social & Community Data Sources

- [Mastodon / infosec.exchange][social-mastodon] — Decentralized social platform
- [Reddit / PullPush.io][social-pullpush] — Reddit comment and submission archive
- [X/Twitter API v2][social-twitter] — Social media platform (opt-in, BYOK)

### Security Blog RSS Feeds

Security intelligence aggregated from blog RSS feeds:

- Socket.dev blog, Snyk blog, OpenSSF blog, GitHub Security blog,
  GitGuardian blog, Sonatype blog

### Runtime Dependencies

PKG-Defender's runtime dependencies are listed in the [Dependencies](#dependencies) table
above with full transparency audit links.

- [aiohttp][dep-aiohttp] — Async HTTP for feed sync and registry lookups
- [click][dep-click] — CLI framework
- [defusedxml][dep-defusedxml] — Safe XML parsing for RPM repodata
- [feedparser][dep-feedparser] — Atom/RSS feed parsing
- [packaging][dep-packaging] — Python version spec parsing
- [platformdirs][dep-platformdirs] — Platform-appropriate config/data directories
- [PyYAML][dep-pyyaml] — YAML parsing for pnpm-lock.yaml lock files
- [rich][dep-rich] — Terminal output formatting
- [tomlkit][dep-tomlkit] — TOML config file read/write (setup wizard)
- [zstandard][dep-zstandard] — Zstandard decompression for RPM repodata

### Development & Build Tools

- [Hatchling][dev-hatchling] — Python build backend
- [pytest][dev-pytest] — Testing framework
- [ruff][dev-ruff] — Python linter and formatter (Astral)
- [mypy][dev-mypy] — Static type checker
- [pre-commit][dev-precommit] — Git hook framework
- [PyInstaller][dev-pyinstaller] — Standalone binary packaging
- [aioresponses][dev-aioresponses] — Async HTTP test mocking

### CI/CD & Infrastructure

- [GitHub Actions][infra-ghactions] — CI/CD and snapshot automation
- [Codecov][infra-codecov] — Code coverage reporting
- [shields.io][infra-shields] — Badge generation service
- [Trivy][infra-trivy] — Container image vulnerability scanner (Aqua Security)
- [Docker][infra-docker] — Container runtime and image distribution

### Community Standards

- [Contributor Covenant][std-covenant] — Code of conduct
- [Conventional Commits][std-convcommits] — Commit message standard
- [no-color.org][std-nocolor] — NO_COLOR standard

### ASCII Art & Branding

- [artty][brand-artty] — ASCII art generation for the PKG-Defender
  logo banner (used offline in development for asset generation)

---

**Last updated:** 2026-06-27

---

<!-- Header Badge Icons -->

[license-badge-icon]: https://img.shields.io/badge/license-Apache_2.0-blue?style=plastic&logo=apache&color=black&logoColor=white&label=License
[python-badge-icon]: https://img.shields.io/pypi/pyversions/pkg-defender?style=plastic&logo=python&color=black&logoColor=white&label=Python
[codecov-badge-icon]: https://img.shields.io/codecov/c/github/divisionseven/pkg-defender?logo=codecov&style=plastic&color=black&logoColor=white&label=Codecov
[github-releases-badge]: https://img.shields.io/github/v/release/divisionseven/pkg-defender?style=plastic&color=black&logo=git&logoColor=white&label=Release
[ci-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender/ci.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=Build
[ecosystems-badge-icon]: https://img.shields.io/badge/Package_Ecosystems-npm_%7C_PyPI_%7C_Cargo_%7C_RubyGems_%7C_Packagist-black?style=plastic
[systems-badge-icon]: https://img.shields.io/badge/System_Packages-Homebrew_%7C_APT_%7C_Yum_%7C_DNF_%7C_Conda-black?style=plastic
[platforms-badge-icon]: https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-black?style=plastic

<!-- Header Badge Links -->

[license-badge-link]: https://opensource.org/licenses/Apache-2.0
[pypi-badge-link]: https://pypi.org/project/pkg-defender/
[codecov-badge-link]: https://app.codecov.io/gh/divisionseven/pkg-defender
[github-releases-link]: https://github.com/divisionseven/pkg-defender/releases
[ci-badge-link]: https://github.com/divisionseven/pkg-defender/actions/workflows/ci.yml
[platforms-badge-link]: https://github.com/divisionseven/pkg-defender
[ecosystems-badge-link]: docs/reference/package-managers.md

<!-- Body Badge Icons -->

[snapshot-action-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender/snapshot.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=PKGD%20Action%20Build
[gh-issues-badge-icon]: https://img.shields.io/github/issues/divisionseven/pkg-defender?color=black&style=plastic&label=Issues
[gh-discussions-badge-icon]: https://img.shields.io/github/discussions/divisionseven/pkg-defender?color=black&style=plastic&label=Discussions

<!-- Body Badge Links -->

[snapshot-action-badge-link]: https://github.com/divisionseven/pkg-defender/actions/workflows/snapshot.yml
[gh-issues-badge-link]: https://github.com/divisionseven/pkg-defender/issues
[gh-discussions-badge-link]: https://github.com/divisionseven/pkg-defender/discussions

<!-- External Supply-Chain Attack Report Links -->

[tanstack-attack]: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
[axios-attack]: https://github.com/axios/axios/issues/10636
[litellm-attack]: https://docs.litellm.ai/blog/security-update-march-2026
[trivy-attack]: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/

<!-- Dependencies — PyPI Links -->

[dep-aiohttp]: https://pypi.org/project/aiohttp/
[dep-click]: https://pypi.org/project/click/
[dep-defusedxml]: https://pypi.org/project/defusedxml/
[dep-feedparser]: https://pypi.org/project/feedparser/
[dep-packaging]: https://pypi.org/project/packaging/
[dep-platformdirs]: https://pypi.org/project/platformdirs/
[dep-pyyaml]: https://pypi.org/project/PyYAML/
[dep-rich]: https://pypi.org/project/rich/
[dep-tomlkit]: https://pypi.org/project/tomlkit/
[dep-zstandard]: https://pypi.org/project/zstandard/

<!-- Dependencies — Audit Dorking Links-->

[audit-aiohttp]: https://www.google.com/search?q=aiohttp+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-click]: https://www.google.com/search?q=%28%22pallets%2Fclick%22+OR+%22pip+install+click%22%29+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-defusedxml]: https://www.google.com/search?q=defusedxml+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-feedparser]: https://www.google.com/search?q=feedparser+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-packaging]: https://www.google.com/search?q=%22pypa%2Fpackaging%22+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29&tbs=qdr:y
[audit-platformdirs]: https://www.google.com/search?q=platformdirs+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-pyyaml]: https://www.google.com/search?q=pyyaml+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-rich]: https://www.google.com/search?q=%28%22Textualize%2Frich%22+OR+%22pip+install+rich%22%29+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-tomlkit]: https://www.google.com/search?q=tomlkit+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y
[audit-zstandard]: https://www.google.com/search?q=zstandard+%28%22supply+chain+attack%22+OR+%22account+takeover%22+OR+compromised+OR+%22malicious+package%22+OR+backdoor+OR+typosquat%29+-site:stackoverflow.com&tbs=qdr:y

<!-- Internal Documentation Links -->

[docs-index]: docs/index.md
[install-guide]: docs/tutorials/getting-started.md
[quick-start]: docs/tutorials/getting-started.md
[threat-scoring]: docs/explanation/scoring.md
[threat-feeds]: docs/reference/threat-feeds.md
[completion-guide]: docs/reference/cli.md
[auditing-guide]: docs/guides/auditing.md
[config-ref]: docs/reference/configuration.md
[cli-ref]: docs/reference/cli.md
[ci-cd-guide]: docs/guides/ci-cd.md
[ecosystems]: docs/reference/package-managers.md
[supported-commands]: docs/reference/package-managers.md
[targeted-managers]: docs/reference/package-managers.md
[pyproject]: pyproject.toml
[contributing]: CONTRIBUTING.md
[security]: SECURITY.md
[disclaimer]: DISCLAIMER.md
[license]: LICENSE

<!-- External Acknowledgement Links -->

[osv-dev]: https://osv.dev
[ghsa]: https://github.com/advisories
[socket-dev]: https://socket.dev

<!-- Threat Intelligence Sources -->

[ossf-malicious]: https://github.com/ossf/malicious-packages

<!-- Package Registry Links -->

[reg-npm]: https://www.npmjs.com
[reg-pypi]: https://pypi.org
[reg-rubygems]: https://rubygems.org
[reg-crates]: https://crates.io
[reg-packagist]: https://packagist.org
[reg-homebrew]: https://brew.sh
[reg-anaconda]: https://anaconda.org
[reg-condaforge]: https://conda-forge.org

<!-- Timestamp Resolution Service Links -->

[ts-librariesio]: https://libraries.io
[ts-koji]: https://koji.fedoraproject.org/kojihub
[ts-bodhi]: https://bodhi.fedoraproject.org
[ts-ubuntu]: https://archive.ubuntu.com
[ts-debian]: https://snapshot.debian.org

<!-- Social & Community Data Source Links -->

[social-mastodon]: https://infosec.exchange
[social-pullpush]: https://pullpush.io
[social-twitter]: https://twitter.com

<!-- Development & Build Tool Links -->

[dev-hatchling]: https://pypi.org/project/hatchling/
[dev-pytest]: https://pypi.org/project/pytest/
[dev-ruff]: https://pypi.org/project/ruff/
[dev-mypy]: https://pypi.org/project/mypy/
[dev-precommit]: https://pypi.org/project/pre-commit/
[dev-pyinstaller]: https://pypi.org/project/pyinstaller/
[dev-aioresponses]: https://pypi.org/project/aioresponses/

<!-- CI/CD & Infrastructure Links -->

[infra-ghactions]: https://github.com/features/actions
[infra-codecov]: https://codecov.io
[infra-shields]: https://shields.io
[infra-trivy]: https://trivy.dev
[infra-docker]: https://www.docker.com

<!-- Community Standard Links -->

[std-covenant]: https://www.contributor-covenant.org
[std-convcommits]: https://www.conventionalcommits.org
[std-nocolor]: https://no-color.org

<!-- Branding & Asset Links -->

[brand-artty]: https://github.com/divisionseven/artty
