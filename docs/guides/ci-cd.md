# CI/CD Integration

Integrate pkg-defender into your continuous integration and deployment pipelines.

## CI Mode

The `--ci` flag (or `--non-interactive`) runs pkg-defender in non-interactive mode, skipping all prompts and using defaults.

```bash
# Use --ci flag with any command
pkgd --ci setup --init
pkgd --ci audit --fail-on-threat
pkgd --ci setup --shell bash
```

### How CI Mode Works

- **Skips prompts** — All interactive input is bypassed
- **Uses defaults** — Safe defaults are applied for all options
- **Auto-confirms** — Destructive operations proceed without confirmation (if safe)
- **Works everywhere** — Available on all commands

### Auto-Detection

CI mode is automatically enabled when these environment variables are detected:

- `CI`, `GITHUB_ACTIONS`, `TF_BUILD`
- `GITLAB_CI`, `CIRCLECI`, `JENKINS_URL`
- `TRAVIS`, `CODEBUILD_BUILD_ID`, `BITBUCKET_COMMIT`
- `BUILDKITE`, `TEAMCITY_VERSION`, `SYSTEM_ACCESSTOKEN`

### Environment Variable Override

Explicitly enable CI mode using `PKGD_CI`:

```yaml
env:
  PKGD_CI: 1
```

### Priority

1. `--ci` flag (explicit) — Highest
2. `PKGD_CI` environment variable
3. Auto-detection from CI provider variables

---

## Database Snapshots

Pre-built threat intelligence database snapshots are available from GitHub Releases. Using snapshots significantly reduces CI pipeline time.

```bash
# Download latest snapshot
pkgd db snapshot --download

# Verify local database integrity
pkgd db snapshot --verify

# Check available version
pkgd db snapshot --latest
```

### Workflow Comparison

| Approach           | First Run Time | Subsequent Runs | Freshness     |
| ------------------ | -------------- | --------------- | ------------- |
| `pkgd intel sync`  | ~30-60 seconds | ~30-60 seconds  | Always latest |
| `pkgd db snapshot` | ~5-10 seconds  | ~5-10 seconds   | ~1 day old    |

### CI/CD Example

```yaml
- name: Download threat database
  run: pkgd db snapshot --download
```

---

## GitHub Actions

### Using the Division 7 `pkg-defender-action`

Use the official [pkg-defender-action](https://github.com/divisionseven/pkg-defender-action) for GitHub Actions:

```yaml
name: Dependency Security

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run pkg-defender audit
        uses: divisionseven/pkg-defender-action@v1
        with:
          fail-on: high
```

### Manual Setup

Download and use the standard `pkg-defender` CLI package manually using `uv` or `pip`, without the GitHub Action wrapper.

### Basic Audit Step

```yaml
name: Dependency Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install uv
        uses: astral-sh/setup-uv@v5

      - name: Install pkg-defender
        run: uv pip install pkg-defender

      - name: Sync threat intelligence
        run: pkgd intel sync

      - name: Audit dependencies
        run: pkgd audit --fail-on-threat --output json
```

### With Cache

```yaml
      - name: Cache threat database
        uses: actions/cache@v4
        with:
          path: ~/.local/share/pkg-defender
          key: pkgd-threat-db-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            pkgd-threat-db-${{ runner.os }}-

      - name: Sync threat intelligence
        run: pkgd intel sync
```

## Exit Code Behavior

### Threat Detection Exit Behavior

When an audit finds threats, two settings control whether it exits with code 4
(`EXIT_THREAT_DETECTED`):

| Control                                            | Default | Behavior                                         |
| -------------------------------------------------- | ------- | ------------------------------------------------ |
| `strict_mode` (`[cooldown]` in config)             | `true`  | Exit 4 if **any** threat is found (any severity) |
| `fail_on_threat_enabled` (`--fail-on-threat` flag) | `true`  | Exit 4 if CRITICAL or HIGH threats found         |

**With default settings (`strict_mode = true`, `fail_on_threat_enabled = true`):**

- Exit **0** — No threats found
- Exit **4** (`EXIT_THREAT_DETECTED`) — Any threat found (including LOW severity
  and social feed entries)

```bash
pkgd audit
```

To only fail on CRITICAL or HIGH threats, set the following in
`pkgd.toml`:

```toml
[cooldown]
strict_mode = false
```

Then use the `--fail-on-threat` flag (or leave it enabled by default):

```bash
pkgd audit --fail-on-threat
```

- Exit **0** — No threats found
- Exit **0** — LOW or MEDIUM threats found (logged but non-blocking)
- Exit **4** (`EXIT_THREAT_DETECTED`) — CRITICAL or HIGH threats found

### Full Exit Code Reference

All pkg-defender exit codes are defined in `src/pkg_defender/cli/_exit_codes.py`:

| Code | Name                        | Description                                     |
| ---- | --------------------------- | ----------------------------------------------- |
| 0    | `EXIT_SUCCESS`              | Success                                         |
| 1    | `EXIT_GENERAL_ERROR`        | General error                                   |
| 2    | `EXIT_USAGE_ERROR`          | Invalid arguments or usage error                |
| 3    | `EXIT_COOLDOWN`             | Package version is in cooldown period           |
| 4    | `EXIT_THREAT_DETECTED`      | Threat or vulnerability detected                |
| 5    | `EXIT_REGISTRY_UNREACHABLE` | Registry or network unreachable                 |
| 6    | `EXIT_CONFIG_ERROR`         | Configuration error                             |
| 7    | `EXIT_DB_ERROR`             | Database error                                  |
| 8    | `EXIT_PARTIAL_FAILURE`      | Setup completed with warnings (partial failure) |
| 130  | `EXIT_SIGINT`               | Interrupted by signal (SIGINT)                  |

## Output Formats for CI

### JSON Output

```bash
pkgd audit --output json
```

Machine-readable output for pipeline consumption. Parse with `jq`:

```bash
pkgd audit --output json | jq '.threats | length'
```

### Pretty-Printed JSON (Debugging)

For debugging or inspecting JSON output in CI logs:

```bash
pkgd audit --output json --pretty
```

This formats the JSON with indentation, making it easier to read in pipeline logs.

### CSV Output

```bash
pkgd audit --output csv
```

Tabular output for spreadsheet or reporting pipeline consumption.

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pkg-defender-audit
        name: Audit dependencies for threats
        entry: pkgd audit --fail-on-threat
        language: system
        pass_filenames: false
        files: (package-lock\.json|poetry\.lock|requirements\.txt|yarn\.lock|pnpm-lock\.yaml|uv\.lock|Pipfile\.lock)$
        always_run: true
```

Install pre-commit:

```bash
pip install pre-commit
pre-commit install
```

## GitLab CI

```yaml
dependency-audit:
  image: python:3.11
  stage: test
  script:
    - pip install uv
    - uv pip install pkg-defender
    - pkgd intel sync
    - pkgd audit --fail-on-threat --output json
  artifacts:
    reports:
      - pkgd-audit-report.json
```

## Azure Pipelines

```yaml
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'

- script: |
    pip install pkg-defender
    pkgd intel sync
    pkgd audit --fail-on-threat --output json > audit-report.json
  displayName: 'Audit dependencies'
```

## Environment Setup

### Complete Environment Example

```yaml
name: Dependency Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install uv
        uses: astral-sh/setup-uv@v5

      - name: Install pkg-defender
        run: uv pip install pkg-defender

      # Option 1: Download database snapshot (faster)
      - name: Download threat database
        run: pkgd db snapshot --download

      # OR: Sync feeds (most current)
      # - name: Sync threat intelligence
      #   run: pkgd intel sync

      - name: Audit dependencies
        run: pkgd audit --fail-on-threat --output json
        env:
          # Optional: GitHub token for higher GHSA rate limits
          PKGD_GITHUB_TOKEN: ${{ secrets.GHSA_TOKEN }}

          # Optional: Socket.dev API key
          PKGD_FEEDS_SOCKET_API_KEY: ${{ secrets.SOCKET_API_KEY }}

          # Explicitly enable CI mode
          PKGD_CI: 1
```

### Environment Variables in CI

| Variable                    | Required | Description                    |
| --------------------------- | -------- | ------------------------------ |
| `PKGD_CI`                   | No       | Explicit CI mode (1 to enable) |
| `PKGD_GITHUB_TOKEN`         | No       | Higher rate limits for GHSA    |
| `PKGD_FEEDS_SOCKET_API_KEY` | No       | Socket.dev feed access         |
| `PKGD_DATABASE_PATH`        | No       | Custom database path           |
| `PKGD_CONFIG_FILE`          | No       | Config file override           |

### Recommended Secrets

1. **GitHub Token** — For higher GHSA API rate limits
   - Create a Classic PAT with `read:packages` scope
   - Store as `GHSA_TOKEN` secret

2. **Socket.dev API Key** — For real-time threat signals
   - Get from Socket.dev dashboard
   - Store as `SOCKET_API_KEY` secret

## Pipeline Integration Patterns

### Gate on Pull Requests

```bash
# Fail PR if new threats introduced
pkgd audit --fail-on-threat --since 24h
```

### Weekly Scheduled Audit

```yaml
# GitHub Actions - scheduled weekly
on:
  schedule:
    - cron: '0 6 * * 1'  # Monday 6am UTC
```

### Post-Deploy Verification

```bash
# After deployment, verify no known threats in production dependencies
pkgd audit /path/to/deployed/lockfile --fail-on-threat
```

### GitHub Actions CI Integration Example Flow

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
│         │                   └──▶ SHA256 Verify                  │
│         │                             │                         │
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
        │           GitHub Snapshot Releases          │
        │      ┌───────────────────────────────┐      │
        └─────▶│  threats-latest.db.gz         │──────┘
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
                │     OSV     GHSA     OSSF    │
                │                              │
                │      (Tier 1 Feeds Only)     │
                │                              │
                ├──────────────────────────────┤
                │     PKG-Defender GitHub      │
                └──────────────────────────────┘
```
---

[← Back to Documentation](../index.md)
