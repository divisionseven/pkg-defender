# CLI Reference

Complete reference for all `pkgd` commands.

## Commands Overview

| Command                                 | Description                                                                 |
| --------------------------------------- | --------------------------------------------------------------------------- |
| [`pkgd hooks`](#pkgd-hooks)             | Generate shell functions for wrapped package manager commands               |
| [`pkgd audit`](#pkgd-audit)             | Scan lock files for threats and cooldown-pending packages                   |
| [`pkgd status`](#pkgd-status)           | Show recent threats, bypasses, and feed state                               |
| [`pkgd bypass`](#pkgd-bypass)           | Create bypass entries for blocked packages                                  |
| [`pkgd health`](#pkgd-health)           | Check system health                                                         |
| [`pkgd reset`](#pkgd-reset)             | Reset all data (database, config, feeds)                                    |
| [`pkgd setup`](#pkgd-setup)             | Interactive first-run setup wizard                                          |
| [`pkgd intel`](#pkgd-intel)             | Intelligence feed management (sync, search, report)                         |
| [`pkgd config`](#pkgd-config)           | Configuration management (view, list, set, set-secret, reset, get, options) |
| [`pkgd daemon`](#pkgd-daemon)           | Background daemon for periodic sync                                         |
| [`pkgd db snapshot`](#pkgd-db-snapshot) | Database snapshot management (download, verify)                             |
| [`pkgd db verify`](#pkgd-db-verify)     | Verify local database integrity and report summary                          |
| [`pkgd logs`](#pkgd-logs)               | View and follow log entries (view, follow)                                  |
| [`pkgd audit-logs`](#pkgd-audit-logs)   | Query and manage audit event logs                                           |
| [`pkgd completion`](#pkgd-completion)   | Shell tab completion (generate)                                             |

Total: 38 commands (14 top-level + 24 subcommands)

---

## Global Options

The following options are available on all commands:

| Option                       | Alias | Description                                                                                                                                            |
| ---------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--version`                  | `-V`  | Show version information                                                                                                                               |
| `--quiet`                    | `-q`  | Suppress non-error output                                                                                                                              |
| `--config PATH`              | `-c`  | Path to config file                                                                                                                                    |
| `--no-color`                 | —     | Disable colored output                                                                                                                                 |
| `--ascii`                    | —     | Force ASCII-only output (for Windows/CI environments)                                                                                                  |
| `--yes`                      | `-y`  | Skip confirmation prompts                                                                                                                              |
| `--force`                    | `-f`  | Skip confirmation prompts and force operations                                                                                                         |
| `--debug`                    | `-d`  | Show full tracebacks for unexpected errors                                                                                                             |
| `--verbose`                  | `-v`  | Increase verbosity: `-v` (INFO), `-vv` (DEBUG)                                                                                                         |
| `--no-verbose`               | —     | Disable verbose output (overrides PKGD_OUTPUT_VERBOSE env var)                                                                                         |
| `--dry-run`                  | `-n`  | Show what would be done without making changes                                                                                                         |
| `--ci` / `--non-interactive` | —     | Run in non-interactive CI mode (skip prompts, use env vars)                                                                                            |
| `--explain`                  | —     | Show detailed explanation of why packages were blocked                                                                                                 |
| `--json`                     | —     | Output result as JSON. For clearing commands (pass), JSON goes to stderr (use `2>result.json` to capture). Use `--dry-run --json` for pipeable output. |

### `--ci` / `--non-interactive` (Detailed)

Run in non-interactive (CI) mode. Skips all prompts and auto-confirms with defaults.

```bash
pkgd --ci install axios
pkgd --non-interactive setup
```

This flag is available on all commands and is useful for:
- CI/CD pipelines
- Automated scripts
- Docker containers
- Environments where user input is not possible

**Behavior:**
- Skips interactive prompts
- Uses default values for all optional inputs
- Auto-confirms destructive operations (if safe to proceed)
- Works with any command: `install`, `audit`, `setup`, `config`, etc.

**Priority:** Explicit `--ci` flag > `PKGD_CI` environment variable > auto-detection

---

## Command Wrapper Pattern

The PRIMARY way to interact with package managers is through the wrapper pattern:

```bash
pkgd <manager> <command> <package>
```

This pattern intercepts package manager commands and runs threat checks BEFORE execution.

### Supported Package Managers

| Ecosystem | Manager                             | Example Commands                                                                               |
| --------- | ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| npm       | npm, yarn, pnpm, bun                | `pkgd npm install`, `pkgd yarn add`, `pkgd pnpm install`                                       |
| Python    | pip, pip3, pipx, pipenv, poetry, uv | `pkgd pip install`, `pkgd pip3 install`, `pkgd pipx run`, `pkgd uv add`, `pkgd poetry install` |
| Ruby      | gem, bundler                        | `pkgd gem install`, `pkgd bundle install`                                                      |
| PHP       | composer                            | `pkgd composer require`, `pkgd composer install`                                               |
| Rust      | cargo                               | `pkgd cargo add`, `pkgd cargo install`                                                         |
| System    | brew, apt, dnf                      | `pkgd brew install`, `pkgd apt install`, `pkgd dnf install`                                    |

### How It Works

1. User types: `pkgd npm install axios`
2. Click's `ManagerGroup` detects `npm` is not a native subcommand
3. `ManagerGroup.get_command()` dynamically creates a wrapper for `npm`
4. Wrapper routes to `NpmAdapter` which runs threat checks
5. If safe, executes: `npm install axios`
6. If threats found, blocks execution and displays findings

### Examples

```bash
# Install a package with threat checking
pkgd npm install axios
pkgd pip install requests
pkgd brew install git

# Upgrade packages
pkgd apt upgrade
pkgd brew upgrade
pkgd npm update

# Add dependencies
pkgd yarn add lodash
pkgd poetry add pytest
pkgd cargo add serde
```

### Manager Wrapper Options

The following options are available on manager passthrough commands (e.g., `pkgd npm install`):

| Option                    | Description                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| `--allow-once [DURATION]` | Allow this single install, bypassing cooldown for a limited time (default: 24h, e.g. `--allow-once=6h`) |
| `--bypass-cooldown`       | Bypass cooldown check for this install (threat checks still run)                                        |
| `--bypass-threat`         | Bypass threat check for this install (cooldown still enforced)                                          |
| `--fail-on-threat`        | Exit with code 1 when threats are detected (default: enabled by config)                                 |

**Placement:**

```bash
# Postfix placement (after manager command)
pkgd npm install axios --allow-once
pkgd npm install axios --bypass-cooldown
pkgd npm install axios --fail-on-threat

# Prefix placement (before manager command — also works)
pkgd --allow-once npm install axios
```

> **Note:** `--force` / `-f` is a **global** option, not a manager passthrough option. It only works in prefix position: `pkgd --force npm install axios`. It does NOT work in postfix position after the manager command.

**Exit code 3:** If a cooldown-pending package is encountered and no bypass option is provided, the command exits with code 3 (`EXIT_COOLDOWN`).

> **Note:** ALL package actions go through the wrapper pattern. Use `pkgd <manager> <command>` for package manager operations.

---

## `pkgd hooks`

Generate shell functions that wrap package manager commands for threat protection.

```bash
pkgd hooks
pkgd hooks --shell fish
pkgd hooks -s powershell
```

The `hooks` command detects installed shells and package managers on your system, then prints shell-specific functions that you can copy into your RC file. Each function inspects the subcommand: dangerous operations (install, upgrade, remove, etc.) are routed through `pkgd` for threat checking, while safe commands (list, search, --help, etc.) pass directly to the real binary with zero overhead.

### Shell Detection

The command scans for supported shells (bash, zsh, fish, powershell, nushell) and identifies which are installed on your system. Use `--shell` to target a specific shell.

### Package Manager Detection

Each supported package manager is checked via its version command (e.g. `pip --version`, `brew --version`) or via `shutil.which()` for managers without dedicated detection commands (uv, yarn, pnpm, pip3).

### Shell Function Output

Functions are grouped by shell, then by package manager. Each shell section shows the RC file path and the function to add. Shell-specific syntax is used:

| Shell      | Function Format                                     |
| ---------- | --------------------------------------------------- |
| bash/zsh   | `brew() { case "$1" in install\|...) pkgd brew ...` |
| fish       | `function brew; switch $argv[1]; case install ...`  |
| powershell | `function brew { if ($args[0] -in @(...)) ... }`    |
| nushell    | `def brew [...args: string] { if ... }`             |

After adding the functions to your RC file, source it to activate them. The functions use `command <manager>` (or native equivalents) to call the real binary for safe subcommands, ensuring zero overhead for non-dangerous operations.

### Options

| Option             | Description                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| `-s, --shell TEXT` | Target shell (bash, zsh, fish, powershell, nushell). Auto-detects all installed shells by default. |
| `-h, --help`       | Show help message and exit.                                                                        |

---

## `pkgd audit`

Scan project lock files for threats and cooldown-pending packages.

```bash
pkgd audit [PATH] [OPTIONS]
```

### Options

| Option                       | Description                                                |
| ---------------------------- | ---------------------------------------------------------- |
| `--output [rich\|json\|csv]` | Output format (default: rich)                              |
| `--json`                     | Output JSON (same as `--output json`)                      |
| `--pretty`, `-p`             | Pretty-print JSON output (use with `--output json`)        |
| `--deep`, `-d`               | Also check cooldown status for each package                |
| `--fail-on-threat`, `-f`     | Exit 4 if CRITICAL or HIGH threats are found               |
| `--since DURATION`           | Only flag threats seen within duration (e.g., `7d`, `24h`) |

> [!Note]
> `--json` is a shorthand alias for `--output json` / `-o json`.
>
> The audit command exits with code `4` (`EXIT_THREAT_DETECTED`) under any of these conditions: `CRITICAL`/`HIGH` threats found (with `--fail-on-threat`), cooldown-pending packages detected, or `strict_mode` enabled with any threats. Exit `2` if no lock file is found. Exit `5` if the registry is unreachable.
>
> The `--pretty` flag formats JSON output with indentation and line breaks for readability, making it easier to read in the terminal or when inspecting output manually. Without `--pretty`, JSON is output as a compact single line.

### Examples

```bash
pkgd audit                             # audit current directory
pkgd audit /path/to/project            # audit specific project
pkgd audit --deep                      # include cooldown checks
pkgd audit --fail-on-threat            # fail CI on threats
pkgd audit --output json               # machine-readable JSON
pkgd audit --output json --pretty      # pretty-printed JSON for readability
pkgd audit --output csv                # CSV for spreadsheets/pipelines
pkgd audit --since 7d                  # only threats from last 7 days
pkgd audit --since 24h --output json   # recent threats as JSON
```

---

## `pkgd intel`

Intelligence feed commands.

### `pkgd intel sync`

```bash
pkgd intel sync
```

Syncs all enabled feeds (OSV, GHSA, npm Advisory, Homebrew, RSS, OSSF Malicious, and social feeds (Mastodon, Reddit, X/Twitter) if enabled). Socket.dev is point-query only and does not participate in bulk sync.

#### Options

| Option           | Alias | Description                                                                                              |
| ---------------- | ----- | -------------------------------------------------------------------------------------------------------- |
| `--output`       | `-o`  | Output format: `json` or `rich` (default: `rich`)                                                        |
| `--pretty`       | `-p`  | Pretty-print JSON output (only with `-o json`)                                                           |
| `--json`         | —     | Output JSON (same as `-o json`)                                                                          |
| `--exclude-feed` | —     | Exclude a feed from this sync. May be specified multiple times. Example: `--exclude-feed ossf_malicious` |

### `pkgd intel search`

```bash
pkgd intel search <query>
pkgd intel search <query> -o json            # JSON output
pkgd intel search <query> -o json --pretty   # pretty-printed JSON
```

Search the local threat database. Social feed entries are included but marked as informational.

#### Options

| Option               | Alias | Description                                                                                      |
| -------------------- | ----- | ------------------------------------------------------------------------------------------------ |
| `QUERY`              | —     | Search term (required, positional argument)                                                      |
| `--manager`          | `-m`  | Package manager to filter by (e.g., npm, pip, cargo)                                             |
| `--exclude-severity` | —     | Severity levels to exclude, comma-separated (CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN). Default: UNKNOWN |
| `--output`           | `-o`  | Output format: `json` or `rich` (default: `rich`)                                                |
| `--pretty`           | `-p`  | Pretty-print JSON output (only with `-o json`)                                                   |
| `--json`             | —     | Output JSON (same as `-o json`)                                                                  |

### `pkgd intel report`

```bash
pkgd intel report                      # Rich table output
pkgd intel report -o json              # JSON output
pkgd intel report -o json --pretty     # pretty-printed JSON
```

Displays a threat intelligence dashboard:
- **Threats by severity** — CRITICAL, HIGH, MEDIUM, LOW
- **Threats by source** — OSV.dev, GHSA, npm Advisory, Homebrew, RSS, OSSF Malicious, Socket.dev, social feeds (Mastodon, Reddit, X/Twitter)
- **Threats by ecosystem** — npm, pypi, homebrew, apt, yum, dnf, rubygems, cargo
- **Top targeted packages** — most-affected packages (top 10)
- **Feed health** — last sync time and status per feed

#### Options

| Option               | Alias | Description                                                                                      |
| -------------------- | ----- | ------------------------------------------------------------------------------------------------ |
| `--output`           | `-o`  | Output format: `json` or `rich` (default: `rich`)                                                |
| `--pretty`           | `-p`  | Pretty-print JSON output (only with `-o json`)                                                   |
| `--json`             | —     | Output JSON (same as `-o json`)                                                                  |
| `--manager`          | `-m`  | Package manager to filter by (e.g., npm, pip, cargo)                                             |
| `--exclude-severity` | —     | Severity levels to exclude, comma-separated (CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN). Default: UNKNOWN |

---

## `pkgd config`

Configuration management.

### `pkgd config view`

```bash
pkgd config view [OPTIONS]
```

Displays the current configuration with all resolved values (defaults + TOML + env vars). Secret values (API tokens) are shown as `[SECRET]` or `[not set]`.

#### Options

| Option   | Alias | Description                    |
| -------- | ----- | ------------------------------ |
| `--json` | —     | Output JSON instead of a table |

When `--json` is used, the output includes all 6 configuration sections (cooldown, feeds, output, database, bypass, daemon) as structured JSON. Secret field values are masked as `[SECRET]` when non-empty.

#### Examples

```bash
pkgd config view                        # rich table output
pkgd config view --json                 # JSON output with secret masking
pkgd --json config view                 # global --json flag also works
```

### `pkgd config list`

```bash
pkgd config list [OPTIONS]
```

List all configuration values with their sources. The source column shows whether each value comes from the built-in default or an environment variable override. When `--json` is used, every value is wrapped in a `{"value": ..., "source": ...}` object.

#### Options

| Option   | Alias | Description                    |
| -------- | ----- | ------------------------------ |
| `--json` | —     | Output JSON instead of a table |

#### Examples

```bash
pkgd config list                        # rich table output with source column
pkgd config list --json                 # JSON output with source annotations
pkgd --json config list                 # global --json flag also works
```

### `pkgd config set`

```bash
pkgd config set <key> <value>
```

Set a config value using dot notation for nested keys:

```bash
pkgd config set cooldown.default_days 7
pkgd config set cooldown.bypass_require_reason false
pkgd config set feeds.staleness_threshold_hours 8
pkgd config set feeds.socket_api_key your_key_here
pkgd config set cooldown.overrides.lodash 3
```

### `pkgd config set-secret`

```bash
pkgd config set-secret <key>
```

Set a secret configuration value (API token) with secure hidden input.

#### Valid Keys

| Key                            | Description                |
| ------------------------------ | -------------------------- |
| `feeds.ghsa_token`             | GitHub GraphQL API token   |
| `feeds.socket_api_key`         | Socket.dev API key         |
| `feeds.x_twitter_bearer_token` | X/Twitter API bearer token |
| `feeds.reddit_client_id`       | Reddit API client ID       |
| `feeds.reddit_client_secret`   | Reddit API client secret   |

This command:
- Prompts for the value with hidden input (not echoed to terminal)
- Requires typing the secret twice to confirm (prevents typos)
- Displays the set value as `********` (masked) for security

### `pkgd config reset`

```bash
pkgd config reset [OPTIONS]
```

Reset all configuration to built-in defaults.

### `pkgd config get`

```bash
pkgd config get <key>
```

Get a specific configuration value. Returns the raw value for scripting and integration.

**Exit codes:**

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| 0    | Success — value returned                         |
| 6    | Config error — key not found or has no value set |

#### Examples

```bash
pkgd config get cooldown.default_days
pkgd config get feeds.osv_enabled
pkgd config get database.wal_mode
```

### `pkgd config options`

```bash
pkgd config options
```

List all configurable options with descriptions and defaults. Outputs a table for each
configuration section showing the dotted path, type, default value, and description.

Combine with `pkgd config get <key>` to see the current value.

#### Examples

```bash
pkgd config options
pkgd config options | grep secret
```

**Exit codes:**
- Exit 0: Success

### Config File Location

Configuration is stored at `~/.config/pkg-defender/pkgd.toml` (platform equivalent via `platformdirs`).

---

## `pkgd status`

Show pkg-defender status: recent threats (last 7 days), active bypasses, and feed sync state.

```bash
pkgd status                      # rich table output
pkgd status -o json              # JSON output
pkgd status -o json --pretty     # pretty-printed JSON
```

### Options

| Option           | Alias | Description                           |
| ---------------- | ----- | ------------------------------------- |
| `-o`, `--output` | —     | Output format: rich or json           |
| `-p`, `--pretty` | —     | Pretty-print JSON output              |
| `--json`         | —     | Output JSON (same as `--output json`) |
| `--feeds`        | —     | Show feed-by-feed health status       |

---

## `pkgd bypass`

Create a bypass entry for a specific package version.

```bash
pkgd bypass <package@version> --reason <reason> [OPTIONS]
```

### Options

| Option            | Description                                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `--reason TEXT`   | Reason for bypass (required)                                                                                                             |
| `--manager`, `-m` | Package manager: apt, brew, bundler, bun, cargo, composer, dnf, gem, npm (default), pip, pip3, pipenv, pipx, pnpm, poetry, uv, yarn, yum |
| `--expires TEXT`  | Bypass expiry (e.g., `24h`, `7d`, `30m`)                                                                                                 |

### Examples

```bash
pkgd bypass lodash@4.17.21 --reason "audit complete"
pkgd bypass axios@1.6.0 --reason "testing" --expires 24h
pkgd bypass pkg@2.0.0 --reason "permanent exception"  # never expires
pkgd bypass express@4.18.0 --reason "dev testing" --expires 7d
```

---

## `pkgd health`

Check pkg-defender system health. Runs comprehensive diagnostics on:

1. **Config File** - Validates pkgd.toml is valid TOML and all settings are valid
2. **Database** - Checks database exists, schema is current, WAL mode status
3. **Intelligence Feeds** - Shows health status for each configured feed:
   - OSV, GHSA, Socket.dev, Reddit, RSS, Mastodon, X/Twitter
   - Shows: Configured (yes/no), Last Sync (timestamp), Status (healthy/error)
4. **API Token Status** - Validates API tokens by making test API calls:
   - GitHub (GHSA): Valid/Invalid/Expired/Not configured
   - Socket.dev: Valid/Invalid/Expired/Not configured
   - X/Twitter: Valid/Invalid/Expired/Not configured
5. **Shell Commands** - Checks which shells have commands installed (zsh, bash, fish, etc.)
6. **Disk Space** - Shows available disk space at data directory
7. **File Permissions** - Checks read/write access for config and database files

```bash
pkgd health                 # Full system check
pkgd health -o json        # JSON output
pkgd health --pretty       # Pretty-printed JSON
```

### Options

| Option            | Alias | Description                                                                  |
| ----------------- | ----- | ---------------------------------------------------------------------------- |
| `-o`, `--output`  | —     | Output format: rich or json                                                  |
| `-p`, `--pretty`  | —     | Pretty-print JSON output                                                     |
| `-v`, `--verbose` | —     | Show detailed diagnostic info (coverage matrix, threat counts, feed details) |

Exit Codes:
- 0 - All checks passed
- 1 - One or more checks failed
---

## Exit Codes Reference

All pkg-defender commands use domain-specific exit codes defined in `src/pkg_defender/cli/_exit_codes.py` (lines 10-22):

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

### Per-Command Exit Behavior Summary

The following exit codes are used per-command (see individual command sections for details):

| Code | Applies To                                                                                    |
| ---- | --------------------------------------------------------------------------------------------- |
| 3    | Manager wrapper passthrough commands (cooldown-pending packages without bypass)               |
| 4    | `pkgd audit` (threats, cooldown, strict mode), manager wrapper (threats)                      |
| 6    | `pkgd config get` (key not found or no value), `pkgd config set` / `set-secret` (invalid key) |
| 7    | `pkgd db snapshot --verify` (local database integrity failure)                                |
| 8    | `pkgd setup` (partial failure)                                                                |

#### `pkgd health`

- Exit 0: All checks passed
- Exit 1: One or more checks failed

#### `pkgd audit`

- Exit 0: No threats or cooldown-pending packages found
- Exit 2: No lock file found or unrecognised lock file format
- Exit 4: Threats detected (`EXIT_THREAT_DETECTED`) — triggered by: CRITICAL/HIGH threats with `--fail-on-threat`, cooldown-pending packages, or `strict_mode` enabled
- Exit 5: Registry or network unreachable

#### Manager Wrapper Passthrough

- Exit 0: Package safe to install
- Exit 3: Cooldown-pending package blocked (no bypass option provided)
- Exit 4: Threat detected and blocked

---

## `pkgd reset`

Reset pkg-defender data. Removes the threat database and feed state.

```bash
pkgd reset              # delete database only, prompts for confirmation
pkgd reset --yes        # skip confirmation
pkgd reset --teardown / -t   # delete DB + config + uninstall daemon service
```

---

## `pkgd setup`

Interactive first-run setup wizard. Detects your shell and installs tab completions and configures package managers.

```bash
pkgd setup                        # detect shell, install completions, sync feeds
pkgd setup --init                 # non-interactive config creation
pkgd setup --shell zsh            # override detected shell
pkgd setup --dry-run              # show what would be changed without modifying files
```

### Options

| Option      | Alias | Description                                                    |
| ----------- | ----- | -------------------------------------------------------------- |
| `--init`    | `-i`  | Non-interactive mode — creates default config and exits        |
| `--force`   | `-f`  | Overwrite existing pkgd.toml when used with --init             |
| `--shell`   | `-s`  | Override detected shell (zsh, bash, fish, powershell, nushell) |
| `--dry-run` | `-n`  | Show what would be changed without modifying files             |

Supported shells: zsh, bash, fish, PowerShell, Nushell.

**Exit codes**

- Exit 0: Setup completed successfully
- Exit 2: Invalid arguments or shell not supported
- Exit 8: Setup completed with warnings (partial failure)
---

## `pkgd db snapshot`

Manage database snapshots: download pre-built threat databases, verify integrity, check versions.

```bash
pkgd db snapshot [OPTIONS]
```

### Options

| Option       | Alias | Description                                                                     |
| ------------ | ----- | ------------------------------------------------------------------------------- |
| `--download` | `-d`  | Download snapshot with SHA256 verification (from GitHub Releases or custom URL) |
| `--verify`   | `-v`  | Verify local database integrity with SHA256                                     |
| `--latest`   | `-l`  | Show latest available snapshot version                                          |
| `--force`    | `-f`  | Force replacement of existing database                                          |

### Examples

```bash
# Check latest available snapshot version
pkgd db snapshot --latest

# Verify local database integrity
pkgd db snapshot --verify

# Download the latest snapshot
pkgd db snapshot --download

# Force replace existing database
pkgd db snapshot --download --force
```

**Exit codes:**

| Code | Meaning                                                    |
| ---- | ---------------------------------------------------------- |
| 0    | Success                                                    |
| 1    | General error                                              |
| 7    | Database integrity failure (local `--verify` check failed) |

### Database Snapshots

Pre-built threat intelligence databases are published to GitHub Releases. These snapshots contain:
- OSV.dev advisories
- GitHub Security Advisories (GHSA)
- Socket.dev signals
- npm advisories

**Benefits:**
- Faster setup in CI/CD pipelines
- Consistent database across environments
- No need to sync feeds on every run

**Usage Pattern:**

```yaml
# In CI: download snapshot instead of syncing
- name: Download threat database
  run: pkgd db snapshot --download

# Or verify existing snapshot integrity
- name: Verify database
  run: pkgd db snapshot --verify
```

> **Note:** Snapshots are updated regularly but may not contain the very latest advisories. For most current intel, use `pkgd intel sync` instead.

---

## `pkgd db verify`

Verify local database integrity and display a summary of database health.

```bash
pkgd db verify
```

### Description

Opens the local threat database in read-only mode and runs `PRAGMA integrity_check` to detect SQLite page-level corruption. Reports four summary fields after a successful integrity check:

- **Threat records** — total count of threats in the database
- **Last sync** — timestamp of the most recent feed sync
- **Schema version** — database schema version from `db_metadata`
- **File size** — database file size on disk (human-readable)

### Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | Database is healthy           |
| 1    | Database not found or corrupt |

### Examples

```bash
# Verify database integrity
pkgd db verify

# Example output:
# Verifying database at /home/user/.local/share/pkg-defender/threats.db...
# PRAGMA integrity_check: ok
#
# Database Summary:
#   Threat records:  14,732
#   Last sync:       2026-05-19 14:30:00
#   Schema version:  10
#   File size:       4.2 MB
```

> **Note:** This command runs `PRAGMA integrity_check` on the **running database** — it validates the SQLite B-tree page structure. To verify snapshot SHA256 during download, use `pkgd db snapshot --verify` instead.

---

## `pkgd logs`

View and follow log entries.

### `pkgd logs view`

View recent log entries.

```bash
pkgd logs view [OPTIONS]
```

#### Options

| Option          | Alias | Description                            |
| --------------- | ----- | -------------------------------------- |
| `-n`, `--lines` | —     | Number of lines to show (default: 100) |
| `-f`, `--full`  | —     | Show full log file (not just recent)   |

#### Examples

```bash
pkgd logs view
pkgd logs view -n 50
pkgd logs view --full
```

### `pkgd logs follow`

Follow new log entries as they are written (tail -f style).

```bash
pkgd logs follow [OPTIONS]
```

#### Options

| Option          | Alias | Description                                   |
| --------------- | ----- | --------------------------------------------- |
| `-n`, `--lines` | —     | Number of initial lines to show (default: 10) |

Press Ctrl+C to stop following.

#### Examples

```bash
pkgd logs follow
pkgd logs follow -n 20
```

---

## `pkgd audit-logs`

Query and manage audit event logs.

```bash
pkgd audit-logs [OPTIONS] COMMAND [ARGS]...
```

### `pkgd audit-logs query`

Query audit event logs.

```bash
pkgd audit-logs query [OPTIONS]
```

Displays audit events matching the specified filters.

#### Options

| Option                             | Description                                                          |
| ---------------------------------- | -------------------------------------------------------------------- |
| `--ecosystem ECOSYSTEM`            | Filter by ecosystem (e.g., npm, pypi)                                |
| `--package PACKAGE` / `-p PACKAGE` | Filter by package name                                               |
| `--source SOURCE`                  | Filter by source (shell_hook, cli, api, cron, test)                  |
| `--verdict VERDICT`                | Filter by verdict (PASS, PARTIAL_PASS, FAIL, BLOCKED, WARN, ERROR)   |
| `--since DATETIME`                 | Only show events after ISO8601 datetime (e.g., 2026-01-01T00:00:00)  |
| `--until DATETIME`                 | Only show events before ISO8601 datetime (e.g., 2026-01-01T00:00:00) |
| `--limit N` / `-l N`               | Maximum events to return (default: 100)                              |

#### Examples

```bash
pkgd audit-logs query
pkgd audit-logs query --ecosystem npm
pkgd audit-logs query --verdict FAIL
pkgd audit-logs query --since 2026-01-01
pkgd audit-logs query -l 50
pkgd audit-logs query --package lodash
pkgd audit-logs query -p express
pkgd audit-logs query --source shell_hook
pkgd audit-logs query --until 2026-01-31T23:59:59
pkgd audit-logs query --ecosystem npm --package lodash --verdict FAIL
pkgd audit-logs query --since 2026-01-01T00:00:00 --until 2026-01-31T23:59:59
```

### `pkgd audit-logs stats`

Show aggregate audit statistics.

```bash
pkgd audit-logs stats
```

Displays summary statistics for audit events including counts by verdict, ecosystem, and source.

#### Options

| Option             | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| `--since DATETIME` | Only show events after ISO8601 datetime (e.g., 2026-01-01T00:00:00)  |
| `--until DATETIME` | Only show events before ISO8601 datetime (e.g., 2026-01-31T23:59:59) |

#### Examples

```bash
pkgd audit-logs stats
pkgd audit-logs stats --since 2026-01-01T00:00:00
pkgd audit-logs stats --until 2026-01-31T23:59:59
pkgd audit-logs stats --since 2026-01-01T00:00:00 --until 2026-01-31T23:59:59
```

---

## `pkgd completion`

Shell tab completion commands.

### `pkgd completion generate`

Generate shell completion script.

```bash
pkgd completion generate <shell> [OPTIONS]
```

### Options

| Option               | Alias | Description                                      |
| -------------------- | ----- | ------------------------------------------------ |
| `shell` (argument)   | —     | Shell type: bash, zsh, fish, powershell, nushell |
| `-e`, `--executable` | —     | Name of the executable (default: pkgd)           |

### Examples

```bash
pkgd completion generate bash > /etc/bash_completion.d/pkgd
pkgd completion generate zsh > ~/.zsh/completions/_pkgd
pkgd completion generate fish | source
pkgd completion generate powershell > ~/Documents/PowerShell/pkgd_completion.ps1
pkgd completion generate nushell > ~/.config/nushell/completions/pkgd.nu
```

---

## `pkgd daemon`

Background daemon commands for periodic feed synchronization.

```bash
pkgd daemon run          # run in foreground (for service managers)
pkgd daemon start        # start as background process
pkgd daemon stop         # stop the background daemon
pkgd daemon restart      # restart the background daemon
pkgd daemon status       # show daemon status from heartbeat
pkgd daemon install      # install as system service (macOS/Linux/Windows)
pkgd daemon uninstall    # uninstall system service
```

### `pkgd daemon run`

Run the daemon in the foreground (used by service managers).

### `pkgd daemon start`

Start the daemon as a background process.

### `pkgd daemon stop`

Stop the background daemon by removing stale heartbeat.

### `pkgd daemon restart`

Restart the background daemon. Stops the running daemon (if any) and starts
a new background process. Delegates to `daemon stop` then `daemon start`
sequentially.

```bash
pkgd daemon restart
```

### `pkgd daemon status`

Show daemon status from heartbeat.

Exit Codes:
- 0 - Daemon is running
- 1 - Daemon is not running

### `pkgd daemon install`

Install the daemon as a system service.

| Option       | Alias | Description                             |
| ------------ | ----- | --------------------------------------- |
| `--platform` | —     | Target platform (macos, linux, windows) |

### `pkgd daemon uninstall`

Uninstall the daemon system service.

### Files

The daemon writes two files to the data directory:

| File          | Purpose                                           |
| ------------- | ------------------------------------------------- |
| `daemon.pid`  | Contains the PID of the running daemon process    |
| `daemon.lock` | Kernel-level lock for single-instance enforcement |

`daemon.lock` is created at startup via `fcntl.flock()` and held for the lifetime of the process. The OS releases the lock when the daemon terminates, but the empty file persists on disk. Do not delete it manually; it is recreated on the next daemon start.

---

[← Back to Documentation](../index.md)
