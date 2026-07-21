---
title: PKGD(1)
date: "July 20, 2026"
footer: "pkg-defender 1.0.6"
header: "User Commands"
---

# NAME

pkgd — supply chain attack defense CLI

# SYNOPSIS

**pkgd** [*OPTIONS*] *COMMAND* [*ARGS*...]

**pkgd** [*OPTIONS*] *MANAGER* *SUBCOMMAND* [*PACKAGE*...] [*MANAGER_OPTIONS*...]

# DESCRIPTION

**pkg-defender** is a supply chain security tool that intercepts package manager commands to check packages against known threats and cooldown policies before they are installed. It supports wrapping package managers such as npm, pip, brew, cargo, and others transparently.

When invoked with a known package manager name as the first argument, **pkgd** intercepts the command, performs security checks (threat database lookup and cooldown verification), and either allows or blocks the operation. When invoked with a native subcommand, it provides threat intelligence, auditing, configuration, and system management features.

# COMMANDS

## Common Commands

**setup**
:   Run the first-time setup wizard to configure feeds, API tokens, and initial settings.

**status**
:   Show defender status including intelligence feed health, active bypasses, and threat counts by severity. Use **\--feeds** for per-feed details.

**audit** *PATH*
:   Scan a project's dependency lock file for known vulnerabilities and cooldown-pending packages. Supports package-lock.json, poetry.lock, requirements.txt, yarn.lock, pnpm-lock.yaml, Pipfile.lock, and uv.lock. Use **\--deep** to also check cooldown status for each package. Use **\--fail-on-threat** to exit with code 4 on CRITICAL/HIGH findings.

**bypass** *PACKAGE_SPEC* **\--reason** *TEXT*
:   Create a bypass entry that allows a specific package version to skip all safety checks. **WARNING:** This disables cooldown and threat detection for the specified package. Requires **\--reason**.

**health**
:   Run system diagnostics: checks config file accessibility, database connectivity, WAL mode, feed sync status, API token validity, disk space, and file permissions. Use **\--verbose** for detailed diagnostics.

**reset**
:   Reset all pkg-defender data. Without **\--teardown**, only the threat database is deleted. With **\--teardown**, the config file and daemon service are also removed.

## Management Commands

**config**
:   Manage configuration settings. Subcommands: *view*, *list*, *set*, *get*, *set-secret*, *options*, *reset*.

    **config view** [**\--json**]
    :   Display the current configuration (all sections). Secret values are masked as `[SECRET]`. With **\--json** output is JSON.

    **config list** [**\--json**]
    :   List all current configuration values with their sources. The source column shows whether each value comes from the default or an environment variable.

    **config set** *KEY* *VALUE*
    :   Set a configuration value (e.g., `config set output.color false`). Values are type-coerced to the target field's type before writing.

    **config get** *KEY*
    :   Get a specific configuration value. Secret values are masked.

    **config set-secret** *KEY*
    :   Set a secret value with hidden input (API tokens, etc.). Masked on output.

    **config options**
    :   List all configurable options with their dotted path, type, default, and description.

    **config reset**
    :   Reset configuration to defaults (preserves the config file location and `[SECRET]` entries).

**intel**
:   Threat intelligence feed commands. Subcommands: *sync*, *search*, *report*.

    **intel sync** [**\--output** *FORMAT*] [**\--pretty**] [**\--json**] [**\--exclude-feed** *FEED*]
    :   Sync threat intelligence from all configured feeds. Feeds: OSV, GHSA, Socket.dev, npm Advisory, OSSF Malicious, Mastodon, Reddit, RSS, X/Twitter. Homebrew is auto-included when `brew` is on `$PATH`.

    **intel search** *QUERY* [**\--manager** *NAME*] [**\--output** *FORMAT*] [**\--pretty**] [**\--json**] [**\--exclude-severity** *LIST*]
    :   Search the local threat database for packages or vulnerabilities. Use **\--manager** to filter by ecosystem.

    **intel report** [**\--output** *FORMAT*] [**\--pretty**] [**\--json**] [**\--manager** *NAME*] [**\--exclude-severity** *LIST*]
    :   Display a threat intelligence report showing recent threats (last 7 days), severity breakdown, source breakdown, ecosystem analysis (last 30 days), and top targeted packages (last 30 days).

**daemon**
:   Background daemon management commands. Subcommands: *run*, *start*, *stop*, *restart*, *status*, *install*, *uninstall*.

    **daemon run**
    :   Run daemon in the foreground (for service managers like systemd/launchd).

    **daemon start**
    :   Start the background sync daemon (writes PID file at `daemon.pid` in the data directory).

    **daemon stop**
    :   Stop the running daemon (SIGTERM with 5s grace, then SIGKILL).

    **daemon restart**
    :   Stop the running daemon (if any) and start a new background process.

    **daemon status**
    :   Show daemon status from heartbeat and PID file.

    **daemon install** [**\--user**]
    :   Install the daemon as a system service (launchd on macOS, systemd on Linux, scheduled task on Windows) for automatic startup.

    **daemon uninstall**
    :   Remove the daemon system service.

## Other Commands

**hooks**
:   Generate shell functions for transparent package manager wrapping. Detects installed shells and package managers, then prints functions that can be added to your shell RC file. Each function conditionally routes dangerous subcommands through pkgd while passing safe commands directly to the real binary.

**completion generate** *SHELL*
:   Generate shell completion script for the specified shell. Supports bash, zsh, fish, powershell, and nushell.

**audit-logs query** [**\--ecosystem** *NAME*] [**\--package** *NAME*] [**\--verdict** *NAME*] [**\--source** *NAME*] [**\--since** *ISO*] [**\--until** *ISO*] [**\--limit** *N*]
:   Query audit event logs with optional filters for ecosystem, package, verdict, source, and time range.

**audit-logs stats**
:   Show aggregate audit statistics including counts by verdict, ecosystem, and source.

**db snapshot** [**\--download**] [**\--verify**] [**\--latest**] [**\--force**]
:   Database snapshot management. **\--download** fetches a snapshot with SHA256 verification (from GitHub Releases or custom URL). **\--verify** checks the SHA256 and integrity of the local database. **\--latest** shows the latest available snapshot version on GitHub. **\--force** replaces an existing database.

**db verify**
:   Verify local database integrity and report summary. Runs `PRAGMA integrity_check` to detect page-level corruption, then reports threat count, last sync time, schema version, and file size. Exits with code 7 if corruption is detected or the database cannot be opened.

**logs view** [**\--lines** *N*] [**\--full**]
:   View recent log entries (default: 100 lines). Use **\--full** to show the entire log file.

**logs follow** [**\--lines** *N*]
:   Follow new log entries as they are written (tail-f style, default 10 initial lines). Press Ctrl+C to stop.

## Package Manager Commands

When invoked with a known package manager name, **pkgd** intercepts the command:

```
pkgd MANAGER ARGS...
```

Examples:

```
pkgd pip install requests
pkgd npm install express
pkgd brew install tree
pkgd cargo add serde
```

The 19 supported invokable managers are: **apt**, **brew**, **bun**, **bundler**, **cargo**, **composer**, **conda**, **dnf**, **gem**, **npm**, **pip**, **pip3**, **pipenv**, **pipx**, **pnpm**, **poetry**, **uv**, **yarn**, **yum**.

# GLOBAL OPTIONS

**-V**, **\--version**
:   Show version information and exit.

**-q**, **\--quiet**
:   Suppress non-error output.

**-c**, **\--config** *PATH*
:   Path to config file. Overrides the default platform-specific location and `PKGD_CONFIG_PATH`.

**\--no-color**
:   Disable colored output. (See also `NO_COLOR`.)

**\--ascii**
:   Force ASCII-only output (for Windows/CI environments).

**-y**, **\--yes**
:   Skip confirmation prompts.

**-f**, **\--force**
:   Skip confirmation prompts and force operations.

**-d**, **\--debug**
:   Show full tracebacks for unexpected errors. (See also `PKGD_DEBUG`.)

**-v**, **\--verbose**
:   Increase verbosity: **-v** (INFO), **-vv** (DEBUG).

**\--no-verbose**
:   Disable verbose output (overrides `PKGD_OUTPUT_VERBOSE` env var).

**-n**, **\--dry-run**
:   Show what would be done without making changes. (See also `PKGD_DRY_RUN`.)

**\--ci**, **\--non-interactive**
:   Run in non-interactive CI mode (skip prompts, use env vars). (See also `PKGD_CI`.)

**\--explain**
:   Show detailed explanation of why packages were blocked.

**\--json**
:   Output result as JSON. For clearing commands (pass), JSON goes to stderr. Use **\--dry-run \--json** for pipeable output.

**-h**, **\--help**
:   Show help message and exit.

# WRAPPER OPTIONS

These options are accepted on every package-manager wrapper invocation (e.g., `pkgd pip install ...`). They control the protection pipeline applied to the intercepted command.

**\--fail-on-threat**
:   Exit with code 4 (`EXIT_THREAT_DETECTED`) when CRITICAL or HIGH threats are detected. Default behavior is configurable via `config.fail_on_threat_enabled`.

**\--cooldown** *HOURS*
:   Override the cooldown window (in hours) for this invocation. The hours value is converted to days (rounded up) and used as the cooldown window. Invalid values fall back to the config default.

**\--allow-once** *DURATION*
:   Allow this single install, bypassing cooldown (default: 24h, e.g., **\--allow-once=6h**). Threat checks still run.

**\--bypass-cooldown**
:   Skip the cooldown check (threat checks still run).

**\--bypass-threat**
:   Skip the threat check (cooldown is still enforced).

**\--dry-run**, **-n**
:   Show what would happen without making changes. (Also a global option.)

**\--json**
:   Output result as JSON. (Also a global option.)

**\--verbose**, **-v**
:   Increase verbosity. (Also a global option.)

**\--ci**, **\--non-interactive**
:   Run in non-interactive CI mode. (Also a global option.)

**\--explain**
:   Show detailed explanation for blocked packages. (Also a global option.)

**\--force**, **-f**
:   Skip confirmation prompts. (Also a global option.)

# EXIT STATUS

**0**
:   Success.

**1**
:   General error.

**2**
:   Usage error (invalid arguments).

**3**
:   Cooldown block (package version is in cooldown period).

**4**
:   Threat detected (vulnerability or malicious package found) **or** cooldown-pending packages in `audit` (see `audit.py:288-289` for the `audit` command's exit-on-cooldown-pending behavior).

**5**
:   Registry unreachable (network or registry error).

**6**
:   Configuration error.

**7**
:   Database error.

**8**
:   Partial failure (e.g., setup completed with warnings).

**130**
:   Interrupted by signal (SIGINT / Ctrl+C).

# FILES

*~/.config/pkg-defender/pkgd.toml*
:   User configuration file. On macOS, the path is *~/Library/Application Support/pkg-defender/pkgd.toml*. On Windows, the path is *%APPDATA%\\pkg-defender\\pkgd.toml*. The exact path is resolved via `platformdirs.user_config_dir("pkg-defender")` and can be overridden by `PKGD_CONFIG_PATH` or **\--config**.

*~/.local/share/pkg-defender/threats.db*
:   Local threat intelligence database (SQLite). Path is resolved via `platformdirs.user_data_dir("pkg-defender")` (macOS: *~/Library/Application Support/pkg-defender/threats.db*).

*~/.local/share/pkg-defender/pkgd.log*
:   Application log file (rotating, 10 MB per file, 5 backups). Path is the same data directory as `threats.db`.

*~/.local/share/pkg-defender/daemon.pid*
:   PID file for the background daemon. Used by `daemon start` / `daemon stop` to send SIGTERM/SIGKILL.

# ENVIRONMENT

**NO_COLOR**
:   Disable colored output (standard env var). Takes precedence over `config.output.color`.

**PKGD_CONFIG_PATH**
:   Path to config file. Overrides the default platform-specific location and the **\--config** flag has higher precedence.

**PKGD_DRY_RUN**
:   Enable dry-run mode (equivalent to **\--dry-run**).

**PKGD_CI**
:   Enable CI mode (equivalent to **\--ci**).

**PKGD_DEBUG**
:   Enable debug mode (set to **1**).

**PKGD_OUTPUT_VERBOSE**
:   Enable verbose output by default.

**PKGD_OUTPUT_COLOR**
:   Set to **false** to disable colored output (overridden by **\--no-color** or `NO_COLOR`).

**PKGD_COOLDOWN_STRICT_MODE**
:   Exit code 4 if any threats are found (default: **false**). Equivalent to `config.cooldown.strict_mode`.

**PKGD_COOLDOWN_DEFAULT_DAYS**
:   Override the cooldown period in days (default: **7**). Equivalent to `config.cooldown.default_days`.

# LOCK FILE FORMATS

The `audit` command recognizes the following dependency lock file formats:

- **package-lock.json** (npm v2 / v3)
- **poetry.lock** (Poetry)
- **requirements.txt** (pip)
- **yarn.lock** (Yarn classic)
- **pnpm-lock.yaml** (pnpm)
- **Pipfile.lock** (Pipenv)
- **uv.lock** (uv)

# INTELLIGENCE FEEDS

The `intel sync` command fetches from the following threat intelligence sources (when enabled in `config.feeds.*`):

- **OSV** (Open Source Vulnerabilities) — always enabled
- **GHSA** (GitHub Advisory Database)
- **npm Advisory Database** — enabled by `feeds.npm_advisory_enabled`
- **Homebrew** — auto-included when `brew` is on `$PATH`
- **OSSF Malicious Packages** — enabled by `feeds.ossf_malicious_enabled`
- **Socket.dev** — enabled by `feeds.socket_enabled`
- **Mastodon** — enabled by `feeds.mastodon_enabled`
- **Reddit** — enabled by `feeds.reddit_enabled`
- **RSS** — enabled by `feeds.rss_enabled`
- **X / Twitter** — enabled by `feeds.x_twitter_enabled`
- **`--exclude-feed`** *FEED* — exclude a feed from this sync. May be specified multiple times. Example: `--exclude-feed ossf_malicious`

# SHELL COMPLETION

Generate shell completion scripts for the following shells via `pkgd completion generate <SHELL>`:

- **bash**
- **zsh**
- **fish**
- **powershell**
- **nushell**

# EXAMPLES

Run the setup wizard:

```
pkgd setup
```

Sync threat intelligence:

```
pkgd intel sync
```

Audit a project's lock file:

```
pkgd audit ./my-project --deep
```

Install a package through the wrapper (intercepted):

```
pkgd pip install requests
```

Search for a known-vulnerable package:

```
pkgd intel search log4j --manager pip
```

Output audit results as JSON for CI consumption:

```
pkgd audit . --output json --pretty
```

# SEE ALSO

Project repository: https://github.com/divisionseven/pkg-defender

For more information on a specific command, run:

```
pkgd COMMAND --help
```

For project documentation, see `docs/index.md`.
