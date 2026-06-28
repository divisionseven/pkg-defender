# Interception Lifecycle

Command interception in pkg-defender follows a defined lifecycle from user invocation through threat assessment to either execution handoff or block. This document traces that path step by step.

## Flow Overview

```mermaid
flowchart TD
    User["User runs: pkgd <manager> <command>"] --> CLI[Click CLI Entry Point]
    CLI --> Group[ManagerGroup]
    Group -->|Direct match| Direct[Direct pkgd subcommand]
    Group -->|Manager name| Passthrough[make_manager_passthrough_command]
    Group -->|No match| Error[Suggestion / UsageError]
    Passthrough --> Dispatcher[ManagerDispatcher]
    Dispatcher --> Parse[Adapter.parse]
    Parse --> Intent{Command intent?}

    Intent -->|SAFE_PASSTHROUGH| Exec
    Intent -->|REMOVE| Exec
    Intent -->|EXECUTE| Check
    Intent -->|INSTALL / UPDATE / SYNC| Check

    Check["_ensure_db_fresh()"] -->|Stale + fail| DBFail[SystemExit EXIT_DB_ERROR]
    Check -->|Pass| Protect[Protection check]
    Protect --> Resolve[Version resolution (registry API)]
    Resolve --> Cache[Timestamp caching (registry API)]
    Cache --> Source{Install source?}
    Source -->|LOCAL_PATH| Local[Local path warning + exec]
    Source -->|VCS| VCSWarn[VCS warning + confirm]
    Source -->|Registry| Tier{Coverage tier}

    Tier -->|AUDIT| CheckT[AUDIT: threat check only]
    Tier -->|PARTIAL / FULL| CheckTC[PARTIAL / FULL: threat + cooldown]

    CheckT -->|Block| Block
    CheckT -->|Pass| Exec
    CheckTC -->|Block| Block[handle_blocked_command]
    CheckTC -->|Pass| Exec

    Exec[handle_cleared_command] --> Handoff[os.execvp → native PM]
    Block --> Warn[Block display + optional bypass]
```

The lifecycle has three phases: command routing, threat assessment, and final disposition.

## Phase 1: Command Routing

### ManagerGroup

When a user runs `pkgd <manager> <command>`, the CLI entry point delegates to `ManagerGroup` (`cli/group.py`). This custom Click Group overrides the `get_command()` method to implement multi-step resolution:

1. **Direct match** — If the command name matches a built-in subcommand (e.g., `audit`, `intel`, `setup`), the built-in command runs normally.
2. **Manager registry** — `get_adapter_class_for_manager(cmd_name)` checks the unified manager registry. If the name maps to an adapter class (e.g., `"pip"` → `PyPIUnifiedAdapter`), `make_manager_passthrough_command(cmd_name)` generates a dynamic Click command.
3. **Fuzzy match** — `difflib.get_close_matches()` suggests similar command names. If a close match is found, Click fails with a "Did you mean?" suggestion. Otherwise, it fails with a generic unknown-command error.
4. **Fallback** — Returns `None`, letting Click raise `UsageError` naturally.

This design is what makes `pkgd pip install requests` work without `pip` being a predefined Click subcommand. The group intercepts the unknown name and routes it to the package manager system.

### make_manager_passthrough_command

The dynamically created command collects raw arguments and hands them to the dispatcher:

1. Uses Click's `ignore_unknown_options=True` and `allow_extra_args=True` so that package manager flags (such as `--save-dev` or `--no-cache`) pass through without Click rejecting them.
2. Collects all remaining CLI tokens as `manager_args` via `click.argument("manager_args", nargs=-1, type=click.UNPROCESSED)`.
3. Passes the raw arguments, along with the manager name, to a `ManagerDispatcher` instance.

> **Note:** pkgd flags are consumed at different points depending on where they appear:
> - **Root group options** (`--dry-run`, `--force`, `--ci`, `--json`, `--verbose`/`-v`, `--explain`): Consumed by Click and stored in context — work both before and after the subcommand
> - **Passthrough options** (`--fail-on-threat`, `--allow-once`, `--bypass-cooldown`, `--bypass-threat`): Consumed by Click on the passthrough command — must appear after the subcommand
> - **Raw string flags** (`--cooldown`): Pass through in `manager_args` and are separated by `split_pkgd_flags()` inside each adapter's `parse()` method

### ManagerDispatcher

`ManagerDispatcher` (`cli/dispatcher.py`) is the routing hub. It receives the manager name and looks up the corresponding adapter class via `get_adapter_class_for_manager()` from `UNIFIED_MANAGER_REGISTRY`. If no adapter exists for the given manager name, the dispatcher raises an error and the command fails — this is the first security boundary (see [Architecture](architecture.md) for the full description of all three security boundaries).

Once the adapter is instantiated, the dispatcher calls `adapter.parse(manager_args)` to determine the command's intent.

## Phase 2: Intent Determination

### Intent-Based Routing

The adapter's `parse()` method categorises every command into one of seven intents:

- **SAFE_PASSTHROUGH** — Non-mutating commands (help, info, search, list). These route directly to `handle_cleared_command()` without any threat check.
- **REMOVE** — Uninstall or remove commands. These also bypass the threat check — there is no need to block a removal.
- **INSTALL** — New package installation. Triggers the threat check pipeline.
- **UPDATE** — Version upgrades. Also triggers the threat check pipeline.
- **SYNC** — Lockfile/manifest-based installation. Also triggers the threat check pipeline.
- **EXECUTE** — Download-and-execute commands (`npx`, `dlx`, `bunx`, `uv run`, `cargo run`, `poetry run`, `bundle exec`). Triggers the threat check pipeline because these may install and execute arbitrary code.
- **UNKNOWN** — Commands that could not be classified. Defaults to safe passthrough.

This routing ensures that threat checks run on any operation that could introduce new code to the system (`INSTALL`, `UPDATE`, `SYNC`, `EXECUTE`), while read-only and removal operations (`SAFE_PASSTHROUGH`, `REMOVE`, `UNKNOWN`) proceed without checks.

## Phase 3: Threat Check Pipeline

For `INSTALL`, `UPDATE`, `SYNC`, and `EXECUTE` intents, the pipeline runs the pre-install check via `_run_pre_install_with_timeout()`. The check proceeds through the following stages:

1. **Config load** — Reads the current application configuration.
2. **DB freshness check** (`_ensure_db_fresh()`) — Queries the threat database's `feed_state` table for the OSV feed's `last_sync` timestamp. If the database is stale (exceeds `staleness_threshold_hours`), an auto-refresh syncs all enabled threat feeds (OSV, GHSA, Socket, npm advisory, Homebrew, etc.) over the network. If the refresh fails, the pipeline raises `SystemExit(EXIT_DB_ERROR)` — this is a blocking step before any other check runs.
3. **Protection warning** (`_check_protection_warning()`) — Checks if pkgd protection is enabled in config. Warns if protection is disabled.
4. **Version resolution** (`_resolve_latest_versions_async()`) — For packages without an explicit version, queries the registry API (e.g., PyPI, npm) to resolve the latest version. This is a network call.
5. **Timestamp caching** (`_cache_version_timestamps_async()`) — For each package version, queries the registry API for the publish timestamp and stores it in the local `version_timestamps` table for cooldown lookups. Failed resolutions are recorded in the `resolution_attempts` table so that cooldown diagnostics can surface the failure reason (e.g., rate-limited, timeout, not found) instead of a blank "Unknown." This is a network call (best-effort, failures do not block the install).
6. **Source intercepts** — Checks each package's install source:
   - `LOCAL_PATH`: Warns and proceeds to execution (informational only).
   - `VCS`: Warns and requires user confirmation before proceeding.
   - `Registry`: Continues to security checks.
7. **Coverage tier routing** — Reads the adapter's `coverage_tier` attribute to determine which security checks run:
   - **AUDIT** (apt, dnf, yum): Threat database query only. Cooldown check is skipped — these ecosystems lack reliable publish timestamps.
    - **PARTIAL** (bundler, poetry, yarn, pnpm, pipenv, bun, uv, brew): Threat database query AND cooldown check.
   - **FULL** (pip, npm, gem, cargo, composer, conda): Threat database query AND cooldown check (same as PARTIAL structurally).
8. **Threat database query** — `_check_threats()` queries the local SQLite database via `check_packages_batch()`. This is a pure local lookup with zero network I/O. Note: the **dispatcher** queries the database, not the adapter — adapters handle only registry API calls.
9. **Cooldown check** — `_check_cooldown()` compares each package version's publish date against the configured cooldown window (default: 7 days). Versions published within the window are blocked regardless of threat database status.

If a threat is found or the cooldown check fails, the pipeline transitions to block handling. Otherwise, it proceeds to execution handoff.

## Phase 4: Block Handling

### handle_blocked_command

When the pipeline determines that a command should not proceed, `handle_blocked_command()` (`cli/exec.py`) manages the disposition. Behaviour varies by block reason:

| Reason         | Behaviour                                                                | Exit Code           |
| -------------- | ------------------------------------------------------------------------ | ------------------- |
| **THREAT**     | Display threat block with summary. Bypass via `--bypass-threat` flag.    | 4                   |
| **COOLDOWN**   | Display cooldown block with remaining wait time. Offer bypass prompt.    | 3 (if not bypassed) |
| **VCS_SOURCE** | Display VCS source warning. Offer confirmation prompt before proceeding. | 1 (if declined)     |
| **LOCAL_PATH** | Display local path warning. Proceed to execution (informational only).   | —                   |

Block reasons are designed so that only **THREAT** and **COOLDOWN** result in a hard block by default. **VCS_SOURCE** and **LOCAL_PATH** are warnings that the user can confirm through, reflecting their lower risk profile.

## Phase 5: Execution Handoff

### handle_cleared_command

When the pipeline clears a command for execution, `handle_cleared_command()` (in `src/pkg_defender/cli/exec.py`) manages the final handoff. It first checks for display-only modes:

- **`--dry-run`** — Prints what would be executed and returns without running anything.
- **`--json`** — Emits JSON-structured output describing the cleared command.

If neither flag is set (or after JSON output to stderr), `handle_cleared_command()` emits an informational `[PKGD]` message to stderr for non-dangerous (`SAFE_PASSTHROUGH`) commands (e.g., `pkgd brew list`), so users see confirmation that the tool is active. It then calls `exec_cleared_command()` (in `src/pkg_defender/cli/exec.py`), which:

1. Looks up the adapter class via `get_adapter_class_for_manager(parsed.manager)` and instantiates it.
2. The adapter builds the execution argument list via `adapter.build_exec_args(parsed)`.
3. `os.execvp(exec_args[0], exec_args)` replaces the pkgd process with the native package manager.

The Python process ends at the `os.execvp()` call. From the shell's perspective, the package manager runs directly with the same PID, inheriting stdin, stdout, stderr, and terminal state. The package manager's exit code propagates back to the shell as pkgd's exit code.

## Security Properties

| Property                        | Description                                                                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Network at pre-install time** | Threat database auto-refresh, version resolution, and publish timestamp caching all perform network I/O on the pre-install path. The threat database query itself (`_check_threats()`) is a pure local SQLite lookup. |
| **Fail-closed design**          | Critical pipeline failures (DB refresh, threat check, cooldown) block installation. Timestamp caching failures are non-blocking (best-effort).                                                                        |
| **Process replacement**         | No subprocess overhead. Manager inherits terminal state and exit code.                                                                                                                                                |
| **No environment sanitisation** | Current environment is preserved. No `env -i` lockdown.                                                                                                                                                               |
| **No binary verification**      | Inode or SHA256 checks of the package manager binary are not implemented.                                                                                                                                             |

## Flow Example: pkgd pip install requests

1. **Click entry:** `pkgd` is invoked with arguments `pip install requests`.
2. **ManagerGroup:** `get_command("pip")` checks the manager registry. `get_adapter_class_for_manager("pip")` returns `PyPIUnifiedAdapter`, so `make_manager_passthrough_command("pip")` creates a dynamic Click command — pip is not a built-in subcommand but a known package manager.
3. **make_manager_passthrough_command("pip"):** Creates a dynamic Click command with `ignore_unknown_options=True`. The raw arguments `["install", "requests"]` are collected as `manager_args`.
4. **ManagerDispatcher → PyPIUnifiedAdapter.parse(["install", "requests"]):**
   - `split_pkgd_flags()` separates any pkgd-specific flags from manager args.
   - `classify_intent("install")` returns `CommandIntent.INSTALL` — triggers the pre-install check pipeline.
5. **Pre-install check pipeline:**
   - `_ensure_db_fresh()` checks the threat database staleness; may trigger feed sync over the network.
   - `_resolve_latest_versions_async()` queries PyPI's API for the latest version if none specified.
   - `_cache_version_timestamps_async()` queries PyPI's API for the publish timestamp.
   - `_check_threats()` queries the local SQLite threat database for `requests` (~2–5 ms, zero network).
   - `_check_cooldown()` checks the cooldown window (default: 7 days).
   - If all checks pass: `handle_cleared_command()` → `exec_cleared_command()`.
6. **exec_cleared_command → os.execvp:** `PyPIUnifiedAdapter.build_exec_args()` reconstructs the pip command, and `os.execvp("pip", ["pip", "install", "requests"])` replaces the pkgd process. Pip runs natively with the same PID and exit code propagation.

---

[← Back to Documentation](../index.md)
