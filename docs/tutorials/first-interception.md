# Your First Interception

This tutorial walks through the experience of having a package installation intercepted by pkg-defender. By the end, the reader will have encountered both a cooldown block and a threat block, inspected system status, created a bypass, verified system health, and cleaned up.

**Prerequisite:** Complete the [Getting Started](getting-started.md) tutorial before starting this one. The reader should have `pkgd` installed, set up, and synced with at least one threat intelligence feed.

---

## Step 1: Trigger a Cooldown Block

pkg-defender enforces a cooldown window on recently published packages. By default, a package version must be at least 7 days old before it can be installed.

Try installing a package that was published very recently:

```bash
pkgd pip install newpkg@1.0.0
```

**Example output:**

```console
[PKGD] BLOCKED — newpkg@1.0.0
[PKGD]   Reason: Cooldown period active
[PKGD]   Published: 2026-06-03 @ 12:00 UTC (source: Registry)
[PKGD]   Age: 0d since release
[PKGD]   Cooldown window: 7 days
[PKGD]   Clears at: 2026-06-10 @ 12:00 UTC (in 7 days)
[PKGD]   Use --bypass-cooldown to bypass cooldown (logged to audit trail, threat checks still run).
[PKGD]   Use --allow-once for a single-use bypass (logged to audit trail, 24h expiry).
[PKGD]   Use --force to bypass permanently (logged to audit trail).
[PKGD] Bypass cooldown and proceed? [y/N]
```

**What happened:**

- The adapter resolved `pip install newpkg@1.0.0` as an INSTALL intent and ran the pre-install check pipeline.
- The cooldown check compared the package's publication date against the configured `cooldown.default_days` (default: 7 days).
- Because the package was published only 6 hours ago, it fell within the cooldown window and was blocked.
- The final line is a prompt; pressing `n` or `Ctrl-C` exits with code **3** (`EXIT_COOLDOWN`), defined in `pkg_defender/cli/_exit_codes.py`. Pressing `y` creates a bypass entry and proceeds with the installation.
- Output lines are written to stderr with `[PKGD]` prefixes — no Rich panels or borders are used.

*The exact output depends on the package and version. The age and remaining time will differ.*

---

## Step 2: Inspect the Audit Log

After observing a cooldown block, check the audit trail to confirm the event was recorded:

```bash
pkgd audit-logs query --ecosystem pypi
```

**Example output:**

The command displays a table of audit events filtered by ecosystem, with columns for timestamp, ecosystem, package, verdict, exit code, source, and runtime:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Timestamp         Ecosystem  Package  Verdict   Exit  Source    Runtime (ms) │
├──────────────────────────────────────────────────────────────────────────────┤
│ 2026-06-03T12:00  pypi       newpkg   BLOCKED   1     cli       47           │
└──────────────────────────────────────────────────────────────────────────────┘
```

**What happened:**

- The `audit-logs query` command queried the local threat database's audit events table.
- Each intercepted command produces an audit record containing the timestamp, ecosystem, package name, verdict, exit code, source, and runtime in milliseconds.
- The cooldown block from Step 1 appears as a `BLOCKED` verdict with exit code 1. (The process exit code is 3 — `EXIT_COOLDOWN` — but the audit log stores the dispatcher's internal exit code of 1.)
- The command exited with code **0** (`EXIT_SUCCESS`).

*The exact timestamp, duration, and event count will differ based on when the command was run.*

---

## Step 3: Check System Status

After observing a cooldown block and inspecting the audit trail, review the overall system state:

```bash
pkgd status
```

**Example output:**

The status dashboard displays three sections:

1. **Threat Count by Severity** — a breakdown of known threats in the database by severity level (CRITICAL, HIGH, MEDIUM, LOW)
2. **Active Bypasses** — packages that have been allowed through despite cooldown or threat checks (initially empty)
3. **Intelligence Feed Health** — per-feed status showing whether each feed is configured, when it last synced, and its current state

The status command confirms the threat database is synced and the system is working. No bypasses exist yet — that changes in the next step.

---

## Step 4: Bypass the Cooldown

When a legitimate package is blocked by the cooldown gate, a bypass entry can be created. All bypasses require a reason and are logged to the audit trail.

```bash
pkgd bypass newpkg@1.0.0 --manager pip --reason "testing in isolated environment"
```

**Example output:**

```console
Bypass created for newpkg@1.0.0
  Reason:  testing in isolated environment
  Ecosystem: pip
  Expires: never
```

**What happened:**

- The `bypass` command inserted a record into the `bypasses` table of the local threat database.
- The bypass is permanent by default (no `--expires` flag). To create a time-limited bypass, add `--expires 24h`.
- The command exited with code **0** (`EXIT_SUCCESS`).

Once the bypass exists, subsequent installation attempts will check the bypass table before blocking — if a matching bypass is found, the cooldown check is skipped.

Verify the bypass appears in the system status:

```bash
pkgd status
```

The "Active Bypasses" table now lists the newly created entry with the package name, version, reason, and expiry (or "never").

> **Note:** Bypasses created with `pkgd bypass` skip **all** safety checks — the bypass record stores `checks_performed="none"`, so both cooldown and threat checks are skipped for matching packages. For a single-use cooldown bypass during installation that still runs threat checks, use `--allow-once` instead:
>
> ```bash
> pkgd pip install newpkg@1.0.0 --allow-once
> ```

---

## Step 5: Trigger a Threat Block

Now try installing a package that has a known vulnerability in the threat database.

```bash
pkgd pip install known-vulnerable-pkg@2.0.0
```

**Example output:**

```console
[PKGD] BLOCKED — known-vulnerable-pkg@2.0.0
[PKGD]   Reason: Known security threat detected
[PKGD]   This package has known security vulnerabilities.
[PKGD]   Run 'pkgd intel search known-vulnerable-pkg' for details.
[PKGD]   Use --bypass-threat to bypass (logged to audit trail).
```

**What happened:**

- The adapter resolved the install intent and ran the full threat check pipeline.
- The threat database was queried locally (no network I/O on the critical path) and returned matching records.
- The block message is displayed as `[PKGD]`-prefixed text lines to stderr — no Rich table or panel is used.
- Unlike cooldown blocks, threat blocks cannot be bypassed interactively. They require the `--bypass-threat` flag to override.
- The suggested `pkgd intel search` command queries the local database for detailed vulnerability information.
- The command exited with code **4** (`EXIT_THREAT_DETECTED`).

*The specific package, version, and threat details will vary depending on the configured intelligence feeds and their data.*

---

## Step 6: Search the Threat Database

After observing a threat block, search the local threat database to learn more about the vulnerable package:

```bash
pkgd intel search known-vulnerable-pkg
```

**Example output:**

The command displays a Rich table of matching threats with columns for ID, ecosystem, package name, severity, source, and first seen date:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                 Threats matching 'known-vulnerable-pkg'                 │
├────────┬───────────┬──────────────────────┬──────────┬────────┬─────────┤
│ ID     │ Ecosystem │ Package              │ Severity │ Source │ First   │
│        │           │                      │          │        │ Seen    │
├────────┼───────────┼──────────────────────┼──────────┼────────┼─────────┤
│ 1      │ pypi      │ known-vulnerable-pkg │ CRITICAL │ osv    │ 2026-05 │
│ 2      │ pypi      │ known-vulnerable-pkg │ HIGH     │ ghsa   │ 2026-05 │
├────────┼───────────┼──────────────────────┼──────────┼────────┼─────────┤
```

**What happened:**

- The `intel search` command queried the local threat database for records matching the package name.
- Results are ordered by severity (CRITICAL first) and then by first seen date.
- The CRITICAL severity row is displayed in red, HIGH in red (via Rich styling).
- Each result shows the threat ID, ecosystem, package name, severity, advisory source, and first seen date.
- The search does not perform any network I/O — it reads exclusively from the local database.
- The command exited with code **0** (`EXIT_SUCCESS`).

*The specific number of threats, IDs, and dates will vary based on the configured intelligence feeds and their data.*

---

## Step 7: Verify System Health

After observing both block types and inspecting threat data, run a system health check:

```bash
pkgd health
```

**Example output:**

The health command produces several Rich tables. The first table covers core system checks:

```
┌───────────────────────────────── [i]System Health[/i] ─────────────────────────────────────┐
│ Check            Status      Details                                                       │
├────────────────────────────────────────────────────────────────────────────────────────────┤
│ Config file      OK          /Users/user/Library/Application Support/pkg-defender/pkgd.toml│
│ Database         OK          /Users/user/Library/Application Support/pkg-defender/...      │
│ WAL mode         OK          wal                                                           │
│ OSV feed         OK          last synced: 2026-06-03T10:00:00                              │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

Additional tables follow for **Intelligence Feed Health** (per-feed configured status, last sync, and state), **API Token Status** (validation of GHSA, Socket.dev, and X/Twitter tokens), **Disk Space**, and **File Permissions**.

The health command runs comprehensive diagnostics covering:

1. **Config file** — validates the TOML configuration file exists
2. **Database** — confirms the threat database is present and reachable
3. **WAL mode** — verifies SQLite Write-Ahead Logging is active
4. **OSV feed** — checks the primary OSV feed has synced at least once
5. **Intelligence feeds** — per-feed health (configured, last sync, status) in a separate table
6. **API tokens** — validates GHSA, Socket.dev, and X/Twitter tokens in a separate table
7. **Disk space** — verifies sufficient free space at the data directory
8. **File permissions** — confirms read/write access to config and database files

For more detail, add `--verbose`:

```bash
pkgd health --verbose
```

The health command exits with code **0** when all checks pass, or code **1** if any check fails.

---

## Step 8: Clean Up

To remove all threat data and reset to a fresh state:

```bash
pkgd reset
```

This deletes the threat database (including bypass records and feed state), but preserves the configuration file. The command prompts for confirmation before proceeding.

To also remove the configuration file:

```bash
pkgd reset --teardown
```

After a reset, run `pkgd setup` and `pkgd intel sync` to restore the system to a working state.

---

## Summary

| Step            | Command                                   | Exit Code                  | Trigger                                                    |
| --------------- | ----------------------------------------- | -------------------------- | ---------------------------------------------------------- |
| Cooldown block  | `pkgd pip install <recent-pkg>`           | 3 (`EXIT_COOLDOWN`)        | Package published within the default 7-day cooldown window |
| Audit log check | `pkgd audit-logs query --ecosystem pypi`  | 0 (`EXIT_SUCCESS`)         | Cooldown block recorded in audit trail                     |
| System status   | `pkgd status`                             | 0 (`EXIT_SUCCESS`)         | Shows threat counts, active bypasses, and feed health      |
| Create bypass   | `pkgd bypass <pkg>@<ver> --reason <text>` | 0 (`EXIT_SUCCESS`)         | Cooldown bypass entry created                              |
| Threat block    | `pkgd pip install <vulnerable-pkg>`       | 4 (`EXIT_THREAT_DETECTED`) | Known vulnerability matched in the threat database         |
| Intel search    | `pkgd intel search <pkg>`                 | 0 (`EXIT_SUCCESS`)         | Threat database query                                      |
| Health check    | `pkgd health`                             | 0 or 1                     | System diagnostics (pass/fail)                             |
| Full reset      | `pkgd reset`                              | 0 (`EXIT_SUCCESS`)         | Threat data removed                                        |

---

## Next Steps

- **[Command Wrappers Guide](../guides/command-wrappers.md)** — How wrappers intercept installs, supported shells, and troubleshooting
- **[Cooldown System Guide](../explanation/cooldown-system.md)** — Configure cooldown windows, bypass behaviour, and strict mode
- **[Threat Feeds Guide](../reference/threat-feeds.md)** — Manage intelligence feed sources, sync schedules, and authentication
- **[Configuration Reference](../reference/configuration.md)** — All configuration options with defaults and environment variable overrides
- **[Full CLI Reference](../reference/cli.md)** — Complete command reference with options and exit codes
