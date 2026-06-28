# Architecture

The architecture of pkg-defender is organized around strict module boundaries, deliberate trade-offs in the execution pipeline, and a security model that prioritises determinism and simplicity at install time.

## Module Boundaries

The source tree is organized into distinct domains with explicit dependency direction:

```
cli/ ──▶ core/ ──▶ models/
  │        │
  │        ├──▶ db/
  │        ├──▶ config/
  │        └──▶ audit/
  │
  ├──▶ intel/ ──▶ db/
  │        │
  │        ├──▶ config/
  │        └──▶ display.py
  │
  ├──▶ audit/
  ├──▶ shells/
  ├──▶ db/
  ├──▶ config/
  ├──▶ display.py
  ├──▶ registry/
  ├──▶ cli/commands/
  └──▶ daemon/
```

**The `core/` module never imports from `registry/` or `intel/`.** This is the central architectural rule. Core modules are pure logic — they accept data via parameters and return results. They have no awareness of where data originates or where it is stored. This constraint serves two purposes:

- **Testability:** Core logic can be tested without database connections, registry lookups, or network dependencies. Tests pass data in and assert on results out, with no setup or teardown of external systems.
- **Separation of concerns:** The threat checker (`core/checker.py`) does not know whether threats came from OSV, GHSA, or a Mastodon feed. The scorer (`core/scorer.py`) applies pre-defined confidence weights from module-level constants (`scorer.py:15-26`), and neither module depends on the registry or database layer. Each module has one reason to change.

Modules that require I/O — database queries, registry API calls, feed synchronisation — live in `db/`, `registry/`, and `intel/` respectively. They import from `models/` and are consumed by `core/`, never the reverse. This one-way dependency chain means the core can be reasoned about in isolation.

## Key Design Decisions

### Pre-Install Check as Pure Local Lookup

The critical path — the check that runs before every package install — uses only local SQLite lookups with zero network I/O. This guarantees fast response times (typically 2–5 ms) regardless of whether external threat feeds are reachable. If a feed synchronisation fails, the threat database still contains its last-known-good state, so install-time checks never depend on network availability.

### SQLite WAL Mode

SQLite runs in Write-Ahead Logging (WAL) mode with a 5-second busy timeout. WAL mode allows concurrent readers without blocking writers, which is essential because multiple `pkgd` processes may access the database simultaneously — for example, during parallel installs in CI. The 5-second busy timeout prevents deadlocks when contention occurs.

### Threat Scoring

Threat scores combine three factors:

- **Source confidence weights** — Structured databases and feeds (OSV: 0.9, GHSA: 0.85, Socket: 0.95, npm_advisory: 0.8, ossf_malicious: 1.0, homebrew_osv: 0.9, RSS: 0.5) are weighted higher than social feeds (Mastodon: 0.4, Reddit: 0.45, X/Twitter: 0.5). Social feed confidence is capped at `min(confidence, 0.2)` at runtime — see `scorer.py:126-128` — ensuring they cannot trigger an automatic block on their own.
- **Multi-source corroboration** — A threat reported by multiple sources receives a score multiplier (2 sources: 1.15×, 3 sources: 1.25×, 4+ sources: 1.3×).
- **Recency decay** — Scores decrease by 5 % per week, with a floor of 50 % of the original score. Older threats are considered less relevant.

### Block Score Threshold of 0.3

The block threshold (`BLOCK_SCORE_THRESHOLD = 0.3`) is calibrated so that only structured threat databases can trigger an automatic block. Social feeds, even at maximum severity, cannot reach this threshold: a LOW severity report (0.3) from a social source evaluates to 0.3 × min(0.5, 0.2) = 0.06. Even a CRITICAL severity (1.0) would only reach 1.0 × 0.2 = 0.20 — still below the threshold. This prevents noise from social channels causing false-positive blocks while still allowing those reports to influence the aggregate score when corroborated by structured sources.

### Strict Mode Default

Two separate configuration options control bypass behaviour:

- **`cooldown.strict_mode`** (default: `true`) — When enabled, bypass prompts are suppressed during cooldown and threat-block events. Users must explicitly pass `--force` or `--bypass-cooldown` flags rather than being asked interactively.
- **`bypass.command_enabled`** (default: `false`) — Controls whether the `pkgd bypass` CLI command is available for creating persistent bypass entries. Disabled by default — admins must explicitly opt in.

Both default to a paranoid posture. Opting out of either requires a deliberate configuration change.

## Security Architecture Rationale

### Process Replacement via os.execvp()

After threat checks pass, pkgd replaces its own process with the native package manager using `os.execvp()`. This is a deliberate choice:

- **Not subprocess.Popen()** — A subprocess would leave the Python process alive, consuming memory and creating a parent-child relationship that can interfere with signal handling and terminal state.
- **Process replacement** — The Python process ends, and the package manager runs directly, inheriting stdin, stdout, stderr, and the terminal session. The package manager's exit code becomes pkgd's exit code.
- **No environment sanitisation** — The current environment is preserved. The removed shell hook architecture had planned `env -i` lockdown, but the command wrapper architecture does not modify environment variables.

### Fail-Closed Design

Any pkgd failure — a database error, a parsing failure, an unexpected exception — blocks the installation. The system does not degrade open: if pkgd cannot determine whether a package is safe, the default answer is to block. This is the conservative choice for a security tool, trading availability for safety.

### Security Boundaries

The interception mechanism enforces three security boundaries:

1. **UNIFIED_MANAGER_REGISTRY lookup (Boundary 1)** — The dispatcher queries the registry for an adapter class that handles the given manager name. If no adapter is registered, the command is rejected. This prevents execution of unsupported or unregistered commands.

2. **Local threat database check (Boundary 2)** — Before every installation, the adapter queries the local SQLite database for known threats and checks the cooldown window. If threats are found, installation is blocked immediately.

3. **Process handoff via os.execvp() (Boundary 3)** — After checks pass, `os.execvp()` replaces the pkgd process with the native package manager. There is no subprocess layer between pkgd and the manager.

A detailed walkthrough of how these boundaries interact during a command invocation can be found in [Interception Lifecycle](interception-lifecycle.md).

## Deliberate Exclusions

The following security features were planned for an earlier shell hook architecture that was removed before the v1.0 release:

- **Binary integrity verification** — Inode checking and SHA256 hash verification of the package manager binary were part of the removed shell hook design. The current command wrapper architecture does not verify binary integrity.
- **Environment lockdown** — The removed architecture planned `env -i` sanitisation to strip the environment. The current architecture preserves the user's environment unchanged.
- **Shell function hooks** — Modifications to `.bashrc`, `.zshrc`, and other shell RC files were removed before release. The current architecture uses a Click-based CLI group (`pkgd <manager> <command>`) that requires no shell configuration.
- **Secure audit logging** — Integration with syslog or journald for user-inaccessible audit trails was planned but not implemented.

The current architecture relies on Click's argument parsing, local SQLite threat queries with zero network I/O at install time, and a fail-closed design that blocks on any error.

---

[← Back to Documentation](../index.md)
