# Bypass

## Overview

Bypasses allow a blocked package to be installed despite failing cooldown or
threat checks. Every bypass is logged to the audit trail with the user, reason,
package, and timestamp — bypasses are not silent.

Use bypasses when you have manually verified that a package is safe and need to
proceed without waiting for a cooldown window or after a false-positive threat
detection. Bypassing should be the exception, not the default workflow.

## Interactive Bypass

When a cooldown block occurs in an interactive terminal, pkg-defender prompts
you to confirm the bypass:

```console
[PKGD] BLOCKED — axios@1.14.2
[PKGD]   Reason: Cooldown period active
[PKGD]   Published: 2026-03-12 @ 00:00 UTC (source: Registry)
[PKGD]   Age: 0d since release
[PKGD]   Cooldown window: 7 days
[PKGD]   Clears at: 2026-03-19 @ 00:00 UTC (in 7 days)
[PKGD]   Use --bypass-cooldown to bypass cooldown (logged to audit trail, threat checks still run).
[PKGD]   Use --allow-once for a single-use bypass (logged to audit trail, 24h expiry).
[PKGD]   Use --force to bypass permanently (logged to audit trail).
[PKGD] Bypass cooldown and proceed? [y/N]
```

Answer `y` to bypass the cooldown for this single installation. The threat
check still runs — a threat block will not be bypassed by interactive
confirmation alone.

**Note:** The cooldown block display uses a 3-branch structure:
1. **Timestamp resolved** — shows published date, source, and remaining cooldown.
2. **Timestamp resolution failed** — shows the failure reason (e.g., rate-limited, timeout) instead of a published date, and blocks for the full default cooldown window.
3. **No timestamp attempt recorded** — displays "Unknown" for the published date and blocks for the full default cooldown window.

Interactive bypass does **not** work in CI pipelines. Pass the `--ci` flag or
set `PKGD_CI=1` to suppress the prompt and block the installation.
Auto-detected CI environments (e.g., `GITHUB_ACTIONS`, `GITLAB_CI`, `CI=true`)
do **not** automatically suppress the prompt — the `--ci` flag must be
explicitly passed. Use the per-command flags for CI pipelines.

## Per-Command Bypass Flags

These flags are available on `pkgd install` and equivalent commands. They apply
to a single invocation only and are logged to the audit trail.

### `--bypass-cooldown`

Skip only the cooldown check for this installation. Threat detection still
runs and can block the install.

```bash
pkgd pip install requests --bypass-cooldown
```

- **Scope:** Cooldown only
- **Expiry:** None (bypass record stored permanently in database)

### `--bypass-threat`

Skip only the threat check for this installation. The cooldown window is still
enforced.

```bash
pkgd pip install requests --bypass-threat
```

- **Scope:** Threat only
- **Expiry:** None (bypass record stored permanently in database)
- **Cooldown:** Still enforced

### `--allow-once`

Bypass the cooldown for a single installation with an automatic expiry. This is
the recommended alternative to `--force` (a global flag) because the bypass is time-limited.

```bash
# Default: 24-hour expiry
pkgd pip install requests --allow-once

# Custom expiry
pkgd pip install requests --allow-once=6h
```

- **Scope:** Cooldown only
- **Expiry:** Default 24 hours from invocation (configurable, e.g. `--allow-once=6h`)
- **Threat checks:** Still enforced
- **Audit logged:** Yes — reason prefix is `allow_once`

## Global Bypass Flag

### `--force`

Permanently bypass the cooldown for this installation. Unlike the per-command
flags above, `--force` is a **global CLI option** available on all commands
(not just install). The bypass does not expire.

```bash
pkgd pip install requests --force
```

When `--force` is used, pkg-defender prints a tip suggesting `--allow-once`
instead:

```console
[PKGD] Tip: Use --allow-once for a single-use bypass (24h expiry) instead of --force (permanent bypass).
```

- **Scope:** Cooldown only
- **Expiry:** None (permanent)
- **Threat checks:** Still enforced
- **Availability:** All commands (global flag)

## The `bypass` Command

The `pkgd bypass` command creates a permanent bypass record in the database
for a specific package version. Unlike the per-command flags, this bypass
persists across multiple install attempts.

```bash
pkgd bypass axios@1.14.2 --reason "needed for legacy integration"
```

**Note:** The `--reason` flag is **required**. Every bypass must document why
it was necessary.

An optional `--expires` flag sets a time limit on the bypass:

```bash
pkgd bypass lodash@4.17.21 --reason "temporary testing" --expires 24h
```

Specify the package manager with `--manager`:

```bash
pkgd bypass express@4.18.0 --manager npm --reason "temporary testing" --expires 7d
```

### Disabled by Default

The `pkgd bypass` command is **disabled by default** for security reasons.
Attempting to run it without enabling it produces an error:

```console
Error: The `pkgd bypass` command is disabled by configuration.
To enable: set `[bypass]
command_enabled = true` in your config file
or set `PKGD_BYPASS_COMMAND_ENABLED=true` in your environment.
```

### Enabling the Command

**Config file (`pkgd.toml`):**

```toml
[bypass]
command_enabled = true
```

**Environment variable:**

```bash
export PKGD_BYPASS_COMMAND_ENABLED=true
```

## CI/CD Bypass Strategies

In CI pipelines, interactive prompts are never available. Use the per-command
flags instead.

### Bypass Cooldown in CI

```bash
pkgd npm install axios --ci --bypass-cooldown
```

### Bypass Threat in CI

```bash
pkgd npm install axios --ci --bypass-threat
```

### Bypass Both in CI

Chain the flags to skip both checks:

```bash
pkgd npm install axios --ci --bypass-cooldown --bypass-threat
```

Bypasses in CI are logged to the audit trail with source=`"cli"` (the same
default source used for all CLI-originated actions). There is no separate
`ci` source tag — pipeline bypasses and interactive ones share the same
source identifier.

## Config-Level Controls

These settings affect how bypasses work across the entire system.

| Setting                          | Default | Description                                                                                        |
| -------------------------------- | ------- | -------------------------------------------------------------------------------------------------- |
| `cooldown.strict_mode`           | `true`  | When `true`, security posture assessment flags weakened settings (does NOT control bypass prompts) |
| `cooldown.bypass_require_reason` | `true`  | Reserved for future use (field exists in config but is not currently enforced)                     |
| `cooldown.enabled`               | `true`  | Set to `false` to disable cooldown checking entirely                                               |
| `fail_on_threat_enabled`         | `true`  | When `true`, threat detection causes installation to fail                                          |
| `bypass.command_enabled`         | `false` | When `true`, the `pkgd bypass` CLI command is available                                            |

### Disabling Cooldown Checking

For development environments where cooldown enforcement is not needed:

```toml
[cooldown]
enabled = false
```

Setting `cooldown.enabled = false` disables cooldown checking entirely — all
packages are allowed through regardless of their release date. This is useful
for development environments where cooldown periods are not a concern.

### Disabling Strict Mode

Controls security posture assessment in `pkgd health` and `pkgd audit`:

```toml
[cooldown]
strict_mode = false
```

When set to `false`:
- `pkgd health` reports "Cooldown strict mode is disabled" as a weakened setting
- `pkgd audit` may still detect and display threats (the exit-code check is independent via `fail_on_threat_enabled`)
- The interactive bypass prompt is **not** affected (controlled by `--ci` flag)

### Disabling Fail-on-Threat

Prevent threat detection from blocking installation. Warnings are still shown:

```toml
fail_on_threat_enabled = false
```

## Audit Trail

Every bypass — whether from interactive prompt, per-command flag, or the
`pkgd bypass` command — is logged to the audit trail.

### Query Audit Events

```bash
# List recent audit events
pkgd audit-logs query

# Filter by ecosystem
pkgd audit-logs query --ecosystem npm

# Filter by verdict
pkgd audit-logs query --verdict BLOCKED

# Filter by date range
pkgd audit-logs query --since 2026-01-01

# Limit results
pkgd audit-logs query -l 50
```

### Check Bypass Statistics

```bash
pkgd audit-logs stats
```

The audit trail captures the user, package, version, reason, expiry (if set),
source (cli, shell_hook, api, cron, test), and timestamp for every bypass
event. Use these commands to verify that bypasses are being used appropriately
and to identify any that may need review.
