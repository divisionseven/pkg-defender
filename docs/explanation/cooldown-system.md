# Cooldown System

The cooldown system enforces a configurable waiting period between package publication and installation, giving security researchers time to discover and report malicious packages.

## How It Works

When you attempt to install a package, `pkgd` checks:

1. **Is cooldown enabled?** — If `cooldown.enabled = false`, the check is skipped.
2. **How old is this version?** — The package's publication date is compared against the current time.
3. **Is it past the cooldown window?** — If the version is newer than `cooldown.default_days`, installation is blocked.

```
Package published ──────[ cooldown window ]──────> Install allowed
                          (default: 7 days)
```

### Trust-Based Penalty

The cooldown window also adjusts based on the **reliability of the timestamp source**. Each timestamp source is classified into one of four trust levels via the `SOURCE_TRUST_MAP` (defined in `db/schema.py`):

| Trust Level  | Sources                                                                        | Cooldown Effect |
| ------------ | ------------------------------------------------------------------------------ | --------------- |
| **Verified** | Native registry APIs (PyPI, npm, RubyGems, Cargo, APT), Bodhi, Debian snapshot | No penalty      |
| **Proxied**  | Koji build system, YUM/DNF repodata                                            | No penalty      |
| **Claimed**  | Packagist, GitHub Releases, GitHub Tags, Libraries.io, user-manual fallback    | **+2 days**     |
| **Unknown**  | Programmatic cache (no source attribution)                                     | No penalty      |

When a timestamp comes from a **claimed** source (maintainer-reported metadata, third-party aggregator, or fallback), a +2 day penalty is added to the cooldown window. This is displayed in cooldown block messages:

```
[PKGD] Cooldown period: 5 days.
[PKGD] Published: 2026-06-01 @ 12:00 UTC (source: GitHub Tags)
[PKGD] Maintainer-claimed timestamp - +2 day cooldown penalty applied
```

The penalty is applied after any `--cooldown <hours>` CLI override but before threat-context signal escalation, so user overrides can still reduce the window but threat escalation can still extend beyond it.

### Resolution Failure Diagnostics

When a timestamp lookup fails (rate limiting, timeout, network error, etc.), the failure is recorded in the `resolution_attempts` table with a `resolution_status` such as `rate_limited`, `timeout`, `network_error`, `not_found`, or `server_error`. This table shares the same composite primary key `(ecosystem, package_name, version)` as `version_timestamps`.

During cooldown checks, `_build_release_date_map()` first queries `version_timestamps` for successful resolutions, then queries `resolution_attempts` for any packages not found there. Packages found only in `resolution_attempts` with a failure status are mapped to `None` with the failure status as the source label — enabling the cooldown layer to display diagnostic information (e.g., "timestamp resolution failed: rate_limited") instead of a blank "Unknown."

### Audit Path Difference

When `pkgd audit` encounters a package whose publish time cannot be resolved (e.g.,
registry outage, network failure, cache miss), it **skips the cooldown check and
treats the package as passed** (fail-open). A warning is logged to stderr:

```
WARNING  pkg_defender.core.auditor:auditor.py:247
  Cooldown: publish time not available for npm some-pkg@1.0.0 — cooldown check skipped (fail-open)
```

This differs from the **install path** (`pkgd <manager> install`), which is
**fail-closed**: when a timestamp cannot be resolved, the install is blocked
regardless of cooldown configuration.

**The audit is a non-blocking scan** — it reports findings but does not gate
operations. The fail-open behavior prevents a transient registry outage from
producing a false-positive cooldown block in audit output. The install path
remains the authoritative gate for cooldown enforcement.

### Signal-Based Escalation

The cooldown window automatically adjusts based on threat intelligence signals detected during the threat-check phase:

- **Verified advisory (CVE, OSV, GHSA):** The package is **blocked indefinitely** — cooldown never expires (`return False, window` regardless of age, see the `has_verified_advisory` check in `step_check_cooldown()`). Only a manual bypass (`pkgd bypass`) can override this.
- **Tier 3 signals (social media mentions):** The cooldown window is extended to a **minimum of 5 days** (see the `has_tier3_signals` check in `step_check_cooldown()`). If the ecosystem default is already ≥5 days (e.g., npm: 7 days), the default is preserved.

This means a package may be blocked for much longer than `cooldown.default_days` when threat signals are present.

### Per-Ecosystem Defaults

The recommended cooldown window varies by package ecosystem. Configure it via `[cooldown.per_ecosystem]` in your `pkgd.toml`:

| Ecosystem                                                         | Recommended Window                      |
| ----------------------------------------------------------------- | --------------------------------------- |
| npm, pnpm, yarn, bun                                              | 7 days                                  |
| pip, pypi, poetry, pipenv, pipx, uv                               | 5 days                                  |
| brew, homebrew                                                    | 2 days                                  |
| bundler, cargo, composer, conda, crates, gem, packagist, rubygems | 3 days                                  |
| Other (apt, dnf, yum, etc.)                                       | `default_days` from config (default: 7) |

> **Note:** These values are **recommendations** — If `[cooldown.per_ecosystem]` is not configured, all ecosystems use `cooldown.default_days` (current default: 7).

## Configuration

```toml
[cooldown]
enabled = true                  # Whether cooldown checking is active
default_days = 7                # Days a new version must age before install
strict_mode = true              # If true, audit exits non-zero on threats
bypass_require_reason = true    # Whether bypass requires a reason
bypass_log_retention_days = 90  # Days to retain bypass log entries

[cooldown.overrides]
# "package-name" = days   (per-package cooldown override)

[cooldown.per_ecosystem]
# "ecosystem" = days      (per-ecosystem default override)
```

### strict_mode

`strict_mode` controls how `pkgd audit` exits when threats are found — it does **not** affect cooldown bypass prompting.

- **`strict_mode = true` (default):** `pkgd audit` exits with a non-zero exit code when threats are found.
- **`strict_mode = false`:** `pkgd audit` exits zero even when threats are found (weakened posture).

The cooldown bypass prompt during `pkgd <manager> install` is controlled by the `--ci` / `--non-interactive` flag instead. When `--ci` is set, the prompt is suppressed and blocked packages are silently rejected.

> **Note:** If you want to disable the interactive bypass prompt, pass `--ci` or set `PKGD_CI=1` in your environment.

## Bypass System

### Creating a Bypass

```bash
pkgd bypass lodash@4.17.21 --reason "audit complete"
```

A bypass always requires a reason (the `--reason` flag is mandatory). The reason is logged in the audit trail.

### Temporary Bypass

```bash
pkgd bypass axios@1.6.0 --reason "testing" --expires 24h
```

Expiry formats:
- `Nd` — days (e.g., `7d`)
- `Nh` — hours (e.g., `24h`)
- `Nm` — minutes (e.g., `30m`)

### Permanent Bypass

```bash
pkgd bypass pkg@2.0.0 --reason "permanent exception"
```

Omitting `--expires` creates a bypass that never expires.

### Per-Package Cooldown Overrides

You can set custom cooldown periods for specific packages:

```bash
pkgd config set cooldown.overrides.lodash 3
```

This sets lodash's cooldown to 3 days instead of the default.

### Per-Command Cooldown Override

You can also override the cooldown window for a single command without persisting a config change:

```bash
pkgd pip install requests@2.31.0 --cooldown 48
```

The `--cooldown` flag accepts a value in **hours** (not days). It applies to all packages in the command. The minimum effective window is 1 day (24 hours), rounded up from the hours value (see `step_check_cooldown()` override handling).

### Bypass Lifecycle

1. **Create** — `pkgd bypass <package@version> --reason <text> [--expires <duration>]`
2. **Active** — Package installs proceed while bypass is active
3. **Expire** — Bypass expires after the set duration (or never, if no expiry)
4. **Audit trail** — All bypasses are logged with reason, creator, and timestamps

## Interaction with Threat Checks

Cooldown and threat checks are independent gates evaluated in sequence:

1. **Threat check runs first** — If blocked, the install stops here. Use `--bypass-threat` to bypass (logged to audit trail, cooldown still enforced).
2. **Cooldown check runs second** — If blocked, use `--bypass-cooldown`, `--allow-once`, `--force`, or answer the interactive prompt to bypass (all logged to audit trail).
3. **Both block separately** — Each gate needs its own bypass. `--bypass-threat` handles threats; `--bypass-cooldown`/`--allow-once`/`--force` handle cooldown.

| Bypass Method           | Bypasses Threat | Bypasses Cooldown | Persists to DB |
| ----------------------- | --------------- | ----------------- | -------------- |
| `--bypass-threat`       | ✅               | ❌                 | ✅              |
| `--bypass-cooldown`     | ❌               | ✅                 | ✅              |
| `--allow-once`          | ❌               | ✅ (24h)           | ✅              |
| `--force`               | ❌               | ✅ (permanent)     | ✅              |
| `pkgd bypass <pkg@ver>` | ✅               | ✅                 | ✅              |

## Using `--force` / `--allow-once` with Package Installs

When cooldown blocks an install, you can bypass it inline. All bypass methods are logged to the persistent bypass audit trail:

```bash
# --bypass-cooldown bypasses cooldown (logged to audit trail, threat checks still run)
pkgd pip install badpkg@1.0.0 --bypass-cooldown

# --allow-once bypasses cooldown with a 24h expiry (safer)
pkgd pip install badpkg@1.0.0 --allow-once

# --allow-once accepts custom durations
pkgd pip install badpkg@1.0.0 --allow-once=6h

# --force bypasses cooldown permanently (logged to audit trail)
pkgd pip install badpkg@1.0.0 --force
```

Both flags work as **postfix** (after the manager command) or **prefix** (before the manager command):

```bash
# Postfix
pkgd pip install badpkg@1.0.0 --force

# Prefix
pkgd --force pip install badpkg@1.0.0
```

> **Note:** `--allow-once` takes priority over `--force` when both are set. Use `--bypass-cooldown` to bypass cooldown only, or `--bypass-threat` to bypass threat blocks only (cooldown still enforced). Both are logged to the audit trail.

---

[← Back to Documentation](../index.md)
