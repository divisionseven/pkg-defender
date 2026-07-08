# Troubleshooting Guide

This guide covers all troubleshooting scenarios for pkg-defender, organized by category. Each section includes symptoms, causes, solutions, and prevention tips.

## Quick Reference

For a complete error catalog, see [Error Messages Reference](../reference/error-messages.md).

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Package Blocking Issues](#package-blocking-issues)
3. [Security Blocking](#security-blocking)
4. [Cooldown System Issues](#cooldown-system-issues)
5. [Threat Detection Issues](#threat-detection-issues)
6. [Manager Detection Issues](#manager-detection-issues)
7. [Database Issues](#database-issues)
8. [Feed/Intel Issues](#feedintel-issues)
9. [Daemon Issues](#daemon-issues)
10. [Performance Issues](#performance-issues)
11. [General Debugging](#general-debugging)
12. [Recovery Procedures](#recovery-procedures)

---

## Installation Issues

### pkgd: command not found

**Symptom:**
```console
$ pkgd --version
pkgd: command not found
```

**Cause:** The package wasn't installed properly, or the installation directory isn't in your PATH.

**Solution:**

```bash
# Option 1: Reinstall with uv
uv pip install pkg-defender

# Option 2: Use a virtual environment
python -m venv ~/.venvs/pkgd
source ~/.venvs/pkgd/bin/activate
uv pip install pkg-defender

# Option 3: Install from source
git clone https://github.com/divisionseven/pkg-defender
cd pkg-defender
uv pip install -e .

# Option 4: Check your PATH
echo $PATH | tr ':' '\n' | grep -E "(local|bin)"
```

**Prevention:** Use a virtual environment or Homebrew on macOS to avoid PATH conflicts.

---

### Permission Denied Errors

**Symptom:**
```console
PermissionError: [Errno 13] Permission denied
```

**Cause:** Installing to system directories without root access, or file permission issues.

**Solution:**

```bash
# Use user installation
uv pip install --user pkg-defender

# Or use a virtual environment
python -m venv ~/venv
source ~/venv/bin/activate
uv pip install pkg-defender
```

**Prevention:** Prefer virtual environments over system-wide installations.

---

### Wrong Python Version

**Symptom:**
```console
ERROR: Package 'pkg-defender' requires a different Python: 3.9.18 not in '>=3.11'
```

**Cause:** Multiple Python versions installed, and the wrong one is being used.

**Solution:**

```bash
# Check Python versions available
python3 --version
python3.11 --version
python3.12 --version

# Use explicit Python version
uv pip install --python 3.11 pkg-defender

# On macOS with Homebrew Python
brew install python@3.11
/usr/local/opt/python@3.11/bin/python3 -m venv ~/.venvs/pkgd
source ~/.venvs/pkgd/bin/activate
uv pip install pkg-defender
```

**Prevention:** Set up a managed Python environment with pyenv or similar tools.

---

### Installation Verification Failed

**Symptom:**
```console
$ pkgd --version
pkgd: command not found
```

**Cause:** Installation appeared to succeed but the command isn't accessible.

**Solution:**

```bash
# Check if package is installed
pip show pkg-defender

# Find where it was installed
pip show pkg-defender | grep Location
which python3
python3 -c "import pkg_defender; print(pkg_defender.__file__)"

# Try running directly
python3 -m pkg_defender.cli.main --version

# Check .local/bin is in PATH
echo $PATH | tr ':' '\n' | head -5
ls -la ~/.local/bin/pkgd 2>/dev/null || echo "Not in ~/.local/bin"
```

**Prevention:** Verify PATH includes the Python scripts directory after installation.

---

## Package Blocking Issues

### Package Blocked by Cooldown

**Symptom:**
```console
Cooldown: axios@1.7.0 is too new (less than 7 day(s) old).
```

**Cause:** The package version is newer than the configured cooldown period.

**Solution:**

```bash
# Check why it was blocked
pkgd npm install axios@1.7.0 --dry-run

# Option 1: Wait for cooldown to expire
# Check cooldown status
pkgd status

# Option 2: Create a bypass with reason
pkgd bypass axios@1.7.0 --reason "needed for critical bug fix"

# Option 3: Temporary bypass that expires
pkgd bypass axios@1.7.0 --reason "testing new release" --expires 24h
```

**Prevention:** Set appropriate cooldown periods for your workflow. Use `pkgd config set cooldown.default_days 0` to disable cooldown checking if needed for testing.

---

### Package Blocked by Threat

**Symptom:**
```console
THREAT DETECTED: badactor@1.0.0 has CRITICAL severity threat.
```

**Cause:** The package matches known malicious patterns in the threat database.

**Solution:**

```bash
# Check the threat details first
pkgd intel search badactor

# View the full threat report
pkgd intel report

# If you verify it's a false positive:
pkgd bypass badactor@1.0.0 --reason "false positive - verified by security team"

# If it's truly malicious, do NOT install it
# Report the package to the relevant registry (npm, PyPI, etc.)
```

**Prevention:** Always investigate threat blocks before bypassing. Never bypass CRITICAL threats without explicit security review.

---

### Audit Exits Non-Zero on Threat Detection (strict_mode)

**Symptom:**
```console
$ pkgd audit --deep
# Exits with code 4 even though no CRITICAL/HIGH threats were found
```

**Cause:** `cooldown.strict_mode = true` causes `pkgd audit` to exit non-zero when
any threat (even LOW/MEDIUM severity) is found during cooldown enforcement.

`strict_mode` does **not** control bypass prompts. Interactive bypass prompts
are skipped when CI mode is active (`--ci` flag, `PKGD_CI` env var, or
auto-detected CI environment).

**Solution:**

```bash
# Check current strict_mode setting
pkgd config get cooldown.strict_mode

# Disable strict_mode to allow audit to pass with LOW/MEDIUM threats
pkgd config set cooldown.strict_mode false

# To restore strict enforcement
pkgd config set cooldown.strict_mode true
```

**Prevention:** Keep `strict_mode = true` in production audits for full security
coverage. Disable only when LOW/MEDIUM threat findings are acceptable.

---

### Bypass Not Working

**Symptom:**
```console
$ pkgd bypass axios@1.7.0 --reason "test"
Error: The `pkgd bypass` command is disabled by configuration.
```

**Cause:** The bypass command is disabled by default (`bypass.command_enabled = false`).
This is an intentional security measure — bypass must be explicitly opted into.

**Solution:**

```bash
# Enable the bypass command
pkgd config set bypass.command_enabled true

# Or use environment variable:
export PKGD_BYPASS_COMMAND_ENABLED=true

# Now retry the bypass
pkgd bypass axios@1.7.0 --reason "verified safe"

# Verify bypass
pkgd status
```

**Prevention:** Keep `bypass.command_enabled = false` in production environments
to prevent accidental bypasses. Enable only when your workflow requires it.

---

## Security Blocking

### Why am I getting blocked?

Exit code blocking is now enabled. If pkgd returns any non-zero exit code, the installation is blocked. This security hardening prevents packages with failing install scripts from being installed.

### How to allow a blocked package

```bash
# Use pkgd bypass to override security checks
pkgd bypass <pkg> --reason "verified safe - tested in dev"

# Or bypass a specific version
pkgd bypass <pkg>@<ver> --reason "trusted package"
```

### pkgd health diagnostics

Run system health diagnostics:

```bash
# Quick health check
pkgd health

# Detailed diagnostics
pkgd health --verbose
```

The `pkgd health --verbose` command checks:
- Configuration validity
- Adapter coverage matrix (coverage tier per ecosystem)
- Threat counts per adapter
- Feed details and freshness
- Threat database freshness
- Ecosystem support (18 adapters)

### Shell timeout issues

If you see "timeout: command not found":

```bash
# PLEASE check the package for threats first
pkgd intel search coreutils

# macOS: Install GNU coreutils
brew install coreutils

# Then timeout will be available as gtimeout
```

---

## Cooldown System Issues

### Cooldown Not Clearing

```console
$ pkgd pip install axios@1.7.0

[PKGD] BLOCKED — axios@1.7.0
[PKGD]   Reason: Cooldown period active
# (but the package should be old enough now)
```

**Cause:** System clock is wrong, or cooldown calculation is incorrect.

**Solution:**

```bash
# Check your system clock
date

# Check the package's publication date
pkgd pip install axios@1.7.0 --dry-run

# Check cooldown configuration
pkgd config get cooldown

# Verify cooldown is enabled
pkgd config set cooldown.enabled true

# Force recalculation
pkgd reset
pkgd setup
```

**Prevention:** Keep your system clock synchronized with NTP.

---

### Check Cooldown Status

**Symptom:** Need to see when a cooldown will expire.

**Solution:**

```bash
# Check overall cooldown status
pkgd status

# View all active bypasses (shown in status output)
pkgd status

# Check specific package cooldown
pkgd npm install <pkg>@<ver> --dry-run

# View cooldown configuration
pkgd config get cooldown
```

---

### Cooldown Too Long for Development

**Symptom:** New package versions are blocked during rapid development cycles.

**Solution:**

```bash
# Reduce cooldown period for testing
pkgd config set cooldown.default_days 0

# Or disable cooldown entirely for testing
pkgd config set cooldown.enabled false

# Restore for production
pkgd config set cooldown.default_days 7
pkgd config set cooldown.enabled true
```

**Prevention:** Use bypasses for specific packages instead of disabling cooldown globally in production.

---

## Threat Detection Issues

Use `pkgd intel report` to view detailed threat reports for flagged packages.

### Threat Check Timing Out

**Symptom:**
```console
[PKGD] Error: Pre-install check timed out after 30 seconds
```

**Cause:** Feed servers are slow or unreachable, or network connectivity issues.

**Solution:**

```bash
# Check network connectivity
curl -I https://api.osv.dev

# Increase timeout threshold
pkgd config set command_timeout_seconds 60

# Re-sync feeds
pkgd intel sync

# Check feed health
pkgd health
```

**Prevention:** Use a daemon for background sync so feeds are pre-cached.

---

### False Positive Reporting

**Symptom:** Legitimate package is flagged as threatening.

**Solution:**

```bash
# First, verify it's actually a false positive
pkgd intel search <package>

# Check the threat details carefully
# Research the package reputation

# Report to the threat feed (if applicable):
# - OSV: https://github.com/google/osv.dev/issues
# - GHSA: https://github.com/github/advisorydatabase/issues

# Create bypass with clear documentation
pkgd bypass <pkg>@<ver> --reason "false positive - verified by security team, reported to feed maintainers"
```

**Prevention:** Contribute to threat feeds by reporting false positives.

---

### Database Corruption

**Symptom:**
```console
Error: Could not open database: {e}. Run 'pkgd db verify' to check database integrity.
# or
Error: No local database found. Run 'pkgd setup' to initialize your local database.
```

**Cause:** Database file was corrupted by improper shutdown or disk issues.

**Solution:**

```bash
# Check database health
pkgd health

# If corrupted, reset completely
pkgd reset --yes

# Re-sync feeds
pkgd intel sync

# Verify
pkgd health
```

**Prevention:** Ensure proper shutdown of daemon before system sleep. Use `pkgd daemon stop` before closing terminal.

---

### Threat Check Returns No Results

**Symptom:**
```console
$ pkgd npm install <package>

[PKGD] Threat check passed — no known threats for <package>@<version>
# but you expected results
```

**Cause:** Feed not synced, API token invalid, or package truly has no threats.

**Solution:**

```bash
# Check feed status
pkgd health

# Force re-sync
pkgd intel sync

# Check if feeds are configured
pkgd config view | grep -A10 feeds

# Verify API tokens
pkgd setup
```

**Prevention:** Keep feeds synchronized. Use daemon for automatic updates.

---

## Manager Detection Issues

### Auto-Detection Not Working

**Symptom:**
```console
$ pkgd some-manager install express
pkgd: unknown package manager: some-manager
```

**Cause:** No recognized project files found in current directory, or no package managers installed.

**Solution:**

```bash
# Explicitly specify the manager
pkgd npm install express

# Check which managers are available
which npm
which pip
which brew

# Check for project files
ls -la package.json  # npm
ls -la requirements.txt  # pip
ls -la package-lock.json  # npm
```

**Prevention:** Always use explicit manager prefix (e.g., `pkgd npm install`) in CI/CD pipelines for reliability.

---

### Wrong Manager Detected

**Symptom:**
```console
$ pkgd pip install requests
# Actually installs via wrong package manager
```

**Cause:** Project files in directory confuse the detector.

**Solution:**

```bash
# Always use the correct manager prefix explicitly
pkgd pip install requests

# Check what files are in current directory
ls -la

# Navigate to a directory without conflicting files
cd /tmp
pkgd pip install requests
```

**Prevention:** Use the correct manager prefix in scripts and CI/CD (e.g., `pkgd pip install`, `pkgd npm install`).

---

## Shell Integration Issues

### Shell Integration Not Installing

**Symptom:**
```console
$ pkgd setup
# Setup appears to complete successfully
$ npm install express
# Native npm runs without interception
```

**Cause:** Aliases not properly sourced, or wrong shell.

**Solution:**

```bash
# Check which shell you're using
echo $SHELL

# Re-run setup for your specific shell
pkgd setup --shell zsh

# Manually verify shell functions are in RC file
cat ~/.zshrc | grep "pkgd"

# Source your RC file
source ~/.zshrc

# Or restart your terminal
```

**Prevention:** Ensure you're running `pkgd setup` in the same shell type you use interactively.

---

### Shell Integration Not Intercepting Commands

**Symptom:**
```console
$ npm install express
# Installs directly without pkgd check
```

**Cause:** Shell functions not sourced, or functions don't include the package manager.

**Solution:**

```bash
# Check which commands are intercepted
type npm  # Should show "npm is a function"
type pip  # Should show "pip is a function"

# Re-run pkgd setup
pkgd reset --teardown
pkgd setup

# Source RC file
source ~/.zshrc

# Test interception
type npm  # Should show "npm is a function"
```

**Prevention:** After running pkgd setup, always source your RC file or restart terminal.

---

### Slow Terminal Startup

**Symptom:**
```console
$ # Terminal takes 5+ seconds to become responsive
```

**Cause:** This is unlikely to be caused by pkg-defender. Shell functions
(which pkg-defender uses for command interception) add negligible startup
overhead. Slow shell startup is typically caused by heavy shell frameworks
or a large RC file.

**Solution:**

```bash
# Check for slow operations in configuration
pkgd health --verbose

# Check daemon status (daemon can slow startup if querying)
pkgd daemon status

# Daemon auto-start is managed via system service, not config key.
# Use `pkgd daemon install --platform <platform>` to install as a service.
```

**Prevention:** Use daemon for background operations.

---

### Package Manager Not Intercepted

**Symptom:**
```console
$ # Using a package manager but it's not intercepted
```

**Cause:** Package manager not detected during setup, or not in hook.

**Solution:**

```bash
# Check which managers are detected
pkgd setup --dry-run

# Re-run setup after installing the manager
brew install node  # Install npm
pkgd setup

# Verify hook installation
pkgd health --verbose
```

**Prevention:** Install all package managers before running initial setup.

---

## Database Issues

### Database Locked

**Symptom:**
```console
$ pkgd <command>
# Command hangs or returns a database-related error
# Possible: sqlite3.OperationalError: database is locked
```

**Cause:** Another pkgd process is using the database (SQLite's native lock).
SQLite retries automatically for 30 seconds (configurable via `busy_timeout_ms`),
then raises the error if the lock persists.

**Solution:**

```bash
# Find and kill running pkgd processes
ps aux | grep pkgd
kill <PID>

# Wait for background operations to complete
sleep 5

# Retry the command
pkgd pip install <package>

# If persistent, check for daemon
pkgd daemon status
pkgd daemon stop
pkgd pip install <package>
pkgd daemon start
```

**Prevention:** Always stop daemon before system sleep or shutdown.

---

### Database Not Initializing

**Symptom:**
```console
Error: No local database found. Run 'pkgd setup' to initialize your local database.
```

**Cause:** Database schema not created, or corrupted.

**Solution:**

```bash
# Run setup to initialize database
pkgd setup

# Or force re-initialization
pkgd reset --yes
pkgd setup

# Check database location
pkgd config get database.path

# Manually verify (Linux)
ls -la ~/.local/share/pkg-defender/
# Manually verify (macOS)
ls -la ~/Library/Application\ Support/pkg-defender/
```

**Prevention:** Run `pkgd setup` after fresh installation.

---

### Database Location/Permissions

**Symptom:**
```console
Error: Could not open database: {e}. Run 'pkgd db verify' to check database integrity.
# or
PermissionError: [Errno 13] Permission denied
```

**Cause:** Wrong permissions or database in inaccessible location.

**Solution:**

```bash
# Check database location
pkgd config get database.path

# Show actual database directory (Linux)
ls -la ~/.local/share/pkg-defender/
# Show actual database directory (macOS)
ls -la ~/Library/Application\ Support/pkg-defender/

# Fix permissions on the database file
chmod 600 ~/.local/share/pkg-defender/threats.db       # Linux
chmod 600 ~/Library/Application\ Support/pkg-defender/threats.db  # macOS

# `database.path` expects a directory path, not the full file path.
# The filename `threats.db` is appended automatically.
# Correct usage:
pkgd config set database.path ~/custom/package-dir
```

**Prevention:** Let the tool manage its own database location. Use `pkgd config get database.path` to see the current path.

## Feed/Intel Issues

### Feed Sync Failing

**Symptom:**
```console
$ pkgd intel sync
Error: Feed sync failed: {exc}. Check your network connection and run 'pkgd intel sync' again.
```

**Cause:** Network issues, feed server down, or API rate limiting.

**Solution:**

```bash
# Check feed health first
pkgd health

# Check network connectivity
curl -I https://api.osv.dev
curl -I https://api.github.com

# Check for rate limiting
pkgd health | grep -i rate

# Wait and retry
sleep 60
pkgd intel sync
```

**Prevention:** Use daemon for automatic retry with backoff.

---

### Feed Out of Date

**Symptom:**
```console
$ pkgd health
Warning: Threat database is stale (last sync: {last_sync}). Run `pkgd intel sync`.
```

**Cause:** Feed sync not running frequently enough.

**Solution:**

```bash
# Force sync
pkgd intel sync

# Check daemon status
pkgd daemon status

# Start daemon if not running
pkgd daemon start

# Adjust sync interval
pkgd config set daemon.sync_interval_hours 4
```

**Prevention:** Keep daemon running for automatic sync.

---

### Network Connectivity Issues

**Symptom:**
```console
Error: Feed sync failed: {exc}. Check your network connection and run 'pkgd intel sync' again.
```

**Cause:** Firewall, VPN, or network configuration blocking requests.

**Solution:**

```bash
# Test basic connectivity
ping api.osv.dev
curl -v https://api.osv.dev

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Configure proxy if needed
export HTTPS_PROXY=http://your-proxy:8080

# Check firewall rules
sudo iptables -L | grep 443  # Linux
sudo pfctl -s rules  # macOS
```

**Prevention:** Configure proxy in environment if behind corporate firewall.

---

### API Token Issues

**Symptom:**
```console
$ pkgd health
# ghsa shows as "error" in the feed health table
# Or during sync:
$ pkgd intel sync
ghsa: error — 401 Client Error: Unauthorized
```

**Cause:** Missing or invalid API token.

**Solution:**

```bash
# Check configured tokens
pkgd config get feeds.ghsa_token

# Re-run setup to configure tokens
pkgd setup

# Set token manually
pkgd config set feeds.ghsa_token <your-token>

# Verify token manually
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/rate_limit

# Use environment variable
export PKGD_FEEDS_GHSA_TOKEN=your_token
```

**Prevention:** Keep tokens secure. Never commit tokens to version control.

---

### Specific Feed Not Syncing

**Symptom:**
```console
$ pkgd health
Intelligence Feed Health
Feed      Configured   Last Sync           Status
osv       yes          2026-06-05 10:00    idle
ghsa      yes          2026-06-05 09:30    error
socket    yes          2026-06-05 10:00    idle
```

**Cause:** Individual feed service issue.

**Solution:**

```bash
# Check specific feed error
pkgd health --verbose

# Disable problematic feed temporarily (flat config keys)
pkgd config set feeds.ghsa_enabled false

# Sync remaining feeds
pkgd intel sync

# Re-enable and retry
pkgd config set feeds.ghsa_enabled true
pkgd intel sync
```

**Prevention:** Use multiple feeds so one failure doesn't break everything.

---

## Daemon Issues

> **Architecture note:** The daemon is not an HTTP server. It is a background
> subprocess that runs an asyncio event loop for periodic feed sync. Single-instance
> enforcement uses `fcntl.flock()` on a lock file, not port binding. There is no
> `daemon.port`, `daemon.auto_start`, or `daemon.cache_size_mb` configuration key.
>
> Daemon files are stored in the **data directory root** (not a `daemon/` subdirectory):
>
> | File | Purpose |
> |------|---------|
> | `daemon_heartbeat.json` | Timestamp of last successful sync cycle |
> | `daemon.pid` | Process ID of the running daemon |
> | `pkgd.log` | Application log file |

### Daemon Not Starting

**Symptom:**
```console
$ pkgd daemon start
[red]Daemon is not running (no fresh heartbeat).[/]
```

**Cause:** Another daemon instance may already be running, or a startup error occurred.

**Solution:**

```bash
# Check if already running
pkgd daemon status

# If another instance is running, stop it first
pkgd daemon stop
pkgd daemon start

# Run in foreground to see startup errors
pkgd daemon run

# Check daemon configuration
pkgd config get daemon
```

**Prevention:** Check `pkgd health` before starting daemon.

---

### Daemon Already Running (Lock Conflict)

**Symptom:**
```console
RuntimeError: Another daemon instance is already running.
```

**Cause:** The daemon uses `fcntl.flock()` on a lock file for single-instance
enforcement. This error means an instance is already active.

**Solution:**

```bash
# Check daemon status
pkgd daemon status

# Stop the running instance
pkgd daemon stop

# Or restart (stops + starts in one command)
pkgd daemon restart
```

**Prevention:** Ensure only one daemon instance runs at a time. Use `pkgd daemon status` to check before starting.

---

### Daemon Crashing

**Symptom:**
```console
$ pkgd daemon status
[red]Daemon is not running (no fresh heartbeat).[/]
```

**Cause:** Crash, OOM kill, or system sleep without cleanup.

**Solution:**

```bash
# Stop any stale process
pkgd daemon stop

# Remove stale heartbeat and PID files
rm ~/.local/share/pkg-defender/daemon_heartbeat.json 2>/dev/null  # Linux
rm ~/Library/Application\ Support/pkg-defender/daemon_heartbeat.json 2>/dev/null  # macOS
rm ~/.local/share/pkg-defender/daemon.pid 2>/dev/null  # Linux
rm ~/Library/Application\ Support/pkg-defender/daemon.pid 2>/dev/null  # macOS

# Restart
pkgd daemon start

# Monitor logs
pkgd logs follow
```

**Prevention:** Monitor daemon health with `pkgd health` periodically.

---

### Stale Heartbeat (Daemon Crashed Without Cleanup)

**Symptom:**
```console
$ pkgd daemon status
[red]Daemon is not running (no fresh heartbeat).[/]
```

**Cause:** Daemon crashed but didn't clean up heartbeat file.

**Solution:**

```bash
# Stop any stale process
pkgd daemon stop

# Remove stale heartbeat
rm ~/.local/share/pkg-defender/daemon_heartbeat.json 2>/dev/null  # Linux
rm ~/Library/Application\ Support/pkg-defender/daemon_heartbeat.json 2>/dev/null  # macOS

# Restart
pkgd daemon start
```

**Prevention:** Use `pkgd daemon stop` before system sleep.

---

### Daemon Auto-Start Not Working

**Symptom:**
```console
# After reboot, daemon is not running
```

**Cause:** System service not installed or enabled.

**Solution:**

```bash
# Install as system service
pkgd daemon install --platform linux  # or macos

# Verify installation
systemctl --user status pkg-defender  # Linux
launchctl list | grep pkg-defender  # macOS

# Check daemon battery setting (daemon stops on battery by default)
pkgd config set daemon.run_on_battery true
```

**Prevention:** Install daemon as system service for automatic startup. Configure `daemon.run_on_battery` if running on a laptop.

---

## Performance Issues

### Slow Threat Checks

**Symptom:**
```console
$ pkgd pip install <package>
# Takes 30+ seconds to check
```

**Cause:** Network latency, large database, or feed timeout too long.

**Solution:**

```bash
# Use verbose to see where time is spent
pkgd pip install <package> --verbose

# Reduce timeout if feeds are fast
pkgd config set command_timeout_seconds 10

# Use daemon for pre-cached results
pkgd daemon start
pkgd intel sync

# Optimize database
pkgd reset --yes
pkgd intel sync
```

**Prevention:** Run daemon for pre-cached threat data.

---

### High Memory Usage

**Symptom:**
```console
# pkgd process uses 500MB+ memory
```

**Cause:** Large threat database, memory leak, or too much data cached.

**Solution:**

```bash
# Check database size (adjust path for your OS)
ls -lh ~/.local/share/pkg-defender/threats.db          # Linux
ls -lh ~/Library/Application\ Support/pkg-defender/threats.db  # macOS

# Note: There is no daemon cache size config. Database is the only persistent store.
# Clear and rebuild database
pkgd reset --yes
pkgd intel sync
```

**Prevention:** There is no cache size configuration option.
The database is the only persistent store. Keep disk usage under control by
setting `database.retention_days` in your config (e.g., `30` to keep only
the last 30 days of threat data) or by adjusting which feeds are enabled.

---

### Slow Database Queries

**Symptom:**
```console
$ pkgd intel search <package>
# Takes 10+ seconds
```

**Cause:** Database not optimized, missing indexes, or large dataset.

**Solution:**

```bash
# Check database health
pkgd health

# Reindex database
pkgd reset --yes
pkgd intel sync

# Check available disk space (adjust for your OS)
df -h ~/.local/share/pkg-defender/          # Linux
df -h ~/Library/Application\ Support/pkg-defender/  # macOS

# Vacuum database (advanced) — adjust path for your OS
# Linux:
sqlite3 ~/.local/share/pkg-defender/threats.db "VACUUM;"
# macOS:
sqlite3 ~/Library/Application\ Support/pkg-defender/threats.db "VACUUM;"
```

**Prevention:** Regular database maintenance with `pkgd reset` and re-sync.

---

## General Debugging

### Enable Verbose Mode

**Symptom:** Need detailed output for troubleshooting.

**Solution:**

```bash
# Per-command verbose
pkgd pip install <package> --verbose
pkgd intel sync --verbose
pkgd health --verbose

# Global verbose via environment
export PKGD_OUTPUT_VERBOSE=true
pkgd pip install <package>

# Global verbose via config
pkgd config set output.verbose true
```

**Verbose output shows:**
- Registry queries and responses
- Cooldown calculation details
- Threat scan results and scoring
- API request/response headers

---

### Log Locations

| Log Type    | Location                                                      |
| ----------- | ------------------------------------------------------------- |
| App log     | `~/.local/share/pkg-defender/pkgd.log` (Linux)                |
|             | `~/Library/Application Support/pkg-defender/pkgd.log` (macOS) |
| CLI output  | stderr (not to file)                                          |
| System logs | System journal (if daemon installed as service)               |

**Viewing logs:**

```bash
# View the application log (adjust path for your OS)
tail -f ~/.local/share/pkg-defender/pkgd.log             # Linux
tail -f ~/Library/Application\ Support/pkg-defender/pkgd.log  # macOS

# Or use the built-in log viewer
pkgd logs follow

# Use lnav for structured log viewing
lnav ~/.local/share/pkg-defender/             # Linux
lnav ~/Library/Application\ Support/pkg-defender/  # macOS

# View recent errors
tail -50 ~/.local/share/pkg-defender/pkgd.log | grep -i error  # Linux
tail -50 ~/Library/Application\ Support/pkg-defender/pkgd.log | grep -i error  # macOS
```

---

### Checking Version

**Solution:**

```bash
# Check pkgd version
pkgd --version

# Check Python version
python3 --version

# Check dependencies
pip show pkg-defender
```

**Always include version in bug reports.**

---

### System Health Check

Run comprehensive health check:

```bash
# Full health check
pkgd health

# With verbose output
pkgd health --verbose

# Check specific components
pkgd status
pkgd daemon status
pkgd config view
```

---

## Recovery Procedures

### Full Reset

When all else fails, reset everything:

```bash
# 1. Stop daemon
pkgd daemon stop

# 2. Reset all data
pkgd reset --yes

# 3. Run setup
pkgd setup

# 4. Sync feeds
pkgd intel sync

# 5. Verify
pkgd health
```

**Warning:** This deletes all cached threat data, bypasses, and configuration.

---

### Reset Feeds Only

Keep configuration, reset only threat data (uses flat config keys — note the underscore, not dot notation):

```bash
# Disable all feeds
pkgd config set feeds.osv_enabled false
pkgd config set feeds.ghsa_enabled false
pkgd config set feeds.socket_enabled false

# Sync to clear
pkgd intel sync

# Re-enable feeds
pkgd config set feeds.osv_enabled true
pkgd config set feeds.ghsa_enabled true
pkgd config set feeds.socket_enabled true

# Re-sync
pkgd intel sync
```

---

### Recover from Corrupted Database

```bash
# Backup corrupted database (adjust path for your OS)
cp ~/.local/share/pkg-defender/threats.db ~/threats.db.corrupted           # Linux
cp ~/Library/Application\ Support/pkg-defender/threats.db ~/threats.db.corrupted  # macOS

# Reset
pkgd reset --yes

# Re-sync
pkgd intel sync
```

---

### Export Configuration Before Reset

```bash
# Export current config
pkgd config view > ~/pkgd-config-backup.txt

# Reset
pkgd reset --yes

# Restore config manually after setup:
#   Linux:   ~/.config/pkg-defender/pkgd.toml
#   macOS:   ~/Library/Application Support/pkg-defender/pkgd.toml
```

## Getting Help

If this guide doesn't solve your issue:

1. **Check `pkgd health`** — Run this first for diagnostic info
2. **Enable verbose mode** — `pkgd <command> --verbose`
3. **Check logs** — Application log at `~/.local/share/pkg-defender/pkgd.log` (Linux) or `~/Library/Application Support/pkg-defender/pkgd.log` (macOS)
4. **Report issues** — Include `pkgd --version` and output of `pkgd health --verbose`

---

[← Back to Documentation](../index.md)
