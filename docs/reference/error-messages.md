# Error Messages and Reference

This reference catalog documents all error messages, exit codes, environment variable restrictions, and package manager detection rules for pkg-defender.

## Quick Reference

| Symptom                       | Quick Fix                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------- |
| `pkgd: command not found`     | Run `uv pip install pkg-defender` or activate your virtual environment.               |
| `pkgd health` shows errors    | Run `pkgd setup && pkgd intel sync`.                                                  |
| Package blocked by cooldown   | Use `pkgd bypass <pkg@ver> --reason "..."` or wait for the cooldown period to expire. |
| Package blocked by threat     | Use `pkgd bypass <pkg@ver> --reason "..."` after reviewing the threat report.         |
| Shell integration not working | Run `pkgd setup` again, then `source ~/.zshrc`.                                       |
| Threat database is stale      | Run `pkgd intel sync` to update.                                                      |
| Daemon not running            | Run `pkgd daemon start`.                                                              |

## Exit Code Reference

pkg-defender uses the following exit codes to indicate the result of a command. Exit codes 0, 1, and 2 follow standard Unix conventions; codes 3+ are domain-specific. Note that `os.execvp` replaces the process with the managed command, so the underlying manager's exit code is relayed directly to the shell.

| Exit Code | Constant                    | Description                                      |
| --------- | --------------------------- | ------------------------------------------------ |
| 0         | `EXIT_SUCCESS`              | Success — no errors or warnings.                 |
| 1         | `EXIT_GENERAL_ERROR`        | General error — an unspecified failure occurred. |
| 2         | `EXIT_USAGE_ERROR`          | Invalid arguments or usage error.                |
| 3         | `EXIT_COOLDOWN`             | Package version is in cooldown period.           |
| 4         | `EXIT_THREAT_DETECTED`      | Threat or vulnerability detected.                |
| 5         | `EXIT_REGISTRY_UNREACHABLE` | Registry or network unreachable.                 |
| 6         | `EXIT_CONFIG_ERROR`         | Configuration error.                             |
| 7         | `EXIT_DB_ERROR`             | Database error.                                  |
| 8         | `EXIT_PARTIAL_FAILURE`      | Setup completed with warnings (partial failure). |
| 130       | `EXIT_SIGINT`               | Interrupted by signal (SIGINT).                  |

Note: Exit codes for the managed process (after `os.execvp` replaces pkgd) come directly from the underlying package manager (e.g., pip, npm, brew). pkgd does not intercept or modify those codes.

## Common Error Messages

| Error                                                                                                                                                               | Cause                                                                                                                | Solution                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `[PKGD] BLOCKED — {name}@{version}`                                                                                                                                 | Known security vulnerability.                                                                                        | Review with `pkgd intel search {name}`, then use `--bypass-threat` if safe.                            |
| `[PKGD] BLOCKED — {name}@{version}`                                                                                                                                 | Version published too recently, or timestamp resolution failed (see `resolution_attempts` table for failure reason). | Use `pkgd bypass <pkg@ver> --reason "..."` or wait for cooldown to expire.                             |
| `[PKGD] Error: Threat database not found. Run 'pkgd setup' to initialize...`                                                                                        | Threat database missing.                                                                                             | Run `pkgd setup` to initialize the threat database.                                                    |
| `[PKGD] Error: Threat database is stale and auto-refresh failed. Run 'pkgd intel sync' manually.`                                                                   | Threat database out of date and auto-refresh failed.                                                                 | Run `pkgd intel sync` to update.                                                                       |
| `[PKGD] Error: Pre-install check timed out after {N} seconds`                                                                                                       | Pre-install check exceeded timeout.                                                                                  | Increase `command_timeout_seconds` in config.                                                          |
| `Error: Unknown config key '{key}'. Run 'pkgd config view' to see valid keys.`                                                                                      | Invalid config key used in `config set`.                                                                             | Run `pkgd config view` to see all valid keys.                                                          |
| `[PKGD] ERROR — Unknown package manager: {name}`                                                                                                                    | Unrecognised package manager name.                                                                                   | Run `pkgd hooks --help` to see supported managers.                                                     |
| `[PKGD] ERROR — Command not found: {name}`                                                                                                                          | Required executable not in PATH.                                                                                     | Ensure the package manager is installed and in PATH.                                                   |
| `[PKGD] ERROR — Exec failed: {e}`                                                                                                                                   | OS-level execution failure.                                                                                          | Check system resources and permissions.                                                                |
| `Config file {path} is corrupt: {exc}. Using defaults. Fix the file or run 'pkgd config reset' to recreate it.`                                                     | Config file has invalid TOML syntax.                                                                                 | Printed to stderr and written to the log file. Fix the file or run `pkgd config reset` to recreate it. |
| ``Error: The `pkgd bypass` command is disabled by configuration.``                                                                                                  | Bypass command disabled via `bypass.command_enabled` setting.                                                        | Set `PKGD_BYPASS_COMMAND_ENABLED=true` or enable in config.                                            |
| `Error: package_spec must include a version (e.g., 'axios@1.14.1')`                                                                                                 | Bypass called without a version constraint.                                                                          | Use `pkgd bypass <pkg>@<ver> --reason "..."`.                                                          |
| `Error: No recognised lock file found in {path}`<br>`Supported: package-lock.json, poetry.lock, requirements.txt, yarn.lock, pnpm-lock.yaml, uv.lock, Pipfile.lock` | No supported lock file found in the target directory.                                                                | Run `pkgd audit` in a directory with a supported lock file.                                            |
| ``⚠️  Threat database is stale (last sync: {sync_age}). Run `pkgd intel sync` to update, or `pkgd install` will auto-refresh.``                                      | Threat database is older than the configured staleness threshold.                                                    | Run `pkgd intel sync` to update, or `pkgd install` will auto-refresh.                                  |

## Intercepted Commands

The following commands are used with `pkgd <manager>` and are intercepted by the unified manager registry. Each command is routed through the pre-install check pipeline (threat detection, cooldown check) via `os.execvp`.

**Note:** `python -m pip install <package>` is **NOT** intercepted by pkg-defender. There is no `python` entry in the unified manager registry. Use `pkgd pip install <package>`, `pkgd pip3 install <package>`, or `pkgd pipx install <package>` instead.

### pipx

```bash
pipx install <package>
```

> **Note:** Only `pipx install` triggers pre-install checks. Commands like `pipx run`, `pipx inject`, `pipx upgrade`, `pipx upgrade-all`, and `pipx uninstall` are classified as safe passthrough by the unified adapter — they are executed directly without security verification.

### uv

```bash
uv pip install <package>
uv sync
uv tool run <command>
uv run <command>
```

### yarn

```bash
yarn add <package>
yarn install
```

### pnpm

```bash
pnpm add <package>
pnpm install
```

## Environment Variable Handling

pkg-defender does **not** filter or restrict environment variables passed to managed commands. When a command is cleared for execution, `os.execvp` replaces the current process with the managed command, inheriting the **full parent environment** unchanged.

### PKGD_* Configuration Overrides

pkg-defender reads configuration from `PKGD_*` environment variables that follow the `PKGD_<SECTION>_<FIELD>` naming convention (e.g., `PKGD_COOLDOWN_DEFAULT_DAYS=7`). These overrides are applied to pkg-defender's own configuration before command dispatch and are **not** passed to the managed process.

For the complete list of supported `PKGD_*` environment variables and their corresponding config keys, see `src/pkg_defender/config/settings.py` (the `_ENV_EXPLICIT_OVERRIDES` list and auto-derivation loop). Note that `PKGD_CI`, `PKGD_DEBUG`, and `PKGD_DRY_RUN` are handled directly in `main.py` via Click's `envvar` parameter and `os.environ` lookups, not through `_ENV_EXPLICIT_OVERRIDES`.

Known `PKGD_*` variables used by pkg-defender include:
- `PKGD_CONFIG_PATH` — custom config file path
- `PKGD_DATABASE_PATH` — custom database path
- `PKGD_DRY_RUN` — enable dry-run mode
- `PKGD_CI` — enable CI mode
- `PKGD_DEBUG` — enable debug logging
- `PKGD_BYPASS_COMMAND_ENABLED` — enable/disable bypass command
- `PKGD_COOLDOWN_DEFAULT_DAYS` — override cooldown window
- `PKGD_FAIL_ON_THREAT` — block on threat detection
- `PKGD_COMMAND_TIMEOUT` — override pre-install timeout

## Manager Detection Reference

pkg-defender auto-detects package managers from project files found in the working directory.

| Manager  | Detection File(s)                                        |
| -------- | -------------------------------------------------------- |
| apt      | `/etc/apt/sources.list`                                  |
| brew     | `Brewfile`, `Formula`                                    |
| bun      | `package.json`                                           |
| bundler  | `Gemfile`, `Gemfile.lock`                                |
| cargo    | `Cargo.toml`                                             |
| composer | `composer.json`                                          |
| conda    | `environment.yml`, `environment.yaml`, `conda-lock.json` |
| dnf      | `/etc/dnf.repos.d/`                                      |
| gem      | `Gemfile`                                                |
| npm      | `package.json`                                           |
| pip      | `pyproject.toml`, `requirements.txt`, `setup.py`         |
| pipenv   | `Pipfile`, `Pipfile.lock`                                |
| pipx     | `pyproject.toml`                                         |
| pnpm     | `package.json`, `pnpm-lock.yaml`                         |
| poetry   | `pyproject.toml`, `poetry.lock`                          |
| uv       | `pyproject.toml`, `uv.lock`                              |
| yarn     | `package.json`, `yarn.lock`                              |
| yum      | `/etc/yum.repos.d/`                                      |

> **Note:** `pip3` shares pip's detection markers (`pyproject.toml`, `requirements.txt`, `setup.py`). Managers not listed here (e.g., `pip3`) are detected via system `which` lookups rather than project marker files.

## Database Reference Notes

### WAL Mode

The database runs in Write-Ahead Logging (WAL) mode by default, which enables safe concurrent access from multiple `pkgd` processes. WAL mode can be disabled via the `database.wal_mode` configuration option (set to `false` to disable).

If WAL-related issues are encountered (e.g., database locked errors during concurrent access), verify WAL mode is enabled:

```bash
pkgd config view | grep wal_mode
# Should show: database.wal_mode = true (default)
```
