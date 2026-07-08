# Data Dictionary

## Package Managers (18 Total)

From `src/pkg_defender/registry/__init__.py` → `UNIFIED_MANAGER_REGISTRY`:

| Ecosystem    | Manager Class            | CLI Executable   |
| ------------ | ------------------------ | ---------------- |
| **homebrew** | `BrewUnifiedAdapter`     | `brew`           |
| **npm**      | `NpmUnifiedAdapter`      | `npm`            |
| **pip**      | `PyPIUnifiedAdapter`     | `pip`, `pip3`    |
| **pipx**     | `PyPIUnifiedAdapter`     | `pipx`           |
| **uv**       | `UvUnifiedAdapter`       | `uv`             |
| **yarn**     | `YarnUnifiedAdapter`     | `yarn`           |
| **pnpm**     | `PnpmUnifiedAdapter`     | `pnpm`           |
| **apt**      | `AptUnifiedAdapter`      | `apt`, `apt-get` |
| **yum**      | `YumUnifiedAdapter`      | `yum`            |
| **dnf**      | `DnfUnifiedAdapter`      | `dnf`            |
| **gem**      | `GemUnifiedAdapter`      | `gem`            |
| **cargo**    | `CargoUnifiedAdapter`    | `cargo`          |
| **composer** | `ComposerUnifiedAdapter` | `composer`       |
| **poetry**   | `PoetryUnifiedAdapter`   | `poetry`         |
| **bundler**  | `BundlerUnifiedAdapter`  | `bundle`         |
| **pipenv**   | `PipenvUnifiedAdapter`   | `pipenv`         |
| **bun**      | `BunUnifiedAdapter`      | `bun`            |
| **conda**    | `CondaUnifiedAdapter`    | `conda`          |

**Total: 18 package managers**

---

## Dangerous Commands

From each adapter's `COMMAND_INTENT_MAP` in `src/pkg_defender/registry/*_unified.py`:

| Ecosystem | Commands Defined                                                                                                               |
| --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| homebrew  | `install`, `upgrade`, `reinstall`, `bundle`, `tap`                                                                             |
| npm       | `install`, `i`, `add`, `update`, `up`, `remove`, `rm`, `uninstall`, `un`                                                       |
| pip       | `install`, `download`, `wheel`, `sync`                                                                                         |
| pipx      | `install`, `download`, `wheel`, `sync`                                                                                         |
| pipenv    | `install`, `sync`, `update`, `upgrade`                                                                                         |
| poetry    | `add`, `install`, `update`, `remove`, `run`                                                                                    |
| uv        | `add`, `install`, `pip`, `pip install`, `pip sync`, `sync`, `upgrade`, `update`, `tool`, `tool install`, `tool upgrade`, `run` |
| yarn      | `add`, `upgrade`, `up`, `set`, `install`, `remove`, `dlx`, `link`                                                              |
| pnpm      | `add`, `install`, `i`, `update`, `upgrade`, `remove`, `dlx`, `import`                                                          |
| bun       | `add`, `install`, `update`, `upgrade`, `x`, `run`                                                                              |
| apt       | `install`, `update`, `upgrade`, `full-upgrade`, `dist-upgrade`, `remove`, `autoremove`, `purge`                                |
| yum       | `install`, `update`, `upgrade`, `localinstall`, `localupdate`, `group`, `remove`, `autoremove`                                 |
| dnf       | `install`, `update`, `upgrade`, `localinstall`, `localupdate`, `group`, `remove`, `autoremove`                                 |
| gem       | `install`, `update`, `fetch`, `query`, `build`, `push`, `owner`                                                                |
| bundler   | `install`, `add`, `update`, `exec`, `check`, `outdated`, `why`, `list`, `show`                                                 |
| cargo     | `add`, `install`, `update`, `fetch`, `build`, `run`                                                                            |
| composer  | `require`, `install`, `update`, `remove`, `create-project`, `global`                                                           |

**Note:** No `maven` or `gradle` commands. `composer` has its own row above.

---

## Threat Intelligence Feeds (9 Total)

From `src/pkg_defender/intel/__init__.py` → `FEED_REGISTRY`:

| Feed Name        | Adapter Class       | Status                        | Default |
| ---------------- | ------------------- | ----------------------------- | ------- |
| `osv`            | `OSVFeedAdapter`    | ✅ Active                      | `true`  |
| `ghsa`           | `GHSAFeed`          | ✅ Active                      | `true`  |
| `socket`         | `None`              | ❌ Code exists, not registered | `false` |
| `npm_advisory`   | `NpmAdvisoryFeed`   | ✅ Active                      | `false` |
| `mastodon`       | `MastodonFeed`      | ✅ Active                      | `false` |
| `reddit`         | `RedditFeed`        | ✅ Active                      | `false` |
| `rss`            | `RSSFeed`           | ✅ Active                      | `true`  |
| `x_twitter`      | `XTwitterFeed`      | ✅ Active                      | `false` |
| `ossf_malicious` | `OSSFMaliciousFeed` | ✅ Active                      | `—`     |

**Active feeds: 8** (`osv`, `ghsa`, `npm_advisory`, `mastodon`, `reddit`, `rss`, `x_twitter`, `ossf_malicious`)
**Total registry entries: 9** (1 has `None` — `socket` is point-query only).

---

## Configuration Keys

From `src/pkg_defender/config/settings.py` → Dataclasses:

### CooldownConfig (7 keys)

| Key                         | Type             | Default | Description                 |
| --------------------------- | ---------------- | ------- | --------------------------- |
| `default_days`              | `int`            | `7`     | Days a new version must age |
| `enabled`                   | `bool`           | `true`  | Whether cooldown is active  |
| `strict_mode`               | `bool`           | `true`  | Disable bypass prompts      |
| `overrides`                 | `dict[str, int]` | `{}`    | Per-package overrides       |
| `per_ecosystem`             | `dict[str, int]` | `{}`    | Per-ecosystem overrides     |
| `bypass_require_reason`     | `bool`           | `true`  | Require reason for bypass   |
| `bypass_log_retention_days` | `int`            | `90`    | Days to retain bypass logs  |

### FeedConfig (28 keys)

| Key                          | Type        | Default                         | Description                         |
| ---------------------------- | ----------- | ------------------------------- | ----------------------------------- |
| `osv_enabled`                | `bool`      | `true`                          | Enable OSV.dev                      |
| `ghsa_enabled`               | `bool`      | `true`                          | Enable GHSA                         |
| `ghsa_token`                 | `str`       | `""`                            | GitHub API token                    |
| `mastodon_enabled`           | `bool`      | `false`                         | Enable Mastodon                     |
| `mastodon_instance`          | `str`       | `"infosec.exchange"`            | Instance hostname                   |
| `mastodon_hashtags`          | `list[str]` | `["supplychain", ...]`          | Hashtags                            |
| `mastodon_max_age_hours`     | `int`       | `72`                            | Max age for posts                   |
| `reddit_enabled`             | `bool`      | `false`                         | Enable Reddit                       |
| `reddit_subreddits`          | `list[str]` | `["netsec", ...]`               | Subreddits                          |
| `reddit_keywords`            | `list[str]` | `["supply chain", ...]`         | Keywords                            |
| `reddit_max_age_hours`       | `int`       | `72`                            | Max age for posts                   |
| `reddit_client_id`           | `str`       | `""`                            | Reddit client_id                    |
| `reddit_client_secret`       | `str`       | `""`                            | Reddit client_secret                |
| `rss_enabled`                | `bool`      | `true`                          | Enable RSS                          |
| `rss_urls`                   | `list[str]` | `[https://socket.dev/..., ...]` | RSS URLs                            |
| `rss_keywords`               | `list[str]` | `["vulnerability", ...]`        | Keywords                            |
| `rss_max_age_hours`          | `int`       | `336`                           | Max age for entries                 |
| `x_twitter_enabled`          | `bool`      | `false`                         | Enable X/Twitter                    |
| `x_twitter_bearer_token`     | `str`       | `""`                            | Bearer token                        |
| `x_twitter_trusted_accounts` | `list[str]` | `[]`                            | Trusted accounts                    |
| `x_twitter_keywords`         | `list[str]` | `["supply chain", ...]`         | Keywords                            |
| `x_twitter_max_age_hours`    | `int`       | `48`                            | Max age for tweets                  |
| `staleness_threshold_hours`  | `int`       | `8`                             | Hours before stale                  |
| `socket_api_key`             | `str`       | `""`                            | Socket.dev API key                  |
| `socket_enabled`             | `bool`      | `false`                         | Enable Socket.dev                   |
| `npm_advisory_enabled`       | `bool`      | `false`                         | Enable npm advisory                 |
| `ossf_malicious_enabled`     | `bool`      | `true`                          | Enable OSSF Malicious Packages feed |
| `http_timeout`               | `int`       | `60`                            | HTTP timeout (seconds)              |

### OutputConfig (6 keys)

| Key                       | Type        | Default       | Description             |
| ------------------------- | ----------- | ------------- | ----------------------- |
| `color`                   | `bool`      | `true`        | Colored terminal output |
| `json_mode`               | `bool`      | `false`       | JSON output mode        |
| `verbose`                 | `bool`      | `false`       | Verbose output          |
| `show_ascii_banner`       | `bool`      | `true`        | Show ASCII banner       |
| `intel_exclude_severity`  | `list[str]` | `["UNKNOWN"]` | Severity to exclude     |
| `search_exclude_severity` | `list[str]` | `["UNKNOWN"]` | Severity to exclude     |

### DatabaseConfig (5 keys)

| Key               | Type           | Default | Description                                      |
| ----------------- | -------------- | ------- | ------------------------------------------------ |
| `wal_mode`        | `bool`         | `true`  | SQLite WAL mode                                  |
| `busy_timeout_ms` | `int`          | `30000` | Busy timeout (ms)                                |
| `path`            | `Path or None` | `None`  | Custom database path                             |
| `snapshot_url`    | `str`          | `""`    | Snapshot download URL (secret)                   |
| `retention_days`  | `int or None`  | `None`  | Days to retain threat records; `None` = disabled |

**Total config keys: 54**

---

### DaemonConfig (2 keys)

| Key                   | Type   | Default | Description                      |
| --------------------- | ------ | ------- | -------------------------------- |
| `run_on_battery`      | `bool` | `false` | Allow daemon on battery power    |
| `sync_interval_hours` | `int`  | `4`     | Hours between daemon sync cycles |

### BypassConfig (1 key)

| Key               | Type   | Default | Description                                                 |
| ----------------- | ------ | ------- | ----------------------------------------------------------- |
| `command_enabled` | `bool` | `false` | Enable the bypass CLI command (opt-in, disabled by default) |

### PKGDConfig Root Fields (5 keys)

| Key                              | Type               | Default | Description                                          |
| -------------------------------- | ------------------ | ------- | ---------------------------------------------------- |
| `command_timeout_seconds`        | `int`              | `30`    | Timeout in seconds for command execution             |
| `registry_api_timeout`           | `float`            | `10.0`  | Timeout in seconds for individual registry API calls |
| `per_ecosystem_registry_timeout` | `dict[str, float]` | `{}`    | Per-ecosystem override for registry API timeout      |
| `fail_on_threat_enabled`         | `bool`             | `true`  | Whether `--fail-on-threat` is enabled by default     |
| `fail_on_warn_enabled`           | `bool`             | `false` | Whether block-on-warning is active                   |

---

## Lock File Parsers

See [Lock File Formats](../reference/lock-file-formats.md) for a comprehensive reference of all supported lock file formats, including format details, transitive dependency coverage, and auditability notes.

Parser functions for lock files are defined in `src/pkg_defender/core/parsers.py`. The following table lists the lock files handled by the generic parser module:

| Lock File           | Ecosystem | Parser Function            |
| ------------------- | --------- | -------------------------- |
| `package-lock.json` | npm       | `parse_package_lock()`     |
| `poetry.lock`       | pypi      | `parse_poetry_lock()`      |
| `requirements.txt`  | pypi      | `parse_requirements_txt()` |
| `Pipfile.lock`      | pypi      | `parse_pipfile_lock()`     |
| `yarn.lock`         | npm       | `parse_yarn_lock()`        |
| `pnpm-lock.yaml`    | npm       | `parse_pnpm_lock()`        |
| `uv.lock`           | pypi      | `parse_uv_lock()`          |

**Total: 7 lock file formats** (NOT 9, NOT 11).

---

## Database Schema (9 Tables)

From `src/pkg_defender/db/schema.py` → `SCHEMA_SQL`. See
[Database Schema](../reference/database-schema.md) for full column-level
detail including types, constraints, CHECK clauses, and indexes.

| Table Name            | Purpose                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| `threats`             | Threat intelligence records                                                 |
| `version_timestamps`  | Package publish times                                                       |
| `bypasses`            | Bypass audit log                                                            |
| `feed_state`          | Feed sync status                                                            |
| `feed_stats`          | Feed sync statistics                                                        |
| `db_metadata`         | Key-value metadata                                                          |
| `audit_events`        | CLI audit log                                                               |
| `resolution_attempts` | Timestamp resolution attempts                                               |
| `schema_version`      | Tracks the current schema version of the database for migration management. |

---

[← Back to Documentation](../index.md)
