# Configuration Reference

Complete reference for all 56 configuration keys.

## Config Loading Order

Configuration is loaded in this order (later sources override earlier):

1. **Default values** — built-in defaults
2. **System config** — `/etc/pkgd/pkgd.toml` on Linux (platform equivalent; loaded first, can be overridden by subsequent layers)
3. **User config** — `~/.config/pkg-defender/pkgd.toml` (Linux; platform equivalent via `platformdirs` — overrides system config)
4. **Project config** — nearest `pkgd.toml` found by searching upward from the current directory (overrides user config)
5. **`PKGD_CONFIG_PATH` environment variable** — explicit config file path; skips all file-discovery layers (system → user → project) when set
6. **`PKGD_*` environment variable overrides** — highest priority, always applied last

## Configuration Keys

### Cooldown

| Key                                  | Default | Description                                                |
| ------------------------------------ | ------- | ---------------------------------------------------------- |
| `cooldown.default_days`              | `7`     | Days a new version must age before install is allowed      |
| `cooldown.enabled`                   | `true`  | Whether cooldown checking is active                        |
| `cooldown.strict_mode`               | `true`  | If true, bypass prompts are disabled                       |
| `cooldown.overrides`                 | `{}`    | Per-package cooldown days overrides (package name -> days) |
| `cooldown.per_ecosystem`             | `{}`    | Per-ecosystem cooldown days overrides (ecosystem -> days)  |
| `cooldown.bypass_require_reason`     | `true`  | Whether bypass requires a reason                           |
| `cooldown.bypass_log_retention_days` | `90`    | Days to retain bypass log entries                          |

### Feeds

| Key                                | Default                                                                                                                                                                                                                                                                                                                                                                | Description                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `feeds.osv_enabled`                | `true`                                                                                                                                                                                                                                                                                                                                                                 | Enable OSV.dev feed                                                              |
| `feeds.ghsa_enabled`               | `true`                                                                                                                                                                                                                                                                                                                                                                 | Enable GitHub Security Advisory feed                                             |
| `feeds.ghsa_token`                 | `""`                                                                                                                                                                                                                                                                                                                                                                   | Bearer token for GitHub GraphQL API                                              |
| `feeds.mastodon_enabled`           | `false`                                                                                                                                                                                                                                                                                                                                                                | Enable Mastodon social feed                                                      |
| `feeds.mastodon_instance`          | `"infosec.exchange"`                                                                                                                                                                                                                                                                                                                                                   | Mastodon instance hostname                                                       |
| `feeds.mastodon_hashtags`          | `["supplychain", "npmjs", "pypi", "infosec", "malware"]`                                                                                                                                                                                                                                                                                                               | Hashtags to monitor                                                              |
| `feeds.mastodon_max_age_hours`     | `72`                                                                                                                                                                                                                                                                                                                                                                   | Max age for Mastodon posts (hours)                                               |
| `feeds.reddit_enabled`             | `false`                                                                                                                                                                                                                                                                                                                                                                | Enable Reddit social feed (disabled until credentials)                           |
| `feeds.reddit_subreddits`          | `["netsec", "javascript", "Python", "programming"]`                                                                                                                                                                                                                                                                                                                    | Subreddits to monitor                                                            |
| `feeds.reddit_keywords`            | `["supply chain", "compromised", "malicious", "backdoor", "typosquat"]`                                                                                                                                                                                                                                                                                                | Keywords for subreddit search                                                    |
| `feeds.reddit_max_age_hours`       | `72`                                                                                                                                                                                                                                                                                                                                                                   | Max age for Reddit posts (hours)                                                 |
| `feeds.reddit_client_id`           | `""`                                                                                                                                                                                                                                                                                                                                                                   | Reddit OAuth client_id (required for official API)                               |
| `feeds.reddit_client_secret`       | `""`                                                                                                                                                                                                                                                                                                                                                                   | Reddit OAuth client_secret (required for official API)                           |
| `feeds.rss_enabled`                | `true`                                                                                                                                                                                                                                                                                                                                                                 | Enable RSS feed                                                                  |
| `feeds.rss_urls`                   | `[https://socket.dev/api/blog/feed.atom, https://snyk.io/blog/feed/, https://openssf.org/feed/, https://github.blog/security/feed/, https://blog.gitguardian.com/feed/, https://blog.sonatype.com/rss.xml]`                                                                                                                                                            | RSS feed URLs                                                                    |
| `feeds.rss_keywords`               | `["vulnerability", "vulnerabilities", "CVE", "supply chain", "supply-chain", "compromised", "malicious", "backdoor", "typosquat", "malware", "virus", "ransomware", "exploit", "breach", "leak", "npm", "pypi", "pip", "rubygems", "cargo", "go.mod", "maven", "gradle", "security", "hack", "attack", "patch", "update", "incident", "alert", "warning", "advisory"]` | Keywords for RSS filtering                                                       |
| `feeds.rss_max_age_hours`          | `336`                                                                                                                                                                                                                                                                                                                                                                  | Max age for RSS entries (hours)                                                  |
| `feeds.x_twitter_enabled`          | `false`                                                                                                                                                                                                                                                                                                                                                                | Enable X/Twitter feed (disabled by default, BYOK)                                |
| `feeds.x_twitter_bearer_token`     | `""`                                                                                                                                                                                                                                                                                                                                                                   | Bearer token for X/Twitter API                                                   |
| `feeds.x_twitter_trusted_accounts` | `[]`                                                                                                                                                                                                                                                                                                                                                                   | Trusted X/Twitter account IDs (1.5x confidence boost)                            |
| `feeds.x_twitter_keywords`         | `["supply chain", "npm compromised", "pypi malicious", "malware"]`                                                                                                                                                                                                                                                                                                     | Keywords for tweet search                                                        |
| `feeds.x_twitter_max_age_hours`    | `48`                                                                                                                                                                                                                                                                                                                                                                   | Max age for tweets (hours)                                                       |
| `feeds.npm_advisory_enabled`       | `false`                                                                                                                                                                                                                                                                                                                                                                | Enable npm advisory feed                                                         |
| `feeds.socket_enabled`             | `false`                                                                                                                                                                                                                                                                                                                                                                | Enable Socket.dev feed (disabled by default)                                     |
| `feeds.socket_api_key`             | `""`                                                                                                                                                                                                                                                                                                                                                                   | API key for Socket.dev feed                                                      |
| `feeds.staleness_threshold_hours`  | `8`                                                                                                                                                                                                                                                                                                                                                                    | Hours before a feed is considered stale                                          |
| `feeds.ossf_malicious_enabled`     | `true`                                                                                                                                                                                                                                                                                                                                                                 | Enable OSSF Malicious Packages feed                                              |
| `feeds.http_timeout`               | `60`                                                                                                                                                                                                                                                                                                                                                                   | HTTP request timeout for feed fetches (seconds)                                  |
| `feeds.feed_sync_timeout`          | `7200`                                                                                                                                                                                                                                                                                                                                                                 | Maximum seconds to wait for all feeds to sync (0 = no timeout). Default 2 hours. |

> [!Note]
> Social feeds (Mastodon, Reddit, X/Twitter) are informational-only. They cannot produce blocking verdicts. Opt-in only.
>
> The `http_timeout` setting controls how long to wait for HTTP responses when fetching feed data. Increase this value if experiencing timeouts on slow networks. Default is 60 seconds.
> The `feed_sync_timeout` setting controls the total wall-clock timeout for all feeds to sync together in one cycle. `0` disables the timeout. Increase this value if the sync consistently times out with large feeds (e.g., OSV bulk dump ~334 MB).
>
> The Homebrew feed (`homebrew`) has no dedicated enable flag in FeedConfig — it runs when the aggregator starts.
>
> The Socket.dev feed (`socket`) is disabled by default. To enable it, set `socket_enabled = true` and provide a `socket_api_key`. Socket.dev provides per-package supply chain risk scoring but only supports point queries (no bulk fetch).

### Output

| Key                              | Default       | Description                                   |
| -------------------------------- | ------------- | --------------------------------------------- |
| `output.color`                   | `true`        | Colored terminal output                       |
| `output.json_mode`               | `false`       | JSON output mode                              |
| `output.verbose`                 | `false`       | Verbose output                                |
| `output.show_ascii_banner`       | `true`        | Whether to show ASCII banner in help output   |
| `output.intel_exclude_severity`  | `["UNKNOWN"]` | Severity levels to exclude from intel report  |
| `output.search_exclude_severity` | `["UNKNOWN"]` | Severity levels to exclude from search output |

### Database

| Key                        | Default | Description                                                                                                                                                               |
| -------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `database.wal_mode`        | `true`  | SQLite WAL journal mode                                                                                                                                                   |
| `database.busy_timeout_ms` | `30000` | SQLite busy timeout in ms                                                                                                                                                 |
| `database.path`            | `null`  | Custom database directory (null = platform data directory)                                                                                                                |
| `database.snapshot_url`    | `""`    | Custom URL for database snapshot download (bypasses GitHub API). Requires a companion `.sha256` file at `{url}.sha256`. Marked as secret — see "Valid Secret Keys" below. |
| `database.retention_days`  | `null`  | Days to retain threat records; `null` disables pruning. Must be `>= 1` if set.                                                                                            |

### Bypass

| Key                      | Default | Description                                                                                                                                                                                                          |
| ------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bypass.command_enabled` | `false` | If `false`, the `pkgd bypass` CLI command returns an error. Disabled by default — must be explicitly enabled via TOML (`[bypass]` / `command_enabled = true`) or `PKGD_BYPASS_COMMAND_ENABLED` environment variable. |

### Daemon

| Key                          | Type   | Default | Description                                                                                                                                                                                                                     |
| ---------------------------- | ------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `daemon.run_on_battery`      | `bool` | `false` | Allow the daemon to run on battery power. Default `false` — daemon self-terminates at startup to conserve power. Settable via TOML (`[daemon]` / `run_on_battery = true`) or `PKGD_DAEMON_RUN_ON_BATTERY` environment variable. |
| `daemon.sync_interval_hours` | `int`  | `4`     | Hours between daemon feed sync cycles. All feeds sync together — no per-feed granularity.                                                                                                                                       |

### Global

| Key                              | Default | Description                                                                                                                                                      |
| -------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `command_timeout_seconds`        | `30`    | Timeout in seconds for command execution. Top-level TOML key. Env var: `PKGD_COMMAND_TIMEOUT`.                                                                   |
| `registry_api_timeout`           | `10.0`  | Timeout in seconds for registry API calls. Top-level TOML key. Env var: `PKGD_REGISTRY_API_TIMEOUT`.                                                             |
| `fail_on_threat_enabled`         | `true`  | Whether `--fail-on-threat` is enabled by default. Top-level TOML key. Env var: `PKGD_FAIL_ON_THREAT`.                                                            |
| `per_ecosystem_registry_timeout` | `{}`    | Per-ecosystem overrides for registry API timeout (ecosystem -> seconds). Top-level TOML key. No env var override available — use TOML file or `pkgd config set`. |
| `fail_on_warn_enabled`           | `false` | Whether blocking on warning-level results is active. Top-level TOML key. Env var: `PKGD_FAIL_ON_WARN`.                                                           |
| `enable_homebrew_formula_commit` | `true`  | Enable homebrew-core commit timestamp resolution. Top-level TOML key. Env var: `PKGD_GLOBAL_ENABLE_HOMEBREW_FORMULA_COMMIT`.                                     |

## Setting Configuration

### Via `pkgd config set`

Use dot notation for nested keys:

```bash
pkgd config set cooldown.default_days 7
pkgd config set feeds.staleness_threshold_hours 8
pkgd config set cooldown.overrides.lodash 3
```

> [!Note]
> To quickly view all the various options for config keys and what they do, simply run:
> `pkgd config options`

### Via TOML File

Edit your config file (Linux: `~/.config/pkg-defender/pkgd.toml`, macOS: `~/Library/Application Support/pkg-defender/pkgd.toml`) directly:

```toml
[cooldown]
default_days = 7
strict_mode = true

[feeds]
osv_enabled = true
mastodon_enabled = true
```

### Via Environment Variables

Use the `PKGD_` prefix with uppercase and underscores:

```bash
export PKGD_COOLDOWN_DEFAULT_DAYS=7
export PKGD_FEEDS_OSV_ENABLED=true
export PKGD_FEEDS_GHSA_TOKEN=ghp_xxxxxxxxxxxx
```

## Viewing Configuration

```bash
pkgd config view
```

Shows all resolved configuration values (defaults + TOML + env vars).

## Resetting Configuration

```bash
pkgd config reset
```

Resets all values to built-in defaults. The TOML file is deleted; configuration falls back to defaults on next load.

## Setting Secrets

Use `pkgd config set-secret` to securely set API tokens. This command:
- Uses hidden input (the value is not echoed to the terminal)
- Requires typing the secret twice to confirm (prevents typos)
- Writes directly to your config file

### Valid Secret Keys

| Key                            | Description                    |
| ------------------------------ | ------------------------------ |
| `feeds.ghsa_token`             | GitHub GraphQL API token       |
| `feeds.socket_api_key`         | Socket.dev API key             |
| `feeds.x_twitter_bearer_token` | X/Twitter API bearer token     |
| `feeds.reddit_client_id`       | Reddit OAuth client_id         |
| `feeds.reddit_client_secret`   | Reddit OAuth client_secret     |
| `database.snapshot_url`        | Database snapshot download URL |

### Usage

```bash
pkgd config set-secret feeds.ghsa_token
pkgd config set-secret feeds.socket_api_key
pkgd config set-secret feeds.x_twitter_bearer_token
pkgd config set-secret feeds.reddit_client_id
pkgd config set-secret feeds.reddit_client_secret
```

The command prompts for the value with hidden input. Type the secret twice to confirm.

### When to Use

- **Use `pkgd setup`** when running for the first time — it prompts for missing tokens
- **Use `pkgd config set-secret`** after setup to update existing tokens or when all tokens are already configured and `pkgd setup` does nothing

### Alternative Methods

1. **Environment variables:** `export PKGD_FEEDS_GHSA_TOKEN=your_token`
2. **Direct TOML edit:** Edit the config file (Linux: `~/.config/pkg-defender/pkgd.toml`, macOS: `~/Library/Application Support/pkg-defender/pkgd.toml`) manually

---

[← Back to Documentation](../index.md)
