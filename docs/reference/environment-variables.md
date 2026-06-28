# Environment Variables

> [!Important]
> **⚠️ Security Warning: Token Handling**
>
> Tokens are sensitive credentials that grant access to external services. Follow these guidelines to protect them:
>
> ### Token Exposure Risks
>
> Tokens can be inadvertently leaked through:
>
> - **Shell history** — Commands with tokens are saved in `~/.bash_history` or `~/.zsh_history`
> - **CI/CD logs** — Export statements and environment values may appear in build logs
> - **Environment files** — `.env` files committed to version control
> - **Screen sharing** — Terminal output visible during calls
> - **Error messages** — Stack traces that include environment values
>
> ### Interactive Setup: Use `pkgd config set-secret` Instead
>
> For interactive use, the recommended approach is:
>
> ```bash
> # Securely set a token (prompts for input, no history)
> pkgd config set-secret feeds.ghsa_token
>
> # Or use the config file with restricted permissions
> chmod 600 ~/.config/pkg-defender/pkgd.toml  # Linux; macOS path: ~/Library/Application Support/pkg-defender/pkgd.toml
> ```
>
> This avoids shell history and provides better access control than environment variables.
>
> ### Token Expiration and Silent Failures
>
> Tokens can expire or be revoked without warning. When this happens:
>
> - Feeds may return empty results instead of erroring
> - You may think you're protected by advisory feeds when you're not
> - Rate limits may be applied unexpectedly
>
> **Check token validity periodically** if feeds appear to return fewer results than expected.

Most configuration keys can be overridden via environment variables using the `PKGD_` prefix. Complex types (dictionaries) are not supported — attempting to set fields like `cooldown.overrides` or `per_ecosystem_registry_timeout` via environment variables will result in a string value rather than a dict, which may cause type errors.

## Precedence

Configuration is resolved in this order (later sources override earlier):

1. **Default values** — dataclass field defaults
2. **System config** — `/etc/pkgd/pkgd.toml` (loaded first, can be overridden)
3. **User config** — platform config file (`~/.config/pkg-defender/pkgd.toml` on Linux, equivalent via `platformdirs`)
4. **Project config** — `./pkgd.toml` (found by walking up from CWD; overrides user config)
5. **`PKGD_CONFIG_PATH` env var** — overrides which config file is loaded (only applicable when no explicit path is passed)
6. **`PKGD_*` env var overrides** — always applied last, highest priority (overrides all file-based config)

## Naming Convention

Convert config keys to environment variables:

1. Prefix with `PKGD_`
2. Uppercase the entire key
3. Replace dots with underscores

Examples:
- `cooldown.default_days` → `PKGD_COOLDOWN_DEFAULT_DAYS`
- `feeds.ghsa_token` → `PKGD_FEEDS_GHSA_TOKEN`
- `output.color` → `PKGD_OUTPUT_COLOR`

## Boolean Parsing Rules

Boolean environment variables accept multiple string representations:

### True Values

- `1`
- `true`
- `yes`
- `on`

### False Values

- `0`
- `false`
- `no`
- `off`

Values are case-insensitive. For example, `PKGD_OUTPUT_COLOR=True`, `PKGD_OUTPUT_COLOR=yes`, and `PKGD_OUTPUT_COLOR=1` all enable colored output.

## CI Environment Auto-Detection

pkg-defender automatically detects CI environments by checking for common CI provider environment variables. When detected, the CLI runs in non-interactive mode by default.

### Detected Variables

| Variable             | CI Provider         |
| -------------------- | ------------------- |
| `CI`                 | Generic CI flag     |
| `GITHUB_ACTIONS`     | GitHub Actions      |
| `TF_BUILD`           | Azure Pipelines     |
| `GITLAB_CI`          | GitLab CI           |
| `CIRCLECI`           | CircleCI            |
| `JENKINS_URL`        | Jenkins             |
| `TRAVIS`             | Travis CI           |
| `CODEBUILD_BUILD_ID` | AWS CodeBuild       |
| `BITBUCKET_COMMIT`   | Bitbucket Pipelines |
| `BUILDKITE`          | Buildkite           |
| `TEAMCITY_VERSION`   | JetBrains TeamCity  |
| `SYSTEM_ACCESSTOKEN` | Azure DevOps        |

### Explicit Override

You can explicitly enable CI mode using `PKGD_CI=1`:

```bash
# Force CI mode
export PKGD_CI=1
pkgd pip install axios
```

### Priority Order

CI mode is determined in this order:

1. **Explicit `--ci` flag** — Highest priority
2. **`PKGD_CI` environment variable** — Second priority
3. **Auto-detection** — Checks for CI provider variables

## Usage Examples

```bash
# Override cooldown period
export PKGD_COOLDOWN_DEFAULT_DAYS=7

# Disable strict mode for interactive use
export PKGD_COOLDOWN_STRICT_MODE=false

# Enable all feeds
export PKGD_FEEDS_OSV_ENABLED=true
export PKGD_FEEDS_MASTODON_ENABLED=true
export PKGD_FEEDS_REDDIT_ENABLED=true
export PKGD_FEEDS_RSS_ENABLED=true

# Set API tokens ⚠️ Use pkgd config set-secret for interactive use
# For CI: use environment secrets (e.g., ${{ secrets.GHSA_TOKEN }})
export PKGD_FEEDS_GHSA_TOKEN=***REDACTED***
export PKGD_FEEDS_SOCKET_API_KEY=***REDACTED***

# Disable colored output for CI
export PKGD_OUTPUT_VERBOSE=true
export PKGD_OUTPUT_COLOR=false
```

## Environment Variable Aliases

Several environment variables are aliases for other variables. When both the alias and the target are set, the target takes precedence.

| Alias                  | Maps To                     | Notes                                                                                                              |
| ---------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `PKGD_GITHUB_TOKEN`    | `PKGD_FEEDS_GHSA_TOKEN`     | Legacy alias: sets `config.feeds.ghsa_token` directly (only applied if `PKGD_FEEDS_GHSA_TOKEN` is not set)         |
| `PKGD_TWITTER_API_KEY` | `PKGD_FEEDS_SOCKET_API_KEY` | Legacy alias: sets `config.feeds.socket_api_key` directly (only applied if `PKGD_FEEDS_SOCKET_API_KEY` is not set) |
| `PKGD_CONFIG_FILE`     | `PKGD_CONFIG_PATH`          | Alternative name for config file path override                                                                     |
| `PKGD_DATA_DIR`        | `PKGD_DATABASE_PATH`        | Alias for database path override                                                                                   |

**Note:** `PKGD_EXTRA_FEED_URL` is not an alias — it appends the URL to the RSS feed list (`config.feeds.rss_urls`) rather than replacing existing entries. Duplicate URLs are ignored.

**Note:** `PKGD_DATABASE_PATH` can also be set directly as an environment variable. It sets `config.database.path` to a custom database directory path and is the target of the `PKGD_DATA_DIR` alias listed above.

## Config File Path Override

The `PKGD_CONFIG_PATH` environment variable controls **which** TOML config file is loaded instead of the automatic discovery chain.

| Variable           | Description                         | Notes                                                                                                                           |
| ------------------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `PKGD_CONFIG_PATH` | Path to a specific config TOML file | Overrides all automatic file discovery (system → user → project). Ignored if an explicit `--config` path is passed to commands. |

When set, pkg-defender loads the file at the specified path **instead** of going through the system → user → project config discovery chain. This is useful for:
- Testing alternate configurations
- Running with a workspace-specific config
- CI/CD environments where the config file is at a known path

**Precedence note:** Even when `PKGD_CONFIG_PATH` points to a config file, `PKGD_*` environment variable overrides still take priority over values in that file.

## CLI Control Variables

These environment variables control CLI behavior but are not config fields:

| Variable                | Description                                               | Notes                                                   |
| ----------------------- | --------------------------------------------------------- | ------------------------------------------------------- |
| `PKGD_DEBUG`            | Enable debug mode for programmatic control                | Used by subprocess calls, not a config field            |
| `PKGD_DRY_RUN`          | Show what would be done without making changes            | Used by `--dry-run` / `-n` flag, not a config field     |
| `PKGD_LIBRARIES_IO_KEY` | Libraries.io API key for higher rate limits on timestamps | Read by `TimestampResolver` in `registry/_timestamp.py` |

**Note:** `PKGD_DEBUG`, `PKGD_DRY_RUN`, and `PKGD_LIBRARIES_IO_KEY` are not configuration fields in `pkgd.toml`. They are only used as environment variables for subprocess control, CLI behavior, and timestamp resolution respectively.

## Comma-Separated Lists

Some environment variables accept comma-separated lists of values:

| Variable                              | Config Field                     | Description                            | Example              |
| ------------------------------------- | -------------------------------- | -------------------------------------- | -------------------- |
| `PKGD_OUTPUT_INTEL_EXCLUDE_SEVERITY`  | `output.intel_exclude_severity`  | Severity levels to exclude from intel  | `UNKNOWN,LOW`        |
| `PKGD_OUTPUT_SEARCH_EXCLUDE_SEVERITY` | `output.search_exclude_severity` | Severity levels to exclude from search | `UNKNOWN,LOW,MEDIUM` |

**Notes:**
- Values are case-insensitive and automatically uppercased
- Whitespace around commas is ignored
- Empty values are filtered out

## Explicit Override Variables

These environment variables override config field values but their names do not follow the `PKGD_<SECTION>_<FIELD>` naming convention:

| Variable                     | Config Field                      | Default | Description                                                                                                             |
| ---------------------------- | --------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| `PKGD_FEEDS_X_TWITTER_TOKEN` | `feeds.x_twitter_bearer_token`    | `""`    | Bearer token for X/Twitter API feed                                                                                     |
| `PKGD_FEEDS_STALENESS_HOURS` | `feeds.staleness_threshold_hours` | `8`     | Hours before a feed entry is considered stale                                                                           |
| `PKGD_HTTP_TIMEOUT`          | `feeds.http_timeout`              | `60`    | HTTP request timeout in seconds                                                                                         |
| `PKGD_OUTPUT_JSON`           | `output.json_mode`                | `false` | Output results as JSON instead of plain text                                                                            |
| `PKGD_SHOW_ASCII_BANNER`     | `output.show_ascii_banner`        | `true`  | Show the ASCII art banner on startup                                                                                    |
| `PKGD_DATABASE_BUSY_TIMEOUT` | `database.busy_timeout_ms`        | `5000`  | SQLite busy timeout in milliseconds                                                                                     |
| `PKGD_DB_SNAPSHOT_URL`       | `database.snapshot_url`           | `""`    | Custom URL for database snapshot download (bypasses GitHub API). Requires a companion `.sha256` file at `{url}.sha256`. |
| `PKGD_COMMAND_TIMEOUT`       | `command_timeout_seconds`         | `30`    | Global command timeout in seconds                                                                                       |
| `PKGD_REGISTRY_API_TIMEOUT`  | `registry_api_timeout`            | `10.0`  | Timeout in seconds for registry API calls                                                                               |
| `PKGD_FAIL_ON_THREAT`        | `fail_on_threat_enabled`          | `true`  | Exit with code 4 if any threats are found                                                                               |
| `PKGD_FAIL_ON_WARN`          | `fail_on_warn_enabled`            | `false` | Exit with code 4 if any warnings are found                                                                              |

## Standard Environment Variables

pkg-defender respects the following standard environment variables:

| Variable      | Description                          | Notes                                                                           |
| ------------- | ------------------------------------ | ------------------------------------------------------------------------------- |
| `NO_COLOR`    | Disable colored output               | When set, overrides `PKGD_OUTPUT_COLOR`                                         |
| `FORCE_COLOR` | Force colored output in ASCII banner | Does NOT override `PKGD_OUTPUT_COLOR` — only affects the welcome banner display |
| `TERM`        | Terminal type                        | Used for color detection (e.g., `xterm-256color`)                               |
| `COLUMNS`     | Terminal width                       | Used for output formatting                                                      |
| `SHELL`       | Shell path                           | Used for shell-specific behavior                                                |

**Priority:** `NO_COLOR` overrides `PKGD_OUTPUT_COLOR` for all console output. If `NO_COLOR` is set, colored output is disabled regardless of `PKGD_OUTPUT_COLOR` value. `FORCE_COLOR` only affects the welcome banner display and does not override `PKGD_OUTPUT_COLOR` for general console output.

---

[← Back to Documentation](../index.md)
