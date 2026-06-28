# Threat Feeds

`pkg-defender` syncs threat intelligence from 9 active threat intelligence feeds (5 enabled by default), combining structured vulnerability databases with social intelligence for early warnings.

## Feed Types

### Structured Feeds

These feeds provide version-precise vulnerability data and can block installs:

| Feed           | Source           | Default  | Description                                                                      |
| -------------- | ---------------- | -------- | -------------------------------------------------------------------------------- |
| OSV.dev        | `osv`            | Enabled  | Open Source Vulnerabilities database — structured, version-precise               |
| GHSA           | `ghsa`           | Enabled  | GitHub Security Advisories — requires optional API token                         |
| Socket.dev     | `socket`         | Disabled | Socket.dev security intelligence — requires API key for full functionality       |
| npm Advisory   | `npm_advisory`   | Disabled | npm registry security advisories                                                 |
| Homebrew       | `homebrew`       | Enabled  | Homebrew vulnerability feed (no dedicated enable flag in FeedConfig)             |
| OSSF Malicious | `ossf_malicious` | Enabled  | OpenSSF Malicious Packages feed — authoritative list of known-malicious packages |

### Social Feeds

These feeds provide early community warnings. Mastodon, Reddit, and X/Twitter entries are **informational only** — the scorer caps their confidence to 0.2 (`scorer.py:126-128`) to ensure they never produce a blocking score. RSS is listed here for organizational reasons but is classified separately by the scoring system (see [Confidence Scores](#confidence-scores) below):

| Feed      | Source      | Default         | Description                                                                                                         |
| --------- | ----------- | --------------- | ------------------------------------------------------------------------------------------------------------------- |
| Mastodon  | `mastodon`  | Disabled        | Security community posts on infosec.exchange and other instances                                                    |
| Reddit    | `reddit`    | Disabled (BYOK) | Posts from netsec, javascript, Python, programming — requires your own Reddit API credentials                       |
| RSS       | `rss`       | Enabled         | Security blogs: Socket.dev, Snyk, OpenSSF, GitHub Security — scored as structured feed (confidence 0.5, not capped) |
| X/Twitter | `x_twitter` | Disabled        | BYOK — requires bearer token, trusted account boost                                                                 |

> **Note:** Reddit feed operates under the BYOK (Bring Your Own Key) model. To enable Reddit, you must:
> 1. Create a Reddit app at [https://www.reddit.com/prefs/apps](https://www.reddit.com/prefs/apps)
> 2. Note your `client_id` (under the app name) and set `client_secret`
> 3. Set `reddit_enabled = true` and configure `reddit_client_id` and `reddit_client_secret`

## Confidence Scores

Each source has a confidence weight used by the scorer (`scorer.py:15-26`). Higher weights mean the source's findings carry more influence in the final threat score.

| Source Key       | Weight | Notes                                                            |
| ---------------- | ------ | ---------------------------------------------------------------- |
| `socket`         | 0.95   | Real-time, most accurate for active attacks                      |
| `ossf_malicious` | 1.0    | Authoritative malicious package list — highest confidence source |
| `osv`            | 0.9    | Structured, version-precise, curated                             |
| `homebrew_osv`   | 0.9    | Homebrew OSV — same upstream OSV database as `osv`               |
| `ghsa`           | 0.85   | High quality but bulk/advisory-level                             |
| `npm_advisory`   | 0.8    | npm registry security advisories                                 |
| `rss`            | 0.5    | Unstructured text, keyword matching                              |
| `x_twitter`      | 0.5    | BYOK, varies by trusted account                                  |
| `reddit`         | 0.45   | Social but moderated communities                                 |
| `mastodon`       | 0.4    | Social, noisy, high false positive                               |

**Social feeds cap:** Mastodon, Reddit, and X/Twitter have their effective confidence capped to 0.2 in the scorer (`scorer.py:126-128`), regardless of the weights above. This ensures social feed entries cannot produce a blocking score (`BLOCK_SCORE_THRESHOLD = 0.3` in `checker.py`). RSS is **not** in this set and retains its full 0.5 weight.

**Homebrew name mismatch:** The `HomebrewFeedAdapter.name` property returns `"homebrew"` (used for feed-state tracking), but individual records use `source="homebrew_osv"` (`homebrew.py:218`), which is the key in `SOURCE_CONFIDENCE`. The table above uses the `SOURCE_CONFIDENCE` keys — the adapter name and the scoring key differ for this feed.

## Configuration

Each feed has enable/disable and configuration keys:

```toml
[feeds]
osv_enabled = true

ghsa_enabled = true
ghsa_token = ""  # Optional GitHub API token

socket_enabled = false  # Enable Socket.dev feed (disabled by default)
socket_api_key = ""  # Required for Socket.dev feed

mastodon_enabled = false
mastodon_instance = "infosec.exchange"
mastodon_hashtags = ["supplychain", "npmjs", "pypi", "infosec", "malware"]
mastodon_max_age_hours = 72

reddit_enabled = false  # BYOK — requires your own Reddit API credentials
# reddit_client_id = ""     # Your Reddit app's client_id (set via: pkgd config set-secret)
# reddit_client_secret = "" # Your Reddit app's client_secret (set via: pkgd config set-secret)
# reddit_subreddits = ["netsec", "javascript", "Python", "programming"]
# reddit_keywords = ["supply chain", "compromised", "malicious", "backdoor", "typosquat"]
# reddit_max_age_hours = 72

rss_enabled = true
rss_urls = ["https://socket.dev/api/blog/feed.atom", "https://snyk.io/blog/feed/", "https://openssf.org/feed/", "https://github.blog/security/feed/", "https://blog.gitguardian.com/feed/", "https://blog.sonatype.com/rss.xml"]
rss_keywords = ["vulnerability", "vulnerabilities", "CVE", "supply chain", "supply-chain", "compromised", "malicious", "backdoor", "typosquat", "malware", "virus", "ransomware", "exploit", "breach", "leak", "npm", "pypi", "pip", "rubygems", "cargo", "go.mod", "maven", "gradle", "security", "hack", "attack", "patch", "update", "incident", "alert", "warning", "advisory"]
rss_max_age_hours = 336

x_twitter_enabled = false
x_twitter_bearer_token = ""
x_twitter_trusted_accounts = []
x_twitter_keywords = ["supply chain", "npm compromised", "pypi malicious", "malware"]
x_twitter_max_age_hours = 48

npm_advisory_enabled = false
ossf_malicious_enabled = true
staleness_threshold_hours = 8
```

## Sync Management

### Manual Sync

```bash
pkgd intel sync
```

Syncs all enabled feeds. On first run, this may take several minutes as it downloads the full vulnerability database.

### Background Daemon

For automatic periodic sync, use the daemon:

```bash
pkgd daemon start        # start background daemon
pkgd daemon status       # check sync status
pkgd daemon stop         # stop daemon
```

The daemon syncs all enabled feeds on a single cycle controlled by `sync_interval_hours` (default: 4h) in the `[daemon]` config section — there are no per-feed sync intervals.

### Feed Health

Check feed status:

```bash
pkgd status
```

Shows last sync time and status for each feed. A separate stale-database warning appears before search/report commands when the OSV feed has not synced within `staleness_threshold_hours` (default: 8).

## Searching Threats

```bash
pkgd intel search lodash          # search for a package
pkgd intel search lodash --manager npm     # search npm ecosystem only
pkgd intel search lodash -o json             # JSON output
pkgd intel search lodash -o json --pretty   # pretty-printed JSON
```

## Threat Report

```bash
pkgd intel report                     # Rich table dashboard
pkgd intel report --manager npm               # npm ecosystem only
pkgd intel report -o json              # JSON output
pkgd intel report -o json --pretty    # pretty-printed JSON
```

The report shows:
- **Threats by severity** — CRITICAL, HIGH, MEDIUM, LOW with color coding
- **Threats by source** — OSV.dev, GHSA, npm Advisory, Homebrew, RSS, OSSF Malicious, Socket.dev, and social feeds (Mastodon, Reddit, X/Twitter)
- **Threats by ecosystem** — npm, pypi, homebrew, apt, yum, dnf, rubygems, cargo
- **Top targeted packages** — most-affected packages (top 10)
- **Feed health** — last sync time and status per feed

## Circuit Breaker

External feed integrations include circuit breaker protection (`aggregator.py`). When a feed fails `CIRCUIT_BREAKER_THRESHOLD` (3) consecutive syncs, the circuit opens and the feed is skipped for `CIRCUIT_BREAKER_COOLDOWN` (3600s / 1 hour). After the cooldown, the circuit enters half-open state and allows one test sync. A successful test closes the circuit; a failed test reopens it.

**Persistence is partial:**

| State transition   | Persisted to DB?  | Details                                                                                                                                                                      |
| ------------------ | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Closed → Open      | No (on next sync) | In-memory in `_record_failure()` (`aggregator.py:262-264`); `circuit_open` written to DB on next sync skip (`aggregator.py:395-401`)                                         |
| Open → Half-open   | No                | In-memory transition after cooldown elapses (`aggregator.py:131-144`)                                                                                                        |
| Half-open → Closed | No                | `_record_success()` only updates in-memory state (`aggregator.py:150-162`)                                                                                                   |
| Half-open → Open   | No (on next sync) | In-memory in `_record_failure()` (`aggregator.py:253-256`); `error` written to DB (`aggregator.py:574-582`); `circuit_open` persisted on next sync (`aggregator.py:395-401`) |

**On daemon restart:** Circuit-open feeds are restored from the DB (`aggregator.py:88-103`), but `opened_at` is set to `time.time()` — the original open timestamp is lost, so the cooldown timer resets from the restart moment rather than from when the circuit actually opened.

---

[← Back to Documentation](../index.md)
