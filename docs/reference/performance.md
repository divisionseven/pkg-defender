# Performance Reference

Performance characteristics of `pkg-defender`.

> [!Note]
> **⚠️ Performance figures are approximate.** All timing and memory values in this
> document are order-of-magnitude estimates, not lab measurements. Actual
> performance depends on hardware, Python version, OS, concurrent workloads,
> and threat database size. Use these numbers as rough guidance, not
> specifications.

## CLI Import Time

### Measurement

```console
$ time pkgd --help
pkgd --help  0.18s user 0.04s system 99% cpu 0.223 total
```

**~180ms** for full CLI import (700-line `main.py` with adapter registry).

### Why Not Faster?

- Click framework + adapter registry module loaded at startup; adapter class imports are lazy
- Lazy imports used for heavy modules: `aiohttp`, intel adapters

### Optimization Notes

Lazy imports used for heavy dependencies:
```python
# in cli/common.py — aiohttp only imported inside specific functions
async def _validate_github_token(token: str) -> tuple[str, str]:
    import aiohttp
    ...
```

---

## Threat Check Latency

### Local SQLite Lookup

```console
$ time pkgd intel search requests
# ~2-5ms per package (local DB, no network I/O)
```

| Operation                  | Latency       | Notes                                                                      |
| -------------------------- | ------------- | -------------------------------------------------------------------------- |
| Single package check       | **2-5ms**     | SQLite index seek (`ecosystem` + `package_name`)                           |
| Bulk check (10 pkgs)       | **15-30ms**   | Single `WHERE package_name IN (...)` query with parameterized placeholders |
| Lock file audit (100 deps) | **200-500ms** | Full `package-lock.json` parse + check                                     |

### Why So Fast?

- **Zero network I/O** — all threat data is local SQLite
- **Pre-indexed** — `idx_threats_ecosystem_package` B-tree index
- **No microservice overhead** — threat checks run in-process via direct SQLite queries

---

## Process Handoff: `os.execvp()`

### What Happens (vs `subprocess`)

| Approach             | Overhead                  | Process Tree                   |
| -------------------- | ------------------------- | ------------------------------ |
| `subprocess.Popen()` | Python parent stays alive | `pkgd` → `pip` (orphan checks) |
| **`os.execvp()`**    | **Zero**                  | `pkgd` **replaced by** `pip`   |

### Code Path

```python
# cli/group.py → cli/dispatcher.py → cli/exec.py:exec_cleared_command() → adapter.build_exec_args() → os.execvp()
import os
exec_args = adapter.build_exec_args(parsed)
os.execvp(exec_args[0], exec_args)
# Python process ENDS HERE — manager takes over with same PID
```

**Key behaviors:**
1. **Process replacement** — `pkgd` ceases to exist, `pip` runs in its place
2. **Exit code inheritance** — `pip`'s exit code becomes `pkgd`'s exit code
3. **No environment lockdown** — does NOT use `env -i` (false claim from old docs)
4. **No binary integrity checks** — does NOT do inode + SHA256 verification (false claim from old docs)

---

## Memory Usage

| Component             | Memory                               |
| --------------------- | ------------------------------------ |
| Base CLI (import)     | ~45MB (Python runtime + all modules) |
| Per-adapter           | ~2-5MB (imported on demand)          |
| SQLite database       | ~35MB on disk (pre-built snapshot)   |
| RSS feeds (in memory) | ~1-5MB (depends on feed count)       |

**Total:** ~50-60MB RAM for a typical `pkgd <manager> install` invocation.

---

## Startup Time Breakdown

```
Total: ~180ms
├── Python runtime init:       ~80ms
├── Click framework:           ~30ms
├── Adapter imports:           ~40ms (lazy-loaded)
├── Config loading:            ~15ms (TOML parse)
└── Threat DB connection:      ~15ms (SQLite open + WAL mode)
```

**Note:** All figures are approximate and environment-dependent. No formal benchmarking infrastructure exists in the codebase — timings above are rough estimates, not lab measurements.

---

## Performance Mechanisms

### Caching

| Cache                     | Location              | TTL               | Purpose                            |
| ------------------------- | --------------------- | ----------------- | ---------------------------------- |
| TOML config LRU           | `settings.py`         | Process-lifetime  | Avoid re-parsing config files      |
| Timestamp TTL             | `_timestamp.py`       | 60s               | Cache version publish timestamps   |
| Rate-limit domain cache   | `_timestamp.py`       | 300s              | Cache domain rate-limit state      |
| Bodhi client TTL          | `_bodhi_client.py`    | 6hr               | Cache Bodhi API responses          |
| Repodata URL validation   | `_repodata_client.py` | Process-lifetime  | Cache validated repodata URLs      |
| SQLite version timestamps | `schema.py`           | Trust-level-based | Cache version-to-timestamp lookups |

### Async Concurrency

- **Feed aggregator:** `asyncio.gather` with `Semaphore(10)` for parallel feed ingestion
- **Repodata URL validation:** `asyncio.gather` for parallel URL checks (11 URLs)
- **Reddit feed:** `asyncio.Semaphore(10)` + `create_task` for parallel post fetching
- **Dispatcher:** `asyncio.wait_for` timeout on pre-install threat checks

### Circuit Breaker

Feed aggregator (`aggregator.py`): 3 consecutive feed failures → open circuit (skip all feeds), 1hr cooldown → half-open (retry one feed).

### HTTP Retry

Shared HTTP client (`_http.py`): exponential backoff + jitter, max 3 retries per request. Per-feed retries across 8+ adapter modules.

### SQLite Optimizations

- WAL mode, busy_timeout=30000ms, cache_size=-80000 pages, synchronous=NORMAL, temp_store=MEMORY
- Batch queries: `check_packages_batch()` (2 queries per ecosystem), `get_version_timestamps_batch()`

---

## Optimization Tips

### For CI/CD (Speed Matters)

1. **Use pre-built database snapshots** — skip `pkgd intel sync`:
   ```bash
   pkgd db snapshot --download  # once, in setup
   pkgd pip install axios       # uses local DB (~2ms check)
   ```

2. **Set `PKGD_CI=1`** — skips interactive prompts, no timeout overhead

3. **Use `--fail-on-threat`** — exits early on CRITICAL/HIGH, no JSON formatting

### For Development

1. **Disable social feeds** — Mastodon/Reddit/X add HTTP latency:
   ```toml
   [feeds]
   mastodon_enabled = false
   reddit_enabled = false
   x_twitter_enabled = false
   ```

2. **Reduce `sync_interval_hours`** — default 4h is fine for dev

---

## Architecture Comparison: Planned vs Current Design

| Aspect               | Planned Shell Hooks (never released)               | Current Command Wrappers      |
| -------------------- | -------------------------------------------------- | ----------------------------- |
| **Startup time**     | ~5ms (shell function)                              | ~180ms (Python CLI)           |
| **Threat check**     | In-shell parsing                                   | SQLite lookup (~2-5ms)        |
| **Process handoff**  | `eval` or `subprocess`                             | `os.execvp()` (zero overhead) |
| **Maintenance**      | 5 shell files (bash/zsh/fish/etc.) — never shipped | Single Python codebase        |
| **Binary integrity** | Planned (inode + SHA256) — never implemented       | **Not implemented**           |
| **Env lockdown**     | Planned (`env -i`) — never implemented             | **Not implemented**           |

**Tradeoff:** Slower startup (~180ms vs ~5ms) but unified codebase and `os.execvp()` efficiency.

---

[← Back to Documentation](../index.md)
