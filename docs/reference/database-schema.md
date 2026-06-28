# Database Schema

The database is a single-file SQLite store managed by `pkg_defender.db.schema`. All
tables use `CREATE TABLE IF NOT EXISTS` for idempotent initialization. The schema
is defined as a single `SCHEMA_SQL` constant evaluated at import time.

- **Number of tables:** 9
- **Database engine:** SQLite 3

**Source of truth:** See the [Data Dictionary](../reference/data-dictionary.md) for authoritative code-generated counts and cross-references.

## threats

Core threat intelligence records ingested from configured feeds. Each row
represents a single threat identified by a unique `{source}:{source_id}` key.

| Column              | Type    | Constraints                                                                    |
| ------------------- | ------- | ------------------------------------------------------------------------------ |
| `id`                | TEXT    | `PRIMARY KEY`                                                                  |
| `ecosystem`         | TEXT    | `NOT NULL` — `CHECK(ecosystem IN (...))`                                       |
| `package_name`      | TEXT    | `NOT NULL`                                                                     |
| `affected_versions` | TEXT    | `NOT NULL DEFAULT '[]'` — JSON array of version strings                        |
| `affected_ranges`   | TEXT    | `NOT NULL DEFAULT '[]'` — JSON array of version range specifiers               |
| `severity`          | TEXT    | `NOT NULL` — `CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'))` |
| `confidence`        | REAL    | `NOT NULL` — `CHECK(confidence >= 0.0 AND confidence <= 1.0)`                  |
| `source`            | TEXT    | `NOT NULL` — `CHECK(source IN (...))`                                          |
| `source_id`         | TEXT    | —                                                                              |
| `summary`           | TEXT    | `NOT NULL DEFAULT ''`                                                          |
| `detail_url`        | TEXT    | —                                                                              |
| `first_seen`        | TEXT    | `NOT NULL DEFAULT (datetime('now'))`                                           |
| `last_seen`         | TEXT    | `NOT NULL DEFAULT (datetime('now'))`                                           |
| `hit_count`         | INTEGER | `NOT NULL DEFAULT 1` — `CHECK(hit_count >= 1)`                                 |
| `cvss_score`        | REAL    | `CHECK(cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0))`      |
| `published_at`      | TEXT    | —                                                                              |
| `ingested_at`       | TEXT    | `NOT NULL DEFAULT (datetime('now'))`                                           |
| `is_malicious`      | INTEGER | `NOT NULL DEFAULT 0` — `CHECK(is_malicious IN (0, 1))`                         |
| `is_unverified`     | INTEGER | `NOT NULL DEFAULT 0` — `CHECK(is_unverified IN (0, 1))`                        |
| `updated_at`        | TEXT    | `NOT NULL DEFAULT (datetime('now'))`                                           |

### Indexes

| Index Name                       | Columns                   | Condition                        |
| -------------------------------- | ------------------------- | -------------------------------- |
| `idx_threats_ecosystem_package`  | `ecosystem, package_name` | —                                |
| `idx_threats_first_seen`         | `first_seen`              | —                                |
| `idx_threats_published`          | `published_at`            | —                                |
| `idx_threats_ecosystem_null_pkg` | `ecosystem`               | `WHERE package_name = 'unknown'` |
| `idx_threats_source_id`          | `source_id`               | —                                |
| `idx_threats_last_seen`          | `last_seen`               | —                                |

### Notes

- `affected_versions` and `affected_ranges` are JSON-encoded lists, deserialised
  in application code via `json.loads()` in `_row_to_threat()`.
- The composite index on `(ecosystem, package_name)` supports the most common
  query pattern: looking up all threats for a given ecosystem and package
  (including ecosystem-wide threats where `package_name = 'unknown'`).

---

## version_timestamps

Cached package version publish timestamps used for cooldown calculations and
freshness checks.

| Column           | Type    | Constraints                                                                                       |
| ---------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `ecosystem`      | TEXT    | `NOT NULL` — `CHECK(ecosystem IN (...))`                                                          |
| `package_name`   | TEXT    | `NOT NULL`                                                                                        |
| `version`        | TEXT    | `NOT NULL`                                                                                        |
| `publish_time`   | TEXT    | `NOT NULL` — `CHECK(publish_time GLOB '????-??-??T*:*:*Z')`                                       |
| `source_label`   | TEXT    | `NOT NULL DEFAULT ''`                                                                             |
| `trust_level`    | TEXT    | `NOT NULL DEFAULT 'unknown'` — `CHECK(trust_level IN ('verified','proxied','claimed','unknown'))` |
| `precision`      | TEXT    | `NOT NULL DEFAULT 'second'` — `CHECK(precision IN ('microsecond','second','day','unknown'))`      |
| `resolved_at`    | TEXT    | `NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))`                                        |
| `cache_ttl_days` | INTEGER | `NOT NULL DEFAULT 7`                                                                              |

- **Primary key:** `(ecosystem, package_name, version)` (composite)

### Notes

- `trust_level` is derived from the `date_source` field of `VersionInfo` at
  insert time via `SOURCE_TRUST_MAP` — the canonical 18-entry mapping defined
  in `db/schema.py`. Groups sources into 4 tiers:
  - `"verified"` → first-party API, authoritative (e.g., `registry_api`, `bodhi`, `snapshot_debian`)
  - `"proxied"` → mirror/build-system, best-effort (e.g., `koji`, `repodata`)
  - `"claimed"` → third-party / self-reported, use with caution (e.g., `registry`, `github_releases`, `github_tags`, `libraries_io`)
  - `"unknown"` → no source information (`cache`)
- `source_label` stores the raw `date_source` string verbatim (e.g., `"pypi"`,
  `"github_tags"`, `"bodhi"`) and is used for user-facing display via
  `_format_source_label()`.
- `precision` is inferred from the datetime's microsecond field at write time
  via `classify_precision()`.
- `cache_ttl_days` is set from `TRUST_TTL_MAP` based on the computed trust
  level — entries older than this should be refreshed from the original source.
- `publish_time` is stored as `Z`-suffixed ISO 8601 UTC (enforced by CHECK
  constraint) for unambiguous timezone handling.
- No separate indexes are needed because the composite primary key already
  covers the primary lookup pattern.

---

## resolution_attempts

Records timestamp resolution attempts for package versions, including both
successful and failed lookups. Used for cooldown diagnostics when the
`version_timestamps` table has no entry for a package version.

| Column              | Type | Constraints                                                                   |
| ------------------- | ---- | ----------------------------------------------------------------------------- |
| `ecosystem`         | TEXT | `NOT NULL` — `CHECK(ecosystem IN (...))`                                      |
| `package_name`      | TEXT | `NOT NULL`                                                                    |
| `version`           | TEXT | `NOT NULL`                                                                    |
| `publish_time`      | TEXT | `CHECK(publish_time IS NULL OR publish_time GLOB '????-??-??T*:*:*Z')`        |
| `resolution_status` | TEXT | `NOT NULL DEFAULT 'all_sources_failed'` — `CHECK(resolution_status IN (...))` |
| `source_label`      | TEXT | `NOT NULL DEFAULT ''`                                                         |
| `last_error`        | TEXT | —                                                                             |
| `attempted_at`      | TEXT | `NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))`                    |
| `retry_after`       | TEXT | —                                                                             |

- **Primary key:** `(ecosystem, package_name, version)` (composite)

### Indexes

| Index Name                       | Columns             | Condition                               |
| -------------------------------- | ------------------- | --------------------------------------- |
| `idx_resolution_attempts_status` | `resolution_status` | —                                       |
| `idx_resolution_attempts_retry`  | `retry_after`       | `WHERE resolution_status != 'resolved'` |

### Notes

- `resolution_status` is validated in application code as one of:
  `"resolved"`, `"all_sources_failed"`, `"no_github_url"`, `"rate_limited"`,
  `"timeout"`, `"network_error"`, `"not_found"`, `"server_error"`,
  `"unknown_error"`.
- `publish_time` is `NULL` when resolution failed. On success, the timestamp
  is also written to `version_timestamps` (the primary lookup table).
- `retry_after` is set for transient failures (e.g., rate limiting) so the
  daemon can schedule retries.

---

## bypasses

Audit log for bypass decisions made by users or automated rules. Every bypass
is recorded with a reason, user attribution, and optional expiration.

| Column             | Type    | Constraints                                 |
| ------------------ | ------- | ------------------------------------------- |
| `id`               | INTEGER | `PRIMARY KEY AUTOINCREMENT`                 |
| `ecosystem`        | TEXT    | `NOT NULL` — `CHECK(ecosystem IN (...))`    |
| `package_name`     | TEXT    | `NOT NULL`                                  |
| `version`          | TEXT    | `NOT NULL`                                  |
| `threat_id`        | TEXT    | `REFERENCES threats(id) ON DELETE SET NULL` |
| `reason`           | TEXT    | `NOT NULL DEFAULT ''`                       |
| `bypassed_at`      | TEXT    | `NOT NULL DEFAULT (datetime('now'))`        |
| `user`             | TEXT    | `NOT NULL DEFAULT ''`                       |
| `expires_at`       | TEXT    | —                                           |
| `checks_performed` | TEXT    | `NOT NULL DEFAULT 'bypassed'`               |

### Indexes

| Index Name                       | Columns                   | Condition |
| -------------------------------- | ------------------------- | --------- |
| `idx_bypasses_ecosystem_package` | `ecosystem, package_name` | —         |
| `idx_bypasses_threat_id`         | `threat_id`               | —         |
| `idx_bypasses_expires_at`        | `expires_at`              | —         |

### Notes

- `threat_id` is a foreign key to `threats(id)` with `ON DELETE SET NULL` —
  deleting a threat sets the corresponding `threat_id` in related bypass
  records to `NULL` rather than cascading the deletion.
- `checks_performed` is validated in application code as one of:
  `"none"`, `"threat_only"`, `"cooldown_only"`, `"full"`, `"bypassed"`.

---

## feed_state

Tracks the current sync status and pagination state for each threat
intelligence feed.

| Column          | Type | Constraints                                                                                                          |
| --------------- | ---- | -------------------------------------------------------------------------------------------------------------------- |
| `feed_name`     | TEXT | `PRIMARY KEY`                                                                                                        |
| `last_sync`     | TEXT | —                                                                                                                    |
| `cursor`        | TEXT | —                                                                                                                    |
| `status`        | TEXT | `NOT NULL DEFAULT 'idle'` — `CHECK(status IN ('idle','syncing','error','disabled','not_configured','circuit_open'))` |
| `error_message` | TEXT | —                                                                                                                    |
| `updated_at`    | TEXT | `NOT NULL DEFAULT (datetime('now'))`                                                                                 |

### Notes

- Each feed has exactly one row. The primary key is `feed_name`, so
  `INSERT OR REPLACE` is used to upsert state.
- The `status` column supports a state machine: `idle` → `syncing` →
  `idle` (success) or `error` (failure). `disabled` and `not_configured`
  are terminal states set by configuration.

---

## feed_stats

Historical snapshots of feed sync results. Used for monitoring feed health
and detecting anomalies.

| Column           | Type    | Constraints                          |
| ---------------- | ------- | ------------------------------------ |
| `feed_name`      | TEXT    | `NOT NULL`                           |
| `synced_at`      | TEXT    | `NOT NULL DEFAULT (datetime('now'))` |
| `record_count`   | INTEGER | `NOT NULL DEFAULT 0`                 |
| `avg_confidence` | REAL    | —                                    |
| `skipped_count`  | INTEGER | `NOT NULL DEFAULT 0`                 |

- **Primary key:** `(feed_name, synced_at)` (composite)

### Indexes

| Index Name              | Columns                     | Condition |
| ----------------------- | --------------------------- | --------- |
| `idx_feed_stats_lookup` | `feed_name, synced_at DESC` | —         |

### Notes

- The application prunes old statistics on insert, keeping only the 30 most
  recent entries per feed (`DELETE` via `OFFSET 30` in `insert_feed_stats()`).
- `avg_confidence` is `NULL` when `record_count` is 0.
- `skipped_count` tracks the number of threat records that failed validation
  and were silently skipped during that sync. A non-zero value indicates
  data quality issues at the feed source or misconfigured ecosystems.
  A warning is logged at sync time when records are skipped.

---

## db_metadata

Generic key-value store for database-level metadata such as the current schema
version for snapshot validation.

| Column       | Type | Constraints                          |
| ------------ | ---- | ------------------------------------ |
| `key`        | TEXT | `PRIMARY KEY`                        |
| `value`      | TEXT | `NOT NULL`                           |
| `updated_at` | TEXT | `NOT NULL DEFAULT (datetime('now'))` |

### Notes

- Metadata is written and read via the `set_metadata()` and `get_metadata()`
  helpers in `pkg_defender.db.schema`.
- Application code uses `get_metadata()` and `set_metadata()` helpers in
  `pkg_defender.db.schema` for access.

---

## schema_version

Tracks the database schema version. Each row records a schema version that
has been applied to this database. Used by `migrate_db()` for version checking
and by `pkgd db verify` for display.

| Column       | Type    | Constraints                          |
| ------------ | ------- | ------------------------------------ |
| `version`    | INTEGER | `PRIMARY KEY`                        |
| `applied_at` | TEXT    | `NOT NULL DEFAULT (datetime('now'))` |

### Notes

- A fresh database gets a single row with `version = 1` and the current
  timestamp.
- `migrate_db()` reads the highest version from this table to determine
  whether migrations are needed. If the stored version exceeds
  `CURRENT_SCHEMA_VERSION`, a downgrade `RuntimeError` is raised.
- This table replaces the PRAGMA-based versioning (`PRAGMA user_version`)
  that was previously used. The table is queryable via standard SQL and
  appears in `pkgd db verify` output.

---

## audit_events

Records every CLI command invocation that goes through the audit pipeline.
This is the most column-rich table and supports filtering-based queries for
reporting and observability.

| Column                    | Type    | Constraints                                                                                  |
| ------------------------- | ------- | -------------------------------------------------------------------------------------------- |
| `id`                      | INTEGER | `PRIMARY KEY AUTOINCREMENT`                                                                  |
| `timestamp`               | TEXT    | `NOT NULL DEFAULT (datetime('now'))`                                                         |
| `ecosystem`               | TEXT    | `NOT NULL` — `CHECK(ecosystem IN (...))`                                                     |
| `package_name`            | TEXT    | `NOT NULL`                                                                                   |
| `version`                 | TEXT    | —                                                                                            |
| `action`                  | TEXT    | `NOT NULL` — `CHECK(action IN ('install','update','upgrade','reinstall','execute','fetch'))` |
| `risk_level`              | TEXT    | `NOT NULL` — `CHECK(risk_level IN ('critical','important','watch'))`                         |
| `source`                  | TEXT    | `NOT NULL` — `CHECK(source IN ('shell_hook','cli','api','cron','test'))`                     |
| `manager`                 | TEXT    | `NOT NULL` — `CHECK(manager IN (...))`                                                       |
| `subcommand`              | TEXT    | —                                                                                            |
| `verdict`                 | TEXT    | `NOT NULL` — `CHECK(verdict IN ('PASS','PARTIAL_PASS','FAIL','BLOCKED','WARN','ERROR'))`     |
| `exit_code`               | INTEGER | `NOT NULL` — `CHECK(exit_code >= 0 AND exit_code <= 255)`                                    |
| `error_message`           | TEXT    | —                                                                                            |
| `threat_count_general`    | INTEGER | `NOT NULL DEFAULT 0` — `CHECK(threat_count_general >= 0)`                                    |
| `threat_count_versioned`  | INTEGER | `NOT NULL DEFAULT 0` — `CHECK(threat_count_versioned >= 0)`                                  |
| `cooldown_pass`           | INTEGER | `NOT NULL DEFAULT 1` — `CHECK(cooldown_pass IN (0, 1))`                                      |
| `cooldown_days_remaining` | INTEGER | `NOT NULL DEFAULT 0`                                                                         |
| `ci_mode`                 | INTEGER | `NOT NULL DEFAULT 0` — `CHECK(ci_mode IN (0, 1))`                                            |
| `runtime_ms`              | INTEGER | `CHECK(runtime_ms IS NULL OR runtime_ms >= 0)`                                               |
| `user`                    | TEXT    | —                                                                                            |
| `session_id`              | TEXT    | —                                                                                            |
| `fail_on_threat_enabled`  | INTEGER | `NOT NULL DEFAULT 1` — `CHECK(fail_on_threat_enabled IN (0, 1))`                             |
| `cooldown_enabled`        | INTEGER | `NOT NULL DEFAULT 1` — `CHECK(cooldown_enabled IN (0, 1))`                                   |
| `coverage_tier`           | TEXT    | `NOT NULL DEFAULT 'full'`                                                                    |

### Indexes

| Index Name                           | Columns                   | Condition |
| ------------------------------------ | ------------------------- | --------- |
| `idx_audit_events_timestamp`         | `timestamp`               | —         |
| `idx_audit_events_ecosystem_package` | `ecosystem, package_name` | —         |
| `idx_audit_events_verdict`           | `verdict`                 | —         |
| `idx_audit_events_source`            | `source`                  | —         |
| `idx_audit_events_session`           | `session_id`              | —         |

---

## Indexes Summary

All database indexes, grouped by table:

| Table                 | Index Name                           | Columns                     | Partial                                       |
| --------------------- | ------------------------------------ | --------------------------- | --------------------------------------------- |
| `threats`             | `idx_threats_ecosystem_package`      | `ecosystem, package_name`   | No                                            |
| `threats`             | `idx_threats_first_seen`             | `first_seen`                | No                                            |
| `threats`             | `idx_threats_published`              | `published_at`              | No                                            |
| `threats`             | `idx_threats_ecosystem_null_pkg`     | `ecosystem`                 | Yes (`WHERE package_name = 'unknown'`)        |
| `threats`             | `idx_threats_source_id`              | `source_id`                 | No                                            |
| `threats`             | `idx_threats_last_seen`              | `last_seen`                 | No                                            |
| `bypasses`            | `idx_bypasses_ecosystem_package`     | `ecosystem, package_name`   | No                                            |
| `bypasses`            | `idx_bypasses_threat_id`             | `threat_id`                 | No                                            |
| `bypasses`            | `idx_bypasses_expires_at`            | `expires_at`                | No                                            |
| `feed_stats`          | `idx_feed_stats_lookup`              | `feed_name, synced_at DESC` | No                                            |
| `audit_events`        | `idx_audit_events_timestamp`         | `timestamp`                 | No                                            |
| `audit_events`        | `idx_audit_events_ecosystem_package` | `ecosystem, package_name`   | No                                            |
| `audit_events`        | `idx_audit_events_verdict`           | `verdict`                   | No                                            |
| `audit_events`        | `idx_audit_events_source`            | `source`                    | No                                            |
| `audit_events`        | `idx_audit_events_session`           | `session_id`                | No                                            |
| `resolution_attempts` | `idx_resolution_attempts_status`     | `resolution_status`         | No                                            |
| `resolution_attempts` | `idx_resolution_attempts_retry`      | `retry_after`               | Yes (`WHERE resolution_status != 'resolved'`) |

**Total indexes: 17** (across 5 of 9 tables; `version_timestamps`, `feed_state`,
`db_metadata`, and `schema_version` have no secondary indexes).
