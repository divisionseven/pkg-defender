# Auditing

Scan project lock files for known threats and cooldown-pending packages.

## Multi-Lock-File Scanning

`pkgd audit` recursively discovers all recognised lock files in the target
directory. Every lock file found is parsed and its packages checked against
the threat database. Each result entry is tagged with the lock file it came
from, visible in the **Source** column of the terminal table and the
`lock_file` field of JSON and CSV output.

## Supported Lock File Formats

`pkgd audit` auto-detects the lock file format from the filename:

| Lock File           | Ecosystem | Format       |
| ------------------- | --------- | ------------ |
| `package-lock.json` | npm       | JSON (v2/v3) |
| `yarn.lock`         | npm       | custom text  |
| `pnpm-lock.yaml`    | npm       | YAML         |
| `poetry.lock`       | pypi      | TOML         |
| `requirements.txt`  | pypi      | Plain text   |
| `Pipfile.lock`      | pypi      | JSON         |
| `uv.lock`           | pypi      | TOML         |

## Basic Usage

```bash
pkgd audit                           # audit current directory
pkgd audit /path/to/project          # audit specific project
```

## Output Formats

```bash
pkgd audit --output rich             # colored terminal output (default)
pkgd audit --output json             # machine-readable JSON
pkgd audit --output json --pretty   # pretty-printed JSON
pkgd audit --output csv              # CSV for spreadsheets/pipelines
```

> **Note:** The `--json` flag is a convenience alias for `--output json`.

## Deep Audit

Include cooldown status checks for each package:

```bash
pkgd audit --deep
```

Without `--deep`, only threat database matches are checked. With `--deep`, each package is also checked against the cooldown engine.

## Time Filtering

Filter threats seen within a specific duration:

```bash
pkgd audit --since 7d                # threats seen in the last 7 days
pkgd audit --since 24h               # threats seen in the last 24 hours
```

> **Note:** `--since` only filters threat entries. Cooldown-pending entries are unaffected — they remain in the output regardless of the time window.

## CI/CD Integration

### Fail on Threats

```bash
pkgd audit --fail-on-threat
```

Exits with code 4 (`EXIT_THREAT_DETECTED`) under any of these conditions:

- **`--fail-on-threat`** with CRITICAL or HIGH severity threats found (the explicit flag).
- **`strict_mode` enabled** in configuration with any threat count > 0.
- **Any cooldown-pending packages** exist in the audit result (cooldown always triggers exit 4).

Social feed entries (LOW severity) and LOW/MEDIUM structured threats do **not** cause a non-zero exit from `--fail-on-threat` alone, though they may trigger exit 4 through `strict_mode`.

The `--fail-on-threat` flag is **enabled by default** via the `fail_on_threat_enabled` config option. Set `fail_on_threat_enabled = false` in `pkgd.toml` to disable it.

### Registry Unreachable

If the threat registry is unreachable during an audit, `pkgd` exits with code 5 (`EXIT_REGISTRY_UNREACHABLE`). This typically indicates a network connectivity issue. Check your connection and try again.

### GitHub Actions Example

```yaml
- name: Audit dependencies
  run: |
    uv pip install pkg-defender
    pkgd audit --fail-on-threat --output json
```

### Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: pkg-defender-audit
      name: Audit dependencies
      entry: pkgd audit --fail-on-threat
      language: system
      pass_filenames: false
      files: (package-lock\.json|poetry\.lock|requirements\.txt|yarn\.lock|pnpm-lock\.yaml|uv\.lock|Pipfile\.lock)$
```

## Interpreting Output

### Rich Output

Threats are displayed in severity-colored panels:
- **CRITICAL** — Bold Red
- **HIGH** — Red
- **MEDIUM** — Yellow
- **LOW** — Blue
- **UNKNOWN** — Dim (typically social feed entries)

The table has five columns:

| Column  | Description                                                                                               |
| ------- | --------------------------------------------------------------------------------------------------------- |
| Package | Name of the affected package                                                                              |
| Version | Version string found in the lock file                                                                     |
| Source  | Lock file the package came from (dim, e.g. `package-lock.json`)                                           |
| Status  | Severity badge (coloured) or `Cooldown` / `OK`                                                            |
| Details | Multiline block with source badges, severity, summary, version match info, published date, and detail URL |

### JSON Output

Machine-readable output suitable for pipeline consumption:

```json
{
  "lock_file": "package-lock.json, requirements.txt",
  "total": 42,
  "threats": [
    {
      "package": "lodash",
      "version": "4.17.20",
      "ecosystem": "npm",
      "lock_file": "package-lock.json",
      "severity": "HIGH",
      "threats": [
        {
          "severity": "HIGH",
          "summary": "Prototype Pollution in lodash",
          "source": "structured",
          "source_id": "GHSA-xxx-xxx-xxx",
          "published_at": "2026-06-01T00:00:00+00:00",
          "version_match_type": "exact",
          "detail_url": "https://github.com/advisories/GHSA-xxx-xxx-xxx"
        }
      ]
    },
    {
      "package": "requests",
      "version": "2.25.0",
      "ecosystem": "pypi",
      "lock_file": "requirements.txt",
      "severity": "LOW",
      "threats": [
        {
          "severity": "LOW",
          "summary": "Reported as potentially suspicious",
          "source": "social",
          "source_id": null,
          "published_at": null,
          "version_match_type": "package_wide",
          "detail_url": null
        }
      ]
    }
  ],
  "cooldown_pending": [
    {
      "package": "axios",
      "version": "0.21.1",
      "ecosystem": "npm",
      "lock_file": "package-lock.json",
      "age_seconds": 172800,
      "clears_at": "2026-06-06T14:30:00+00:00"
    }
  ]
}
```

### CSV Output

Tabular output for spreadsheet or pipeline consumption with 9 columns:

```
package, version, ecosystem, lock_file, severity, source, published_at, version_match_type, summary
```

Threat rows use the threat's severity, source, and version match type. The `lock_file` column identifies which lock file the package came from. `published_at` is the threat advisory publication date (empty for cooldown rows). `version_match_type` is one of `exact`, `range`, or `package_wide`.

Cooldown-pending packages appear as additional rows with `COOLDOWN` as severity, `cooldown` as source, and the clears-at timestamp in the summary column.

---

[← Back to Documentation](../index.md)
