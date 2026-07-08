<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_transparent.svg">
  <img src="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_fill.svg" width="300" alt="pkg-defender logo">
</picture>

<h1>Threat Intelligence Snapshot</h1>
<p><em>Build Time: $build_time</em></p>
<p><strong>PKG-Defender (PKGD) v$pkgd_version</strong></p>

</div>

## What Is This?

This *"snapshot"* is a pre-built, machine-readable **threat intelligence database** for the open-source package ecosystem, published fresh every 6 hours under the `snapshot-latest` tag. It aggregates known-malicious packages from multiple data sources, curated automatically by the [PKG-Defender](https://github.com/divisionseven/pkg-defender) project. On each scheduled run, the previous snapshot release is automatically deleted and replaced by the latest published version under the `snapshot-latest` tag. This ensures users can never accidentally retrieve stale data.

**Why this matters:** Malicious package attacks (typosquatting, dependency confusion, protestware, credential theft) are on the rise. Fresh threat intelligence is critical for effective detection. This snapshot updates **every 6 hours**, ensuring your security tooling has the latest data — not last week's.

**Who should use this:** Security engineers, DevOps teams, platform maintainers, and anyone running automated package risk analysis. Download and use it with `pkgd` CLI, integrate it into your CI/CD pipelines, or consume the raw database directly.

## Latest Snapshot — General Stats

| Metric | Value |
| :--- | :--- |
| **Total known threats** | `$threat_count` |
| **Ecosystems covered** | `$ecosystem_count` |
| **Compressed database size** | `$db_size_compressed` |
| **SHA-256 checksum** | `$sha256` |

## Latest Snapshot — Ecosystem Breakdown

| Ecosystem | Threats |
| :--- | ---: |
$ecosystem_breakdown

## Latest Snapshot — Data Sources

| Source | Records |
| :--- | ---: |
$source_breakdown

---

## How to Use a Snapshot

### Download the Latest Snapshot

```bash
pkgd db snapshot --download
```

This pulls the latest `threats-latest.db.gz` and its checksum, verifies integrity, and makes the database available for local queries.

### List Available Snapshots

```bash
pkgd db snapshot --latest
```

Shows metadata for the most recent snapshot — build time, threat count, checksum, and file size — without downloading.

### Verify a Snapshot

```bash
pkgd db snapshot --verify
```

Checks the SHA-256 hash of your local database against the published checksum to confirm it hasn't been tampered with or corrupted.

---

## Learn More

| Resource | Link |
| :--- | :--- |
| **CLI Reference** | [Snapshot CLI Documentation (pkgd db) &rarr;](https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/cli.md#pkgd-db-snapshot) |
| **CI/CD Guide** | [Integrating Threat Snapshots Into Pipelines &rarr;](https://github.com/divisionseven/pkg-defender/blob/main/docs/guides/ci-cd.md#database-snapshots) |
| **Getting Started** | [PKG-Defender Quickstart &rarr;](https://github.com/divisionseven/pkg-defender/blob/main/docs/guides/getting-started.md) |
| **Architecture** | [Snapshot System Design &rarr;](https://github.com/divisionseven/pkg-defender/blob/main/docs/explanation/architecture.md) |
| **Report an Issue** | [File a Bug or Feature Request &rarr;](https://github.com/divisionseven/pkg-defender/issues) |

---

*This release was generated automatically by the PKG-Defender Snapshot workflow. For questions or feedback, please [open an issue](https://github.com/divisionseven/pkg-defender/issues). Thank you for supporting PKG-Defender.*

*— Division 7*
