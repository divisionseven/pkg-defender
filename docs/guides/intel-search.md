# Intelligence Search

## Overview

The `pkgd intel` command group provides access to the local threat intelligence
database, which stores threat data synced from multiple intelligence sources.
Use these commands to investigate packages, review the current threat
landscape, and verify whether a blocked package is known to be malicious.

The local database is populated by `pkgd intel sync` and is used by `pkgd
install` and `pkgd audit` when checking packages. Searching this database
directly gives you visibility into what threats are known and why a package may
have been blocked.

**When to search vs. audit:** Use `pkgd intel search` to investigate a specific
package — for example, after an interception to understand why it was blocked.
Use `pkgd audit` to scan your project's lock files for known threats across all
dependencies at once. Search queries the local threat database directly; audit
runs a full project scan.

## Searching for Threats

### Basic Search

Search the local threat database by package name:

```bash
pkgd intel search axios
```

The search uses a `LIKE %query%` pattern match on the package name, so partial
matches work. Searching for `axios` finds `axios`, `axios-ntlm`,
`@types/axios`, and any other package whose name contains the string.

Results are displayed in a table with the following columns:

| Column       | Description                                      |
|--------------|--------------------------------------------------|
| ID           | Unique identifier for the threat record          |
| Ecosystem    | Package ecosystem (npm, pip, cargo, etc.)        |
| Package      | Package name                                     |
| Severity     | Threat severity level                            |
| Source       | Intelligence source that reported the threat     |
| First Seen   | Date the threat was first observed               |

### Filtering by Ecosystem

Restrict the search to a specific package ecosystem:

```bash
pkgd intel search axios --manager npm
```

Valid `--manager` values include `pip`, `npm`, `cargo`, `gem`, `composer`,
and others recognized by the system.

### Excluding Severity Levels

By default, results exclude `UNKNOWN` severity threats. Override this with
`--exclude-severity`:

```bash
# Exclude LOW and UNKNOWN severities
pkgd intel search express --exclude-severity LOW,UNKNOWN

# Include all severities
pkgd intel search express --exclude-severity ""
```

Valid severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.

### JSON Output

For machine-readable output, use the `--output json` or `--json` flag:

```bash
pkgd intel search lodash -o json
pkgd intel search lodash -o json --pretty
```

## Interpreting Results

### Severity Levels

Threats are classified into five severity levels, listed in descending order of
priority:

| Severity   | Meaning                                                       |
|------------|---------------------------------------------------------------|
| CRITICAL   | Immediate action required — active exploitation or wormable   |
| HIGH       | Significant risk — known exploit or broad malicious campaign  |
| MEDIUM     | Moderate risk — limited exploit or potential threat           |
| LOW        | Minimal risk — low-impact or theoretical threat               |
| UNKNOWN    | Severity not assigned by the source                           |

Results are sorted by severity (highest first) and then by date (newest first),
so critical threats always appear at the top.

### Source Provenance

Each result includes the intelligence source that identified the threat. The
source field tells you which feed reported the package, allowing you to assess
the credibility and recency of the report. Multiple sources may report the same
package — cross-referencing across sources increases confidence in the finding.

### First Seen Date

The `First Seen` column shows when a threat was first observed. This helps
distinguish established threats (known for weeks or months) from emerging ones
(recently discovered). Use this alongside the severity level to prioritize
investigations.

## Syncing Threat Intelligence

Threat data must be synced from remote sources before searching. Run:

```bash
pkgd intel sync
```

This downloads the latest threat data from all configured intelligence sources:

- OSV (Open Source Vulnerabilities)
- GitHub Advisory Database (GHSA)
- Socket.dev
- npm Advisory Database
- Homebrew (if installed)
- Mastodon
- Reddit
- RSS feeds
- X/Twitter
- OpenSSF Malicious Packages

Each feed is independently configurable in the `[feeds]` section of the
configuration file. Feeds that are disabled in configuration are skipped during
sync:

```toml
[feeds]
ghsa_enabled = true
socket_enabled = false    # default: false (requires Socket.dev API key)
reddit_enabled = false
```

The sync command shows per-feed results, including the number of new threats
synced and any errors encountered. Run `pkgd intel sync` periodically (daily or
weekly) to keep the local database current. The `pkgd daemon` can automate this
process.

## Threat Reports

The `pkgd intel report` command generates a summary of the current threat
landscape:

```bash
pkgd intel report
```

The report includes:

- **Recent threats:** Packages with new threat entries in the last 7 days
- **Threat overview:** Breakdown of threats by severity level and by
  intelligence source
- **Threat landscape:** Ecosystem-level breakdown over the last 30 days, and
  the most-targeted packages across all ecosystems

Filter the report by ecosystem or severity:

```bash
pkgd intel report --manager npm
pkgd intel report --exclude-severity LOW,UNKNOWN
pkgd intel report -o json
```

## Feed Health

`pkgd status` always shows the Intelligence Feed Health table, which displays
the operational status of each configured feed including whether it is enabled,
the last successful sync time, connection health, and any configuration issues.

```bash
pkgd status
```

Adding `--feeds` includes an additional Audit Sources section showing feeds that
run at audit time (such as `npm_advisory`):

```bash
pkgd status --feeds
```

Use these commands when a sync reports errors or when feeds appear to be
returning no data.
