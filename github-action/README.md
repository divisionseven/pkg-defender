# PKG-Defender GitHub Action

**Thin CLI wrapper** for [pkg-defender](https://github.com/divisionseven/pkg-defender) — security audit GitHub Action for package dependencies.

This action is a lightweight wrapper around the `pkgd` CLI. It installs `pkg-defender` via pip, runs `pkgd audit` against your lock files, and reports findings as GitHub Action annotations and outputs.

## Usage

### Basic Usage

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        uses: divisionseven/pkg-defender-action@v1
```

### With Custom Settings

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        uses: divisionseven/pkg-defender-action@v1
        with:
          fail-on: high
          lock-files: "**/package-lock.json,**/yarn.lock"
```

### Full Example with Outputs

```yaml
name: Security Audit
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        id: audit
        uses: divisionseven/pkg-defender-action@v1
        with:
          fail-on: critical
      - name: Get results
        if: always()
        run: |
          echo "Findings: ${{ steps.audit.outputs.findings }}"
          echo "Summary: ${{ steps.audit.outputs.summary }}"
          echo "Exit code: ${{ steps.audit.outputs.exit-code }}"
```

## How It Works

This action is a **thin CLI wrapper** around the `pkgd` CLI. It works as follows:

1. Installs `pkg-defender` via `pip install pkg-defender`
2. Sets up the threat database via `pkgd --ci setup`
3. Resolves your `lock-files` glob pattern using `@actions/glob`
4. Runs `pkgd audit --json --fail-on-threat` for each matched lock file
5. Parses the JSON output and creates GitHub Action annotations
6. Fails the workflow if threats are found (exit code 4)

## Inputs

| Input         | Default                                                                                                             | Description                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `fail-on`     | `high`                                                                                                              | Minimum severity to fail workflow. Options: `critical`, `high`, `medium`, `low`, `none`. CRITICAL and HIGH trigger failure. |
| `ecosystems`  | `npm,pypi,cargo,rubygems`                                                                                           | *(Legacy — not used by wrapper. pkgd auto-detects lock file types.)*                                                        |
| `db-snapshot` | `latest`                                                                                                            | *(Legacy — not used by wrapper. pkgd manages the database.)*                                                                |
| `token`       | `${{ github.token }}`                                                                                               | *(Legacy — not used by wrapper.)*                                                                                           |
| `lock-files`  | `**/package-lock.json,**/yarn.lock,**/pnpm-lock.yaml,**/Pipfile.lock,**/poetry.lock,**/uv.lock,**/requirements.txt` | Glob pattern for lock files to scan.                                                                                        |

## Outputs

| Output      | Description                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------------- |
| `findings`  | JSON array of findings with package, version, ecosystem, severity, and threat details                                       |
| `summary`   | Human-readable summary (e.g., "No security threats found. All packages are safe." or "3 threats found: 1 CRITICAL, 2 HIGH") |
| `exit-code` | Exit code from pkgd audit (0 = success, 4 = threat detected)                                                                |

## Exit Codes

| Code | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| 0    | No threats found, threats below fail-on threshold, or no cooldown-pending packages |
| 4    | Threat detected at or above fail-on threshold                                      |

## Fail-on Behavior

The `fail-on` input controls when the action fails:

- `fail-on: critical` — Fail if CRITICAL or HIGH threats found
- `fail-on: high` — Fail if CRITICAL or HIGH threats found
- `fail-on: medium` — Never fail (output is informational)
- `fail-on: low` — Never fail (output is informational)
- `fail-on: none` — Never fail (output is informational)

The `--fail-on-threat` flag is passed to `pkgd audit` when `fail-on` is `critical` or `high`. This matches the pkg-defender CLI behavior: only CRITICAL and HIGH severity threats trigger failure.

## License

Apache-2.0
