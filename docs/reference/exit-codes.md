# Exit Codes

All exit codes are defined as constants in `src/pkg_defender/cli/_exit_codes.py`. Every command in the CLI exits with one of these standard codes, enabling predictable scripting and integration.

## Exit Code Reference

| Code | Constant Name               | Meaning                          | When It Occurs                                                                                                              | What the User Sees                                                                                                                                                                                                | Classification |
| ---- | --------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| 0    | `EXIT_SUCCESS`              | Success                          | Command completed successfully                                                                                              | Green success message, command output printed normally                                                                                                                                                            | ALLOW          |
| 1    | `EXIT_GENERAL_ERROR`        | General error                    | Any unspecified error; used across 30 locations for exec failures, config errors, database errors, daemon errors, and more  | Error message printed to stderr with `Error:` prefix                                                                                                                                                              | ERROR          |
| 2    | `EXIT_USAGE_ERROR`          | Invalid arguments or usage error | Invalid CLI arguments (audit, setup, bypass commands)                                                                       | Usage/help text printed to stderr, `Usage:` or `Error: Invalid` message                                                                                                                                           | ERROR          |
| 3    | `EXIT_COOLDOWN`             | Package in cooldown period       | A package version is in cooldown and blocked, or timestamp resolution failed (see `resolution_attempts` for failure reason) | Bold red `[PKGD]` plain-text block printed to stderr showing package name, cooldown window, and optionally remaining cooldown days or resolution failure diagnostic                                               | BLOCK          |
| 4    | `EXIT_THREAT_DETECTED`      | Threat or vulnerability detected | A threat or vulnerability was found and blocked                                                                             | Bold red `[PKGD]` plain-text block printed to stderr. Basic output shows package name and bypass instructions. Use `--explain` for detailed output including severity, source, score, summary, and reference URLs | BLOCK          |
| 5    | `EXIT_REGISTRY_UNREACHABLE` | Registry or network unreachable  | Cannot reach package registry or network                                                                                    | "Registry unreachable" error to stderr                                                                                                                                                                            | ERROR          |
| 6    | `EXIT_CONFIG_ERROR`         | Configuration error              | Invalid configuration                                                                                                       | Configuration error details to stderr                                                                                                                                                                             | ERROR          |
| 7    | `EXIT_DB_ERROR`             | Database error                   | Database operation failed                                                                                                   | Database error details to stderr                                                                                                                                                                                  | ERROR          |
| 8    | `EXIT_PARTIAL_FAILURE`      | Setup completed with warnings    | Setup completed but with warnings or partial failures                                                                       | Warning message printed to stderr, but command partially completes with output to stdout                                                                                                                          | PARTIAL        |
| 130  | `EXIT_SIGINT`               | Interrupted by signal (SIGINT)   | User pressed Ctrl+C or the process received SIGINT                                                                          | Process stops mid-output, no error panel (SIGINT behaviour)                                                                                                                                                       | SIGNAL         |

## Exit Code Ranges

Exit codes are organised into logical ranges:

| Range | Category                      |
| ----- | ----------------------------- |
| 0     | Success                       |
| 1–2   | General and usage errors      |
| 3–4   | Blocking and security-related |
| 5–8   | Operational errors            |
| 130   | Signal interruption           |

## Blocking Behaviour

Exit codes 3 (`EXIT_COOLDOWN`) and 4 (`EXIT_THREAT_DETECTED`) represent blocking outcomes in the tool's fail-closed security model. When either of these codes is returned, the requested operation (typically a package installation) has been prevented, and no package modification has occurred.

## CI/CD Handling

When integrating `pkgd` into CI/CD pipelines, each exit code should be handled according to its severity:

| Code | CI/CD Action       | Notes                                                                                      |
| ---- | ------------------ | ------------------------------------------------------------------------------------------ |
| 0    | ✅ Pass             | Command completed successfully                                                             |
| 1    | ❌ Fail             | Unexpected error — investigate logs                                                        |
| 2    | ❌ Fail             | Fix CLI arguments or usage                                                                 |
| 3    | ❌ Fail             | Package blocked by cooldown — investigate whether cooldown is expected or needs adjustment |
| 4    | ❌❌ Fail with alert | Threat or vulnerability detected — treat as a security incident                            |
| 5    | ⚠️ Retry or fail    | Network issue — consider retry logic for transient failures                                |
| 6    | ❌ Fail             | Fix configuration and re-run                                                               |
| 7    | ⚠️ Retry or fail    | Transient database issue — retry may resolve; persistent failures require investigation    |
| 8    | ⚠️ Warning          | Setup completed with warnings — manual verification recommended                            |
| 130  | ⚠️ Cancelled        | Process interrupted by user or signal — not a pipeline failure                             |

Pipelines should use `--fail-on-threat` for stricter enforcement of blocking exit codes, or `--bypass-cooldown` / `--bypass-threat` (with caution) to allow packages that would otherwise be blocked.

## See Also

- [Security Model](../explanation/security-model.md) — detailed explanation of fail-closed behaviour and what actions trigger each blocking exit code
