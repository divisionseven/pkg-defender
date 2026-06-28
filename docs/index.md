# PKG-Defender Documentation

## Tutorials

Step-by-step guides for newcomers. Start here if you are new to PKG-Defender.

| Tutorial                                                   | Description                                                            |
| ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Getting Started](tutorials/getting-started.md)            | Install the `pkg-defender` CLI, run your first audit, and verify setup |
| [Your First Interception](tutorials/first-interception.md) | Walk through a live package interception from block to bypass          |

## How-to Guides

Practical, task-oriented guides for specific workflows and integrations.

| Guide                                                    | Description                                                          |
| -------------------------------------------------------- | -------------------------------------------------------------------- |
| [AI Agent Integration](guides/ai-agent-integration.md)   | Configure AI coding agents (Copilot, Cline, etc.) to use pkgd safely |
| [Auditing](guides/auditing.md)                           | Audit lock files and project directories for known threats           |
| [Bypass](guides/bypass.md)                               | Create override bypasses for blocked packages                        |
| [CI/CD](guides/ci-cd.md)                                 | Integrate with GitHub Actions, pre-commit hooks, and CI pipelines    |
| [Daemon](guides/daemon.md)                               | Run the background threat feed sync daemon as a service              |
| [FAQ](guides/faq.md)                                     | Frequently asked questions and answers                               |
| [Intelligence Search](guides/intel-search.md)            | Query the local threat intelligence database                         |
| [Production Deployment](guides/production-deployment.md) | Deploy pkg-defender in production environments                       |
| [Shell Integration](guides/shell-integration.md)         | Set up transparent shell wrappers for automatic interception         |
| [Troubleshooting](guides/troubleshooting.md)             | Diagnose and resolve common issues                                   |

## Reference

Technical lookup documentation covering commands, configuration, data formats, and internals.

| Reference                                                   | Description                                                       |
| ----------------------------------------------------------- | ----------------------------------------------------------------- |
| [CLI](reference/cli.md)                                     | All `pkgd` commands, options, and usage examples                  |
| [Configuration](reference/configuration.md)                 | Full configuration key reference with defaults and descriptions   |
| [Data Dictionary](reference/data-dictionary.md)             | Authoritative catalog of package managers, lock files, and feeds  |
| [Database Schema](reference/database-schema.md)             | SQLite schema, tables, columns, and indexes                       |
| [Environment Variables](reference/environment-variables.md) | All `PKGD_*` environment variable overrides                       |
| [Error Messages](reference/error-messages.md)               | Complete catalog of error messages and their causes               |
| [Exit Codes](reference/exit-codes.md)                       | Standardized exit codes for scripting and integration             |
| [Lock File Formats](reference/lock-file-formats.md)         | Supported lock file formats and their audit characteristics       |
| [Package Managers](reference/package-managers.md)           | Supported package manager coverage and registry details           |
| [Man Page](man/pkgd.1.md)                                   | Command reference in man page format (troff generated via pandoc) |
| [Performance](reference/performance.md)                     | CLI import time, threat check latency, and handoff benchmarks     |
| [Scoring Formula](reference/scoring-formula.md)             | Mathematical breakdown of the threat scoring formula              |
| [Timestamp Resolution](reference/timestamp-resolution.md)   | How publication timestamps are resolved across ecosystems         |
| [Threat Feeds](reference/threat-feeds.md)                   | Threat intelligence feed configuration and management             |

## Explanation

Background, concepts, and design rationale for understanding how `pkg-defender` works.

| Document                                                        | Description                                                           |
| --------------------------------------------------------------- | --------------------------------------------------------------------- |
| [Architecture](explanation/architecture.md)                     | Command wrapper architecture, security boundaries, and design choices |
| [Cooldown System](explanation/cooldown-system.md)               | Cooldown gates, strict mode, and bypass mechanics                     |
| [Interception Lifecycle](explanation/interception-lifecycle.md) | End-to-end flow of a package interception event                       |
| [Scoring](explanation/scoring.md)                               | How threat scores are calculated from multiple intelligence sources   |
| [Security Model](explanation/security-model.md)                 | Threat model, trust boundaries, and security properties               |

## Examples

Ready-to-use configuration files and CI workflow templates.

| Example                                                                                       | Description                                                                              |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Full PKGD Config](examples/config/pkgd.toml)                                                 | Complete `pkgd.toml` with all configuration keys                                         |
| [CI Workflow (Using PKGD CLI)](examples/github-actions/pkg-defender-cli.yml)                  | CI workflow example — using the `pkgd` CLI                                               |
| [CI Workflow (Using PKG-Defender GH Action)](examples/github-actions/pkg-defender-action.yml) | CI workflow example — using the PKG-Defender [GitHub Action](../github-action/README.md) |
| [Pre-commit Hook](examples/pre-commit/.pre-commit-config.yaml)                                | Pre-commit hook configuration for automatic audit before commits                         |

## Project Documentation

Project governance, community guidelines, version history, and component documentation.

| Document                                    | Description                                   |
| ------------------------------------------- | --------------------------------------------- |
| [Contributing](../CONTRIBUTING.md)          | Guidelines for contributing to `pkg-defender` |
| [Security](../SECURITY.md)                  | Security policy and vulnerability reporting   |
| [Code of Conduct](../CODE_OF_CONDUCT.md)    | Code of conduct for the community             |
| [Disclaimer](../DISCLAIMER.md)              | Legal disclaimer and warranty terms           |
| [Authors](../AUTHORS.md)                    | List of project contributors                  |
| [Changelog](../CHANGELOG.md)                | Version history and release notes             |
| [GitHub Action](../github-action/README.md) | GitHub Action for CI/CD integration           |
| [Test Suite](../tests/README.md)            | Test suite structure and running tests        |

---

[← Back to README](../README.md)
