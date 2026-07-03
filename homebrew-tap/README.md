<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_transparent.svg">
    <img src="https://raw.githubusercontent.com/divisionseven/pkg-defender/main/docs/assets/brand/logo/pkgd_logo_fill.svg" alt="pkg-defender" width="500">
  </picture>

# PKG-Defender (PKGD) — Homebrew Tap

### Stop supply chain attacks *before* they reach your machine or CI pipeline

[![License][license-badge-icon]][license-badge-link]
[![Python][python-badge-icon]][pypi-badge-link]
[![Binary][github-binary-releases-badge]][github-binary-releases-link]
[![Snapshot][github-snapshot-releases-badge]][github-snapshot-releases-link]
[![Codecov][codecov-badge-icon]][codecov-badge-link]
[![Build][ci-badge-icon]][ci-badge-link]

[![Ecosystems][ecosystems-badge-icon]][ecosystems-badge-link]
[![Systems][systems-badge-icon]][ecosystems-badge-link]
[![Platforms][platforms-badge-icon]][platforms-badge-link]

</div>

## PKGD Highlights

> **The supply chain attack defense CLI — Cooldown gates, multi-source threat
> intelligence, command wrappers, CI/CD interception, and lock file dependency
> auditing for all major package managers.**

- **Unified Command Wrapper**: `pkgd [OPTIONS] MANAGER SUBCOMMAND [PACKAGE...] [MANAGER_OPTIONS...]`
  - Wrap any [supported][supported-commands] *"dangerous"* package manager
    command (`pkgd pip install requests`, `pkgd npm install express`,
    `pkgd brew upgrade tree`, etc.)
  - *"Dangerous Commands"* are defined as any package manager command that has
    the potential to put software **on** your machine (`install`, `update`,
    `download`, `add`, `sync`, etc.)
- **Auto-Detect Manager**: automatically detects package manager from project
  files or system packages
- **Version Detection**: `get_installed_version()` for all 18 package managers
  across 10 ecosystems enables version comparison
- **Fail-Closed Security**: any failure blocks installation with warning and
  options for informed manual override
- **Alternative PM Coverage**: `python -m pip`, `pipx`, `yarn`, `pnpm` and other
  alt manager calls all [supported][supported-commands]
- **Cooldown Gates**: configurable time-since-release hold window with
  per-package, tracked and auditable overrides (ships with a default of 7
  days)
- **Multi-source Threat Intelligence**: OSV.dev, GHSA, Socket.dev, npm
  advisories, and more all synced and stored locally (with automatic staleness
  detection)
- **Social Intelligence Feeds**: Mastodon, Reddit, RSS, X/Twitter - free sources
  shipped / B.Y.O.K. options available (informational only — non-blocking)
- **Lock File Auditing**: all major formats: `package-lock.json`, `poetry.lock`,
  `requirements.txt`, `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `Pipfile.lock`
  ([currently supported formats][targeted-managers])
- **Background Daemon**: automated background intelligence feed sync with
  OS-native launchd / systemd / Task Scheduler
- **CI/CD Integration**: `--fail-on-threat` exits on CRITICAL/HIGH for secure
  pipeline gating

[Full Documentation Index &rarr;][docs-index]

## PKG-Defender Homebrew Tap

Homebrew tap for [PKG-Defender (PKGD)](https://github.com/divisionseven/pkg-defender) — the supply chain attack defense CLI that stops malicious packages before they reach your machine or CI pipeline.

### Installation

```sh
brew tap divisionseven/pkg-defender
brew install pkg-defender
```

> **Note for Homebrew 6.0+:** You may be prompted to run `brew trust divisionseven/pkg-defender` if Homebrew's automatic trust evaluation requires confirmation.

### Verification

After installation, confirm the binary is working:

```sh
pkgd --version
pkgd --help
```

### Upgrading

```sh
brew update
brew upgrade pkg-defender
```

### Uninstalling

```sh
brew uninstall pkg-defender
brew untap divisionseven/pkg-defender
```

### Contributing

This tap repository contains only the Homebrew formula for distributing `pkg-defender`. For feature requests, bug reports, or contributions to the tool itself, please visit the [main project repository](https://github.com/divisionseven/pkg-defender) and review its [contributing guide](https://github.com/divisionseven/pkg-defender/blob/main/CONTRIBUTING.md).

### License

This tap is licensed under the Apache License, Version 2.0. See [LICENSE][license] for the full license text. The packaged `pkg-defender` tool is also Apache-2.0 licensed, [see license here][pkgd-repo-license].

---

**Last updated:** 2026-07-02

---

<!-- Header Badge Icons -->

[license-badge-icon]: https://img.shields.io/badge/license-Apache_2.0-blue?style=plastic&logo=apache&color=black&logoColor=white&label=License
[python-badge-icon]: https://img.shields.io/pypi/pyversions/pkg-defender?style=plastic&logo=python&color=black&logoColor=white&label=Python
[codecov-badge-icon]: https://img.shields.io/codecov/c/github/divisionseven/pkg-defender?logo=codecov&style=plastic&color=black&logoColor=white&label=Codecov
[github-binary-releases-badge]: https://img.shields.io/github/v/release/divisionseven/pkg-defender?filter=v*&style=plastic&color=black&logo=git&logoColor=white&label=Release
[github-snapshot-releases-badge]: https://img.shields.io/github/v/tag/divisionseven/pkg-defender?filter=snapshot-latest&style=plastic&logo=sqlite&logoColor=white&color=black&label=Snapshot
[ci-badge-icon]: https://img.shields.io/github/actions/workflow/status/divisionseven/pkg-defender/ci.yml?branch=main&logo=github&style=plastic&color=black&logoColor=white&label=Build
[ecosystems-badge-icon]: https://img.shields.io/badge/Language_Packages-npm_%7C_PyPI_%7C_Cargo_%7C_RubyGems_%7C_Packagist-black?style=plastic
[systems-badge-icon]: https://img.shields.io/badge/System_Packages-Homebrew_%7C_APT_%7C_Yum_%7C_DNF_%7C_Conda-black?style=plastic
[platforms-badge-icon]: https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-black?style=plastic

<!-- Header Badge Links -->

[license-badge-link]: https://opensource.org/licenses/Apache-2.0
[pypi-badge-link]: https://pypi.org/project/pkg-defender/
[codecov-badge-link]: https://app.codecov.io/gh/divisionseven/pkg-defender
[github-binary-releases-link]: https://github.com/divisionseven/pkg-defender/releases
[github-snapshot-releases-link]: https://github.com/divisionseven/pkg-defender/releases/tag/snapshot-latest
[ci-badge-link]: https://github.com/divisionseven/pkg-defender/actions/workflows/ci.yml
[platforms-badge-link]: https://github.com/divisionseven/pkg-defender
[ecosystems-badge-link]: docs/reference/package-managers.md

<!-- Internal Documentation Links -->

[docs-index]: https://github.com/divisionseven/pkg-defender/blob/main/docs/index.md
[supported-commands]: https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/package-managers.md
[targeted-managers]: https://github.com/divisionseven/pkg-defender/blob/main/docs/reference/package-managers.md
[pkgd-repo-license]: https://github.com/divisionseven/pkg-defender/blob/main/LICENSE
[license]: LICENSE
