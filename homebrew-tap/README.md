# Homebrew Tap for PKG-Defender

[![Release](https://img.shields.io/github/v/release/divisionseven/pkg-defender?color=black&logo=git&logoColor=white&label=Release&style=plastic)](https://github.com/divisionseven/pkg-defender/releases)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue?style=plastic&logo=apache&color=black&logoColor=white&label=License)](LICENSE)

Homebrew tap for [PKG-Defender (PKGD)](https://github.com/divisionseven/pkg-defender) — the supply chain attack defense CLI that stops malicious packages before they reach your machine or CI pipeline.

## Installation

```sh
brew tap divisionseven/pkg-defender
brew install pkg-defender
```

> **Note for Homebrew 6.0+:** You may be prompted to run `brew trust divisionseven/pkg-defender` if Homebrew's automatic trust evaluation requires confirmation.

## Verification

After installation, confirm the binary is working:

```sh
pkgd --version
pkgd --help
```

## Upgrading

```sh
brew update
brew upgrade pkg-defender
```

## Uninstalling

```sh
brew uninstall pkg-defender
brew untap divisionseven/pkg-defender
```

## Contributing

This tap repository contains only the Homebrew formula for distributing `pkg-defender`. For feature requests, bug reports, or contributions to the tool itself, please visit the [main project repository](https://github.com/divisionseven/pkg-defender) and review its [contributing guide](https://github.com/divisionseven/pkg-defender/blob/main/CONTRIBUTING.md).

## License

This tap is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text. The packaged `pkg-defender` tool is also Apache-2.0 licensed.
