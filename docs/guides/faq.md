---
title: Frequently Asked Questions
description: Common questions about pkg-defender
---

# Frequently Asked Questions

## General

### What is pkg-defender?

pkg-defender is a supply chain security tool that checks packages before you install them against known vulnerabilities from multiple threat feeds.

### Which package managers are supported?

- **npm** (Node.js) — `pkgd npm install axios`
- **pip** (Python) — `pkgd pip install requests`
- **pip3** — `pkgd pip3 install requests`
- **pipenv** — `pkgd pipenv install requests`
- **pipx** — `pkgd pipx install requests`
- **poetry** — `pkgd poetry add requests`
- **uv** — `pkgd uv pip install requests`
- **brew** (Homebrew) — `pkgd brew install wget`
- **cargo** (Rust) — `pkgd cargo install serde`
- **gem** (Ruby) — `pkgd gem install rails`
- **bundler** (Ruby) — `pkgd bundler install`
- **apt** (Debian/Ubuntu) — `pkgd apt install vim`
- **yum** (RHEL/CentOS) — `pkgd yum install vim`
- **dnf** (Fedora) — `pkgd dnf install vim`
- **composer** (PHP) — `pkgd composer install`
- **bun** (Node.js) — `pkgd bun install zod`
- **pnpm** (Node.js) — `pkgd pnpm install axios`
- **yarn** (Node.js) — `pkgd yarn add axios`

### Is this free?

Yes, the core tool is free and open source.

## Installation

### Why do I need Python 3.11+?

We use modern Python features for better async performance and security.

### Does this work on Windows?

We primarily test on macOS and Linux. Windows support is experimental.

## Usage

### How does the bypass command work?

The bypass command skips all safety checks. It should ONLY be used in isolated test environments, never in production.

See `pkgd bypass --help` for the security warning.

### What happens if a feed is down?

The daemon will retry automatically. You can check feed status with `pkgd health`.

### How often do feeds update?

By default, feeds sync every 4 hours when the daemon is running. You can configure this with `sync_interval_hours` in your config under the `[daemon]` section.

### Can I use this in CI/CD?

Yes! See the CI/CD guide for GitHub Actions, GitLab, Azure Pipelines, and other systems.

## Troubleshooting

### "command not found" after installation

Try running: `uv pip install pkg-defender`
Or use a virtual environment: `python -m venv venv && source venv/bin/activate && uv pip install pkg-defender`

### Database locked errors

This happens if multiple instances run simultaneously. Stop any running processes and try again.

### Empty results from intel search

- Check `pkgd health` to see if feeds are working
- Verify your API tokens are valid
- Check the [Troubleshooting Guide](./troubleshooting.md) for debugging

## Common Error Messages

### Installation Errors

| Error                     | Cause                             | Solution                                           |
| ------------------------- | --------------------------------- | -------------------------------------------------- |
| `pkgd: command not found` | PATH not configured               | Use `python3 -m pkg_defender.cli.main` or fix PATH |
| `pip: command not found`  | pip not installed                 | Install pip with `python3 -m ensurepip`            |
| `Python 3.11+ required`   | Wrong Python version              | Install Python 3.11 or later                       |
| `Permission denied`       | Installing to protected directory | Use `--user` flag or virtual environment           |

### Package Blocking Errors

| Block Message (stderr)                                                | Cause                                                                                                                     | Solution                                                                                                 |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `[PKGD] BLOCKED — <package>@<version>`                                | Package version published recently, or timestamp resolution failed (check `resolution_attempts` table for failure reason) | Wait, specify an older version, or use `--bypass-cooldown` (audit-logged)                                |
| `[PKGD] BLOCKED — <package>@<version>`                                | Known security vulnerability                                                                                              | Run `pkgd intel search <package>` for details, or use `--bypass-threat` if confirmed safe (audit-logged) |
| `Cooldown: <pkg>@<version> is too new (less than <days> day(s) old).` | Version within cooldown window                                                                                            | Wait for window to expire (configured by `cooldown.default_days`), or use `--bypass-cooldown`            |
| `Error: Missing option '--reason'.`                                   | `--reason` required but omitted                                                                                           | Add `--reason "testing in dev"` (required for bypass)                                                    |

### Feed/Intel Errors

| Message                                                         | Cause                              | Solution                                                                    |
| --------------------------------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------- |
| `Error: Package '<name>' not found in <ecosystem>.`             | Package does not exist in registry | Verify the package name and ecosystem                                       |
| `THREAT DETECTED: <pkg> has <severity> severity threat.`        | Known vulnerability found          | Run `pkgd intel search <package>` for details                               |
| `Error: '<manager>' not found or unreachable. Is it installed?` | Registry or manager not installed  | Verify the package manager is installed                                     |
| `Warning: Threat database is stale`                             | Feeds haven't synced recently      | Run `pkgd intel sync` to refresh threat data                                |
| `🔒 PKG-Defender blocked '<pkg>' — Cannot verify ...`            | Registry unreachable (fail-closed) | Check internet connection; verify registry status                           |
| `[PKGD] Error: Pre-install check timed out after ...`           | Registry request timeout           | Increase `command_timeout_seconds` in config (root-level key, default: 30s) |

### Database Errors

| Message                             | Cause                      | Solution                                                                                                                    |
| ----------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `Could not open threat database`    | Database connection failed | Run `pkgd setup` to reinitialize; check database permissions                                                                |
| `database is locked` (SQLite error) | Concurrent access          | Stop other pkgd processes or run `pkgd daemon stop`                                                                         |
| `Permission denied`                 | File permissions issue     | Check permissions on data dir (Linux: `~/.local/share/pkg-defender/`, macOS: `~/Library/Application Support/pkg-defender/`) |

### Shell Integration Errors

| Message                                                                 | Cause                  | Solution                                                        |
| ----------------------------------------------------------------------- | ---------------------- | --------------------------------------------------------------- |
| `Shell '<name>' is not supported. Supported shells: bash, fish, ...`    | Unsupported shell      | Use bash, zsh, fish, powershell, or nushell                     |
| `Shell '<name>' is not installed, skipping completion installation.`    | Shell binary not found | Install the shell or specify a different one                    |
| `Shell '<path>' is not supported, defaulting to bash.` (logged warning) | Unrecognized shell     | Check your `$SHELL` variable or use one of the supported shells |
| `pkgd: command not found`                                               | pkgd not in PATH       | Reinstall pkgd or add installation directory to PATH            |

### Daemon Errors

| Message                                              | Cause                            | Solution                                        |
| ---------------------------------------------------- | -------------------------------- | ----------------------------------------------- |
| `Daemon is not running (no fresh heartbeat).`        | Daemon not started               | Run `pkgd daemon start`                         |
| `Another daemon instance is already running.`        | Another daemon process is active | Run `pkgd daemon stop` then `pkgd daemon start` |
| `Daemon start/stop fails without a specific message` | Stale PID or heartbeat           | Run `pkgd daemon stop` then `pkgd daemon start` |
| `Service installed: <path>` (success) / error raised | System service missing           | Run `pkgd daemon install --platform <os>`       |

### Quick Diagnosis

When encountering any error:

```bash
# 1. Check version
pkgd --version

# 2. Run health check
pkgd health

# 3. Enable verbose output
pkgd <command> --verbose    # -v for INFO, -vv for DEBUG

# 4. Check logs
pkgd logs view              # Uses the correct OS-specific path automatically
# Or manually:
# Linux:   tail -50 ~/.local/share/pkg-defender/pkgd.log
# macOS:   tail -50 ~/Library/Application\ Support/pkg-defender/pkgd.log
```

For detailed troubleshooting, see the [Troubleshooting Guide](./troubleshooting.md).

## Security

### Are my API tokens safe?

Yes. Tokens are stored in your local config file with 600 permissions. We never send tokens anywhere except to the respective feed APIs.

See the environment variables guide for security best practices.

## Contributing

### How do I contribute?

See CONTRIBUTING.md in the repository.
