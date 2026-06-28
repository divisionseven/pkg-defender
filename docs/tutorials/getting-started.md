# Getting Started

## Prerequisites

- **Python 3.11 or later** (verified from `pyproject.toml`)
- uv, pip, Homebrew, or git (depending on install method)

## Installation

### From PyPI (Recommended: uv)

```bash
uv pip install pkg-defender
```

> **Note:** We recommend using [uv](https://github.com/astral-sh/uv) for faster, more reliable package management. If you do not have uv installed, see the [uv installation guide](https://docs.astral.sh/uv/#installation).

### From PyPI (pipx)

```bash
pipx install pkg-defender
```

> **Note:** [pipx](https://pypa.github.io/pipx/) installs CLI tools in isolated environments, avoiding dependency conflicts. Upgrade with `pipx upgrade pkg-defender`.

### From PyPI (pip)

```bash
pip install pkg-defender
```

For development, also install `[test]` and `[lint]` extras:
`pip install "pkg-defender[test,lint]"`

### From Homebrew (macOS/Linux)

```bash
brew tap divisionseven/pkg-defender
brew install pkg-defender
```

### From Source

```bash
git clone https://github.com/divisionseven/pkg-defender
cd pkg-defender
uv sync --dev
```

> **Note:** Requires Python >=3.11.

## Verify Installation

After installation, verify everything works:

```bash
# Check version
pkgd --version

# Check system health
pkgd health

# Run initial setup
pkgd setup
```

## Run Setup

```bash
pkgd setup
```

The setup wizard will:

1. **Detect your shell and install tab completions** — supports bash, zsh, and fish (PowerShell and Nushell use a manual stub)
2. **Detect package managers** — checks for all supported package managers (npm, pip, brew, cargo, conda, and more)
3. **Prompt for API tokens** — optional tokens for GHSA, Socket.dev, X/Twitter, and Reddit feeds
4. **Configure OSSF Malicious Packages feed** — if you did not provide a GitHub token, you'll be asked how to handle this feed (which can take 45-75 minutes to sync without a token due to GitHub rate-limiting):

   | Option                       | Behavior                                                                                   |
   | ---------------------------- | ------------------------------------------------------------------------------------------ |
   | **Sync all feeds now**       | Includes OSSF — the initial sync will take longer                                          |
   | **Defer OSSF to daemon**     | Skips OSSF for now; the daemon will sync it automatically in the background later          |
   | **Permanently disable OSSF** | Won't sync until you re-enable it with `pkgd config set feeds.ossf_malicious_enabled true` |

5. **Choose database location** — use the default platform path or specify a custom location
6. **Sync threat intelligence** — downloads ~350-500 MB of vulnerability data from configured feeds (OSSF is included or deferred based on your choice in step 4)

### Dry-run preview

```bash
pkgd setup --dry-run
```

Shows what will change without modifying any files.

### Teardown

```bash
pkgd reset --teardown
```

Deletes the threat database, removes the config file, and uninstalls the
daemon service (if running). This is a full reset back to a clean state.

## Check a Package

```bash
pkgd npm install lodash@4.17.21
```

This checks the package against:

- **Cooldown gate** — is the version too new? (default: must be 7+ days old)
- **Threat intelligence** — are there known vulnerabilities from your configured threat feeds? (e.g., OSV.dev, GHSA, Socket.dev)

If both checks pass, the native package manager (`npm install`) is invoked transparently.

## Audit a Project

```bash
pkgd audit .
```

Scans the current directory for lock files and checks all dependencies against the threat database. Supports 7 lock file formats: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `requirements.txt`, `Pipfile.lock`, and `uv.lock`.

For CI/CD pipelines, add `--fail-on-threat` to exit with code 4 (`EXIT_THREAT_DETECTED`) when CRITICAL or HIGH threats are found:

```bash
pkgd audit --fail-on-threat
```

## Check System Status

```bash
pkgd status
```

Shows recent threats, active bypasses, and feed sync state.

## If Something Goes Wrong

Quick fixes for common issues:

### pkgd: command not found

```bash
# Reinstall
uv pip install pkg-defender

# Or use virtual environment
python -m venv venv
source venv/bin/activate
uv pip install pkg-defender
```

### Hooks not intercepting commands

```bash
# Re-run setup
pkgd setup

# Source your RC file
source ~/.zshrc  # or ~/.bashrc
```

### Package blocked by cooldown

```bash
# Bypass with reason
pkgd bypass <package>@<version> --reason "needed for project"

# Or reduce cooldown
pkgd config set cooldown.default_days 0
```

### Database locked

```bash
# Kill any running pkgd processes
pkill -f pkg_defender

# Or stop daemon
pkgd daemon stop
```

### Feed sync failures

```bash
# Check health
pkgd health

# Force re-sync
pkgd intel sync
```

### Full reset (when all else fails)

```bash
pkgd --yes reset --teardown
pkgd --ci setup
pkgd intel sync
```

For comprehensive troubleshooting, see the [Troubleshooting Guide](../guides/troubleshooting.md).

## What's Next?

- **[Shell Integration Guide](../guides/shell-integration.md)** — How wrappers intercept installs, supported shells, troubleshooting
- **[Threat Feeds Reference](../reference/threat-feeds.md)** — Manage 9 intelligence feeds, sync schedules, configuration
- **[Cooldown System Explanation](../explanation/cooldown-system.md)** — Configure cooldown windows, bypasses, strict mode
- **[Auditing Guide](../guides/auditing.md)** — Lock file scanning, output formats, CI integration
- **[Full CLI Reference](../reference/cli.md)** — Complete command reference with options and examples

## Shell Completions (Optional)

`pkgd setup` automatically detects your shell and installs tab completion scripts.

### Supported Shells

- **bash**: Completions installed to `~/.local/share/bash-completion/completions/pkgd`
- **zsh**: Completions installed to `~/.zsh/completions/_pkgd`
- **fish**: Completions installed to `~/.config/fish/completions/pkgd.fish`

### Shell Detection

The setup command detects your shell from the `SHELL` environment variable. If your shell is not detected correctly, you can override it:

```bash
pkgd setup --shell zsh
```

### Manual Completion Installation

If you need to manually install completions, use the `completion generate` command:

```bash
# Generate and install bash completion
pkgd completion generate bash > ~/.local/share/bash-completion/completions/pkgd

# Generate and install zsh completion
pkgd completion generate zsh > ~/.zsh/completions/_pkgd

# Generate and install fish completion
pkgd completion generate fish > ~/.config/fish/completions/pkgd.fish

```

After installing completions, restart your shell or source your shell configuration file.
