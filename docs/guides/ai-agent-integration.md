# AI Agent Integration

Guide AI coding agents (Copilot, Cline, Claude Code, etc.) to use `pkgd`
correctly during package management operations.

## Common Commands

| Command                                      | Purpose                                                          |
| -------------------------------------------- | ---------------------------------------------------------------- |
| `pkgd audit <lockfile>`                      | Scan a lock file for threats and cooldown-pending packages       |
| `pkgd <manager> install <pkg>`               | Intercept a package manager install command                      |
| `pkgd status`                                | Show defender status: feeds, bypasses, and threats               |
| `pkgd intel sync`                            | Sync threat intelligence feeds                                   |
| `pkgd config set/get`                        | Manage configuration                                             |
| `pkgd setup`                                 | Interactive first-run setup wizard                               |
| `pkgd hooks`                                 | Generate shell functions for wrapped package manager commands      |

## Example Workflow: Pre-Install Threat Check

```console
# Step 1: Sync latest intelligence
$ pkgd intel sync

# Step 2: Audit project dependencies
$ pkgd audit requirements.txt

# Step 3: Check specific install commands
$ pkgd pip install requests==2.31.0

# Step 4: Review status and threats
$ pkgd status --json
```

## Important Rules

- **If a package download is blocked, DO NOT override it.** Inform the user
  and let them decide how to respond (e.g., create a bypass).
- **Route ALL package manager operations through `pkgd`** — do not call
  `pip`, `npm`, or other package managers directly without using the `pkgd` wrapper
  (`pkgd pip install`, `pkgd npm install`).
- **Use `pkgd config set` for configuration** — do not modify `pkgd.toml`
  or config files directly unless the user explicitly requests it.

## Environment Variables

| Variable                     | Purpose                                    |
| ---------------------------- | ------------------------------------------ |
| `PKGD_CI=1`                  | Enable non-interactive mode for automation |
| `PKGD_FEEDS_SOCKET_API_KEY`  | Socket.dev API key for threat intelligence |
| `PKGD_COOLDOWN_DEFAULT_DAYS` | Override cooldown window (default: 7 days) |
| `PKGD_DEBUG=1`               | Enable debug logging                       |

## Related

For threat intelligence feed setup, see [Threat Feeds](../reference/threat-feeds.md).
For CI/CD integration, see [CI/CD Integration](ci-cd.md).
