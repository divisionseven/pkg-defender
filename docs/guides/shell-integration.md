# Shell Integration

## Overview

Shell integration provides two capabilities that make pkg-defender transparent
to use: **tab completion** and **command interception**.

**Tab completion** allows you to press `Tab` after typing `pkgd` to see
available commands, options, and arguments. This is installed automatically
by the setup wizard.

**Command interception** uses shell wrapper functions to intercept package
manager commands — `pip install`, `npm install`, `brew install`, and others —
and route only dangerous subcommands through pkg-defender's threat check before
passing control to the real package manager. Safe commands (list, search,
`--help`, etc.) pass directly to the real binary with zero overhead. This means
you can keep using the commands you already know while benefiting from
pkg-defender's protection.

No daemon is required for either feature. Shell integration runs within the
interactive shell session and adds zero runtime overhead after the initial
check.

---

## Installation

Shell integration is configured in two steps: automatic tab completion
installation, followed by optional shell function setup.

### Step 1: Run the Setup Wizard

```bash
pkgd setup
```

The setup wizard automatically detects your current shell from the `SHELL`
environment variable and installs tab completion scripts to the appropriate
directory. It also creates a configuration file, detects installed package
managers, and prompts for optional API tokens.

To target a specific shell different from the detected one:

```bash
pkgd setup --shell fish
```

To preview what the setup wizard will do without modifying any files:

```bash
pkgd setup --dry-run
```

### Step 2: Generate Shell Functions (Optional)

For transparent interception of package manager commands, generate shell
wrapper functions that route only dangerous subcommands through pkg-defender:

```bash
pkgd hooks
```

This detects all installed shells and package managers on your system, then
prints the shell functions you need to add to each shell's RC file. The output
looks like:

```
Shell Detection:
  ✓ bash
  ✓ zsh
  ✓ fish
  − powershell
  − nushell

Package Manager Detection:
  ✓ brew
  ✓ npm
  ✓ pip

Shell Functions

zsh (~/.zshrc):
  brew() {
      case "$1" in
          install|upgrade|reinstall|remove|uninstall|pin|unpin|switch|edit|tap|untap|cask|bottle|postinstall|migrate|link|unlink|relink|cleanup|autoremove|update|upgrade|outdated)
              pkgd brew "$@"
              ;;
          *)
              command brew "$@"
              ;;
      esac
  }

bash (~/.bashrc):
  brew() {
      case "$1" in
          install|upgrade|reinstall|remove|uninstall|pin|unpin|switch|edit|tap|untap|cask|bottle|postinstall|migrate|link|unlink|relink|cleanup|autoremove|update|upgrade|outdated)
              pkgd brew "$@"
              ;;
          *)
              command brew "$@"
              ;;
      esac
  }

fish (~/.config/fish/config.fish):
  function brew
      switch $argv[1]
          case install upgrade reinstall remove uninstall pin unpin switch edit tap untap cask bottle postinstall migrate link unlink relink cleanup autoremove update upgrade outdated
              pkgd brew $argv
          case '*'
              command brew $argv
      end
  end
```

Copy the relevant functions into each shell's RC file, then source that file (or
restart your terminal). To target a single shell:

```bash
pkgd hooks --shell zsh
pkgd hooks --shell powershell
```

> **Note:** Shell wrapper functions only intercept dangerous subcommands
> (install, upgrade, remove, etc.). Safe commands (list, search, `--help`,
> `info`) pass directly to the real binary. You can always bypass interception
> by using `pkgd <manager>` directly (e.g., `pkgd pip install`).

---

## Supported Shells

pkg-defender supports five shells: bash, zsh, fish, PowerShell, and Nushell.

### Bash

| Item                  | Details                                           |
| --------------------- | ------------------------------------------------- |
| Completion path       | `~/.local/share/bash-completion/completions/pkgd` |
| RC file for functions | `~/.bashrc`                                       |
| Function syntax       | `case "$1" in install\|...) pkgd ... ;; esac`     |
| Source command        | `source ~/.bashrc`                                |

**Example shell function:**

```bash
pip() {
    case "$1" in
        install|uninstall|download|wheel|hash|completion|debug|check|config|list|show|search|index|inspect|freeze|req)

                pkgd pip "$@"
            ;;
        *)
            command pip "$@"
            ;;
    esac
}
npm() {
    case "$1" in
        install|ci|update|uninstall|dedupe|config|cache|exec|run|init|create|set|rebuild|doctor|explain|fund|audit|outdated|prune|pack|link|publish|unpublish|version|diff|edit|team|access|repo|token|org|owner|whoami|deprecate|star|unstar|ping|query)
            pkgd npm "$@"
            ;;
        *)
            command npm "$@"
            ;;
    esac
}
```

> **Note:** The actual dangerous subcommands vary by package manager. Run
> `pkgd hooks` to see the exact list for your system.

### Zsh

| Item                  | Details                                       |
| --------------------- | --------------------------------------------- |
| Completion path       | `~/.zsh/completions/_pkgd`                    |
| RC file for functions | `~/.zshrc`                                    |
| Function syntax       | Same as bash — `case "$1" in install\|...) ;` |
| Source command        | `source ~/.zshrc`                             |

**Example shell function:**

```zsh
pip() {
    case "$1" in
        install|uninstall|download|wheel|hash|completion|debug|check|config|list|show|search|index|inspect|freeze|req)
            pkgd pip "$@"
            ;;
        *)
            command pip "$@"
            ;;
    esac
}
```

### Fish

| Item                  | Details                                   |
| --------------------- | ----------------------------------------- |
| Completion path       | `~/.config/fish/completions/pkgd.fish`    |
| RC file for functions | `~/.config/fish/config.fish`              |
| Function syntax       | `switch $argv[1]; case install ... ; end` |
| Source command        | `source ~/.config/fish/config.fish`       |

**Example shell function:**

```fish
function pip
    switch $argv[1]
        case install uninstall download wheel hash completion debug check config list show search index inspect freeze req
            pkgd pip $argv
        case '*'
            command pip $argv
    end
end
```

### PowerShell

| Item                  | Details                                             |
| --------------------- | --------------------------------------------------- |
| Completion path       | `~/.config/powershell/pkgd_completion.ps1`          |
| RC file for functions | `$PROFILE`                                          |
| Function syntax       | `if ($args[0] -in @('install',...)) { & pkgd ... }` |
| Source command        | `. $PROFILE`                                        |

**Example shell function:**

```powershell
function pip {
    if ($args[0] -in @('install', 'uninstall', 'download', 'wheel', 'hash', 'completion', 'debug', 'check', 'config', 'list', 'show', 'search', 'index', 'inspect', 'freeze', 'req')) {
        & pkgd pip @args
    } else {
        & (Get-Command pip -CommandType Application) @args
    }
}
```

> **Note:** PowerShell was already using functions in the previous version —
> the syntax remains similar but now uses conditional interception rather than
> unconditional forwarding.

> **Note:** Click's built-in completion generation does not support
> PowerShell natively. Automatic tab completion installation during
> `pkgd setup` will be skipped for PowerShell. As a result, manual
> completion generation is not available for PowerShell via
> `pkgd completion generate`.

### Nushell

| Item                  | Details                                                 |
| --------------------- | ------------------------------------------------------- |
| Completion path       | `~/.config/nushell/completions/pkgd.nu`                 |
| RC file for functions | `~/.config/nushell/config.nu`                           |
| Function syntax       | `def <manager> [...args] { if ($args.0 in [...]) ... }` |
| Source command        | `source ~/.config/nushell/config.nu`                    |

**Example shell function:**

```nushell
def pip [...args: string] {
    if (($args | length) == 0) {
        ^pip
    } else if ($args.0 in [install uninstall download wheel hash completion debug check config list show search index inspect freeze req]) {
        ^pkgd pip ...$args
    } else {
        ^pip ...$args
    }
}
```

> **Note:** Click's built-in completion generation does not support
> Nushell natively. Automatic tab completion installation during
> `pkgd setup` will be skipped for Nushell. As a result, manual
> completion generation is not available for Nushell via
> `pkgd completion generate`.

---

## Verification

After installation, verify that shell integration is working correctly.

### Check Tab Completion

Open a new terminal (or source your RC file) and type:

```bash
pkgd <Tab><Tab>
```

You should see a list of available commands — `audit`, `bypass`, `config`,
`daemon`, `health`, `hooks`, `intel`, `reset`, `setup`, `status`, and
others.

### Check Command Interception

Verify that shell functions are active:

```bash
type pip
```

If the function is installed correctly, this should report `pip is a function`
(bash/zsh/fish) or show the function definition (PowerShell/Nushell), rather
than showing the path to the `pip` binary.

### Run a Health Check

```bash
pkgd health
```

The health check reports configuration validity, database status, feed
configuration, API token validity (GitHub, Socket.dev, X/Twitter, Reddit, Libraries.io), disk space, and file permissions. For more detail:

```bash
pkgd health --verbose
```

### Check System Status

```bash
pkgd status
```

Displays threat count by severity, active bypasses, and feed synchronization state.

### Test Interception

Run a dry-run check to confirm a package manager command routes through
pkg-defender:

```bash
pkgd pip install requests --dry-run
```

This checks the package against the threat database and cooldown gate
without actually installing it. If everything is working, you will see
the check result followed by a message that the installation would
proceed (or be blocked).

### Verify Tab Completion Files

Confirm the completion files exist at the expected location:

```bash
# Bash
ls -la ~/.local/share/bash-completion/completions/pkgd

# Zsh
ls -la ~/.zsh/completions/_pkgd

# Fish
ls -la ~/.config/fish/completions/pkgd.fish
```

### Verify Shell Functions in RC File

Check that shell functions were added to your shell's RC file:

```bash
# Bash / Zsh
cat ~/.bashrc | grep pkgd
cat ~/.zshrc | grep pkgd

# Fish
cat ~/.config/fish/config.fish | grep pkgd
```

---

## Troubleshooting

### Shell Integration Not Installing

**Symptom:** `pkgd setup` completes without errors, but `npm install`
runs the native npm command without interception.

**Cause:** The shell functions were not added to your RC file, or the wrong
shell was targeted during setup.

**Solution:**

```bash
# Check which shell you are using
echo $SHELL

# Re-run setup for your specific shell
pkgd setup --shell zsh

# Manually verify the shell functions are in your RC file
cat ~/.zshrc | grep "pkgd"

# Source your RC file
source ~/.zshrc

# Or restart your terminal
```

**Prevention:** Ensure you run `pkgd setup` in the same shell type you use
interactively.

---

### Command Interception Not Working

**Symptom:** `npm install express` installs directly without passing through
pkg-defender.

**Cause:** Shell functions have not been added to the shell RC file, or the RC
file has not been sourced after adding them.

**Solution:**

```bash
# Check whether pip is currently wrapped
type pip

# If it shows a binary path, shell functions are not active.
# Generate and add shell functions:
pkgd hooks --shell zsh

# Then copy the output lines into ~/.zshrc and source it:
source ~/.zshrc

# Verify again
type pip  # Should now show "pip is a function"
```

**Prevention:** After adding shell functions to your RC file, always source it
or restart your terminal.

---

### Shell Integration Not Causing Slow Startup

**Symptom:** The terminal takes several seconds to become responsive after
opening a new shell session.

**Cause:** This is unlikely to be caused by pkg-defender. Shell functions (which
pkg-defender uses for command interception) are parsed at RC file load time but
add negligible startup overhead — their body only executes when you invoke the
command. Slow shell startup is typically caused by heavy shell frameworks
(oh-my-zsh, nvm, pyenv, etc.) or a large RC file.

**Solution:**

To rule out pkg-defender as a factor, temporarily remove the shell function
definitions from your RC file and test startup speed in a new terminal:

```bash
# Zsh — comment out function definitions in ~/.zshrc
# Bash — comment out function definitions in ~/.bashrc
# Fish — comment out function definitions in ~/.config/fish/config.fish
```

After removal, you can still use pkg-defender by invoking `pkgd` explicitly
— only the convenience wrapper functions are removed.

To fully remove all pkg-defender shell integration and data:

```bash
pkgd reset --teardown
```

**Prevention:** pkg-defender shell functions add negligible startup overhead by
design — no special configuration is needed.

---

### Package Manager Not Intercepted

**Symptom:** A newly installed package manager is not intercepted by
pkg-defender.

**Cause:** The manager was installed after the shell functions were generated,
so no function exists for it.

**Solution:**

```bash
# Check which managers are detected
pkgd hooks

# Re-run hooks to generate shell functions for all detected managers
pkgd hooks --shell zsh

# Add the new functions to your RC file and source it
source ~/.zshrc
```

**Prevention:** Run `pkgd hooks` after installing any new package manager.

---

### Tab Completion Not Working

**Symptom:** Pressing `Tab` after `pkgd` shows no completions.

**Cause:** The completion file was not installed, or the shell has not
loaded it.

**Solution:**

```bash
# Re-run setup to install completions
pkgd setup

# Or manually install completions
pkgd completion generate bash > ~/.local/share/bash-completion/completions/pkgd

# Restart your shell or source the completion file
# (bash completions are loaded automatically from that directory)
```

---

### Shell Not Detected Correctly

**Symptom:** `pkgd setup` detects the wrong shell.

**Cause:** The `SHELL` environment variable points to a shell that differs
from the one you are actively using.

**Solution:**

```bash
# Check the current SHELL value
echo $SHELL

# Override the shell detection
pkgd setup --shell zsh
pkgd hooks --shell zsh
```

---

## Removing Shell Integration

To remove all shell integration — both tab completions and command wrapper
functions:

```bash
# Remove completions (manually delete the files):
rm ~/.local/share/bash-completion/completions/pkgd   # bash
rm ~/.zsh/completions/_pkgd                           # zsh
rm ~/.config/fish/completions/pkgd.fish               # fish
rm ~/.config/powershell/pkgd_completion.ps1            # powershell
rm ~/.config/nushell/completions/pkgd.nu               # nushell

# Remove shell function definitions from your RC files
# (edit ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, etc.)
```

For a complete teardown of all pkg-defender data including configuration
and the threat database:

```bash
pkgd reset --teardown
```
