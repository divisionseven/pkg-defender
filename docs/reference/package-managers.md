# Package Manager Reference

> **Purpose:** A comprehensive reference for every package manager PKG-Defender targets — covering dangerous interception commands, lockfile formats, supported languages, OS compatibility, registries, and implementation priority.

*Last updated: June 2026*

---

## Supported Package Managers

**Currently Supported:** 19 of 32 managers (~59% coverage)

- **Tier 1**: 6/6 (100%) — `pip`/`pip3`/`pipx`, `uv`, `npm`, `yarn`(v1 Classic), `yarn`(v2-v4 Berry), `pnpm`
- **Tier 2**: 8/8 (100%) — `poetry`, `pipenv`, `cargo`, `bun`, `gem`, `composer`, `bundler`, `conda`
- **Tier 3**: 0/9 (0%)
- **Tier 4**: 3/9 (33%) — `apt`, `brew`, `dnf`/`yum`

> **Currently Supported Legend:**
> - ✅ = Full command interception support in code
> - 🟡 = Partial support (inherits parent adapter behavior)
> - 🟠 = Not yet implemented (future release target)
> - ❌ = Not yet implemented

| Package Manager         | Ecosystem / Language    | Primary OS   | Registry                | Has Lockfile                    | Currently Supported | Tier |
| ----------------------- | ----------------------- | ------------ | ----------------------- | ------------------------------- | ------------------- | ---- |
| `pip` / `pip3` / `pipx` | Python                  | All          | PyPI                    | 🟡 Manifest (`requirements.txt`) | ✅                   | 1    |
| `uv`                    | Python                  | All          | PyPI                    | ✅ `uv.lock`                     | ✅                   | 1    |
| `npm`                   | JavaScript / Node       | All          | npmjs.com               | ✅ `package-lock.json`           | ✅                   | 1    |
| `yarn` (v1 Classic)     | JavaScript / Node       | All          | npmjs.com               | ✅ `yarn.lock`                   | ✅                   | 1    |
| `yarn` (v2–v4 Berry)    | JavaScript / Node       | All          | npmjs.com               | ✅ `yarn.lock` (new fmt)         | ✅                   | 1    |
| `pnpm`                  | JavaScript / Node       | All          | npmjs.com               | ✅ `pnpm-lock.yaml`              | ✅                   | 1    |
| `poetry`                | Python                  | All          | PyPI                    | ✅ `poetry.lock`                 | ✅                   | 2    |
| `pipenv`                | Python                  | All          | PyPI                    | ✅ `Pipfile.lock`                | ✅                   | 2    |
| `cargo`                 | Rust                    | All          | crates.io               | ✅ `Cargo.lock`                  | ✅                   | 2    |
| `bun`                   | JavaScript / Node       | macOS, Linux | npmjs.com               | ✅ `bun.lockb` / `bun.lock`      | ✅                   | 2    |
| `gem`                   | Ruby                    | All          | rubygems.org            | ❌                               | ✅                   | 2    |
| `bundler`               | Ruby                    | All          | rubygems.org            | ✅ `Gemfile.lock`                | ✅                   | 2    |
| `conda`                 | Python / Data Science   | All          | conda-forge, Anaconda   | 🟡 Partial (`conda-lock.yml`)    | ✅                   | 2    |
| `composer`              | PHP                     | All          | packagist.org           | ✅ `composer.lock`               | ✅                   | 2    |
| `pdm`                   | Python                  | All          | PyPI                    | ✅ `pdm.lock`                    | ❌                   | 3    |
| `hatch`                 | Python                  | All          | PyPI                    | ❌                               | ❌                   | 3    |
| `mamba` / `micromamba`  | Python / Data Science   | All          | conda-forge             | 🟡 Partial                       | ❌                   | 3    |
| `maven` (mvn)           | Java / JVM              | All          | Maven Central           | ❌ (uses `pom.xml`)              | ❌                   | 3    |
| `gradle`                | Java / Kotlin / JVM     | All          | Maven Central / JCenter | 🟡 Partial (`gradle.lockfile`)   | ❌                   | 3    |
| `nuget`                 | .NET / C#               | All          | nuget.org               | ✅ `packages.lock.json`          | ❌                   | 3    |
| `dotnet`                | .NET / C#               | All          | nuget.org               | ✅ `packages.lock.json`          | ❌                   | 3    |
| `go`                    | Go                      | All          | proxy.golang.org        | ✅ `go.sum`                      | ❌                   | 3    |
| `deno`                  | JavaScript / TypeScript | All          | JSR / deno.land         | ✅ `deno.lock`                   | ❌                   | 3    |
| `swift package` (SPM)   | Swift                   | macOS, Linux | GitHub / source         | ✅ `Package.resolved`            | ❌                   | 4    |
| `cocoapods`             | Swift / ObjC            | macOS        | cocoapods.org           | ✅ `Podfile.lock`                | ❌                   | 4    |
| `carthage`              | Swift / ObjC            | macOS        | GitHub / source         | ✅ `Cartfile.resolved`           | ❌                   | 4    |
| `brew` (Homebrew)       | System / Mixed          | macOS, Linux | formulae.brew.sh        | ✅ `Brewfile.lock.json`          | ✅                   | 4    |
| `apt`                   | System (Debian/Ubuntu)  | Linux        | apt repos               | ❌                               | ✅                   | 4    |
| `dnf` / `yum`           | System (RHEL/Fedora)    | Linux        | dnf repos               | ❌                               | ✅                   | 4    |
| `pacman`                | System (Arch)           | Linux        | Arch repos              | ❌                               | ❌                   | 4    |
| `nix` / `nix-env`       | System / Mixed          | Linux, macOS | nixpkgs                 | ✅ `flake.lock`                  | ❌                   | 4    |
| `snap`                  | System                  | Linux        | snapcraft.io            | ❌                               | ❌                   | 4    |
| `flatpak`               | System (Linux)          | Linux        | Flathub                 | ❌                               | ❌                   | 4    |

> **Coverage vs. Priority:** `CoverageTier` (FULL / PARTIAL / AUDIT) controls which security checks run per manager — distinct from implementation priority (Tier 1–4) shown in the table. See each adapter's `coverage_tier` field for exact values.

> **Note:** The goal is to fully support all listed package managers. Implementation priority follows the adoption tier system. To present a case for fast-tracking a package manager, open an issue or submit a PR.

---

## Dangerous Commands by Manager

These are the commands that **install, update, or modify packages on the machine** — PKG-Defender's interception surface. Commands that only remove packages, list packages, or display information are excluded.

> **Command Risk Legend:**
>
> - 🔴 **Critical** — Direct package install, must intercept
> - 🟡 **Important** — Installs from lockfile/manifest or fetches deps as side effect
> - 🟠 **Watch** — May install implicitly or installs tools/scripts globally

### Python

#### `pip` / `pip3` / `pipx`

| Command                                | Risk | Notes                                           |
| -------------------------------------- | ---- | ----------------------------------------------- |
| `pip install <pkg>`                    | 🔴    | Core install — intercept always                 |
| `pip install -r requirements.txt`      | 🔴    | Bulk install from requirements file             |
| `pip install .`                        | 🔴    | Install local project (may pull deps from PyPI) |
| `pip install -e .`                     | 🔴    | Editable install — still pulls deps             |
| `pip install --upgrade <pkg>`          | 🔴    | Upgrades existing package                       |
| `pip install --upgrade-strategy eager` | 🔴    | Upgrades all deps transitively                  |
| `pipx install <pkg>`                   | 🔴    | Global CLI tool install                         |
| `pipx upgrade <pkg>`                   | 🔴    | Upgrades a globally installed tool              |
| `pipx upgrade-all`                     | 🔴    | Upgrades all pipx-managed tools                 |
| `pip download <pkg>`                   | 🟡    | Downloads wheel to disk — pre-cursor to install |
| `pip wheel <pkg>`                      | 🟡    | Builds wheel, pulls deps                        |
| `pip sync` (pip-tools)                 | 🔴    | Syncs environment to requirements               |

#### `uv`

| Command                              | Risk | Notes                                   |
| ------------------------------------ | ---- | --------------------------------------- |
| `uv add <pkg>`                       | 🔴    | Adds dep to project and installs        |
| `uv pip install <pkg>`               | 🔴    | pip-compatible interface                |
| `uv pip install -r requirements.txt` | 🔴    | Bulk install                            |
| `uv sync`                            | 🔴    | Syncs environment from `uv.lock`        |
| `uv run <script>`                    | 🟠    | Can silently install deps to run script |
| `uv tool install <tool>`             | 🔴    | Installs a CLI tool globally            |
| `uv tool upgrade <tool>`             | 🔴    | Upgrades a globally installed tool      |
| `uv update`                          | 🔴    | Updates lockfile and installs           |

#### `poetry`

| Command               | Risk | Notes                                 |
| --------------------- | ---- | ------------------------------------- |
| `poetry add <pkg>`    | 🔴    | Adds and installs dependency          |
| `poetry install`      | 🔴    | Installs all deps from `poetry.lock`  |
| `poetry update`       | 🔴    | Updates deps and reinstalls           |
| `poetry update <pkg>` | 🔴    | Updates specific package              |
| `poetry run <script>` | 🟠    | Executes in venv, may trigger install |

#### `pipenv`

| Command                | Risk | Notes                                 |
| ---------------------- | ---- | ------------------------------------- |
| `pipenv install <pkg>` | 🔴    | Installs and adds to Pipfile          |
| `pipenv install`       | 🔴    | Installs all from `Pipfile.lock`      |
| `pipenv update`        | 🔴    | Updates all packages                  |
| `pipenv update <pkg>`  | 🔴    | Updates specific package              |
| `pipenv sync`          | 🔴    | Installs exact versions from lockfile |
| `pipenv upgrade <pkg>` | 🔴    | Upgrades specific package             |

#### `conda`

| Command                       | Risk | Notes                       |
| ----------------------------- | ---- | --------------------------- |
| `conda install <pkg>`         | 🔴    | Core install                |
| `conda update <pkg>`          | 🔴    | Updates a package           |
| `conda update --all`          | 🔴    | Updates all packages in env |
| `conda env create -f env.yml` | 🔴    | Creates env from spec file  |
| `conda env update -f env.yml` | 🔴    | Updates env from spec file  |

#### `pdm`

| Command            | Risk | Notes                         |
| ------------------ | ---- | ----------------------------- |
| `pdm add <pkg>`    | 🔴    | Adds and installs dependency  |
| `pdm install`      | 🔴    | Installs from `pdm.lock`      |
| `pdm update`       | 🔴    | Updates all packages          |
| `pdm update <pkg>` | 🔴    | Updates specific package      |
| `pdm sync`         | 🔴    | Syncs environment to lockfile |

#### `hatch`

| Command            | Risk | Notes                                             |
| ------------------ | ---- | ------------------------------------------------- |
| `hatch env create` | 🔴    | Creates environment and installs deps             |
| `hatch run <cmd>`  | 🟠    | Auto-creates env and installs deps before running |
| `hatch dep show`   | ℹ️    | Info only — safe                                  |

---

### JavaScript / Node.js

#### `npm`

| Command                          | Risk | Notes                                                  |
| -------------------------------- | ---- | ------------------------------------------------------ |
| `npm install` / `npm i`          | 🔴    | Installs all deps from `package.json`                  |
| `npm install <pkg>`              | 🔴    | Installs specific package                              |
| `npm install -g <pkg>`           | 🔴    | Global install — high risk                             |
| `npm install --save <pkg>`       | 🔴    | Install + save to package.json                         |
| `npm install --save-dev <pkg>`   | 🔴    | Install as dev dep                                     |
| `npm ci`                         | 🔴    | Clean install from `package-lock.json`                 |
| `npm update`                     | 🔴    | Updates all packages                                   |
| `npm update <pkg>`               | 🔴    | Updates specific package                               |
| `npm install --legacy-peer-deps` | 🔴    | Force install ignoring peer conflicts                  |
| `npx <pkg>`                      | 🔴    | Executes package — **silently installs if not cached** |
| `npm exec <pkg>`                 | 🔴    | Alias for npx                                          |
| `npm link`                       | 🟠    | Links local package, can introduce untrusted code      |

#### `yarn` (v1 Classic)

| Command                                       | Risk | Notes                                |
| --------------------------------------------- | ---- | ------------------------------------ |
| `yarn add <pkg>`                              | 🔴    | Installs and adds dep                |
| `yarn add -D <pkg>`                           | 🔴    | Install as dev dep                   |
| `yarn add -g <pkg>` / `yarn global add <pkg>` | 🔴    | Global install                       |
| `yarn install`                                | 🔴    | Installs all deps                    |
| `yarn upgrade <pkg>`                          | 🔴    | Upgrades specific package            |
| `yarn upgrade`                                | 🔴    | Upgrades all packages                |
| `yarn upgrade-interactive`                    | 🔴    | Interactive upgrade — still installs |
| `yarn link`                                   | 🟠    | Same risk as npm link                |

#### `yarn` (v2–v4 Berry)

| Command                | Risk | Notes                                 |
| ---------------------- | ---- | ------------------------------------- |
| `yarn add <pkg>`       | 🔴    | Same as v1                            |
| `yarn install`         | 🔴    | Installs from lockfile                |
| `yarn up <pkg>`        | 🔴    | Upgrades a dependency                 |
| `yarn dlx <pkg> <cmd>` | 🔴    | Like npx — **downloads and executes** |
| `yarn set version`     | 🟠    | Can trigger Berry/plugin downloads    |

#### `pnpm`

| Command                   | Risk | Notes                                                                |
| ------------------------- | ---- | -------------------------------------------------------------------- |
| `pnpm add <pkg>`          | 🔴    | Installs specific package                                            |
| `pnpm install` / `pnpm i` | 🔴    | Installs all from manifest                                           |
| `pnpm update`             | 🔴    | Updates all packages                                                 |
| `pnpm update <pkg>`       | 🔴    | Updates specific package                                             |
| `pnpm add -g <pkg>`       | 🔴    | Global install                                                       |
| `pnpm dlx <pkg>`          | 🔴    | Like npx — downloads and runs                                        |
| `pnpm import`             | 🟡    | Converts `package-lock.json` → `pnpm-lock.yaml`, triggers re-install |

#### `bun`

| Command                      | Risk | Notes                                       |
| ---------------------------- | ---- | ------------------------------------------- |
| `bun add <pkg>`              | 🔴    | Installs specific package                   |
| `bun install`                | 🔴    | Installs all from manifest                  |
| `bun update`                 | 🔴    | Updates all packages                        |
| `bun update <pkg>`           | 🔴    | Updates specific package                    |
| `bun add -g <pkg>`           | 🔴    | Global install                              |
| `bun x <pkg>` / `bunx <pkg>` | 🔴    | Executes package — silently downloads       |
| `bun run <script>`           | 🟠    | Can trigger auto-install if `--install` set |

#### `deno`

| Command                  | Risk | Notes                                       |
| ------------------------ | ---- | ------------------------------------------- |
| `deno add <pkg>`         | 🔴    | Adds dep to `deno.json`                     |
| `deno install <url/pkg>` | 🔴    | Installs script/binary globally             |
| `deno cache <url>`       | 🟡    | Pre-caches remote module                    |
| `deno task <task>`       | 🟠    | May download deps as side effect            |
| `deno run <url>`         | 🟠    | Fetches and executes remote module directly |

---

### Ruby

#### `gem`

| Command                 | Risk | Notes                         |
| ----------------------- | ---- | ----------------------------- |
| `gem install <gemname>` | 🔴    | Installs gem                  |
| `gem update <gemname>`  | 🔴    | Updates specific gem          |
| `gem update`            | 🔴    | Updates all gems              |
| `gem fetch <gemname>`   | 🟡    | Downloads `.gem` file to disk |

#### `bundler` (`bundle`)

| Command               | Risk | Notes                                  |
| --------------------- | ---- | -------------------------------------- |
| `bundle install`      | 🔴    | Installs all from `Gemfile.lock`       |
| `bundle add <gem>`    | 🔴    | Adds and installs a gem                |
| `bundle update <gem>` | 🔴    | Updates specific gem                   |
| `bundle update`       | 🔴    | Updates all gems                       |
| `bundle exec`         | 🟠    | Executes in bundled context — indirect |

---

### PHP

#### `composer`

| Command                         | Risk | Notes                                              |
| ------------------------------- | ---- | -------------------------------------------------- |
| `composer require <vendor/pkg>` | 🔴    | Adds and installs dependency                       |
| `composer install`              | 🔴    | Installs from `composer.lock`                      |
| `composer update`               | 🔴    | Updates all packages                               |
| `composer update <vendor/pkg>`  | 🔴    | Updates specific package                           |
| `composer global require <pkg>` | 🔴    | Global install — high risk                         |
| `composer global update`        | 🔴    | Updates globally installed packages                |
| `composer create-project <pkg>` | 🔴    | Bootstraps a project — installs a package skeleton |

---

### JVM (Java / Kotlin)

#### `maven` (`mvn`)

Maven does not have standalone "install" commands in the manner of npm — dependencies are resolved and fetched during the build lifecycle.

| Command                                  | Risk | Notes                                          |
| ---------------------------------------- | ---- | ---------------------------------------------- |
| `mvn install`                            | 🔴    | Full build + resolves and downloads all deps   |
| `mvn package`                            | 🔴    | Resolves and downloads deps                    |
| `mvn compile`                            | 🔴    | Resolves and downloads deps                    |
| `mvn verify`                             | 🔴    | Full lifecycle, downloads all deps             |
| `mvn dependency:get -Dartifact=<coords>` | 🔴    | Explicitly downloads a specific artifact       |
| `mvn dependency:resolve`                 | 🟡    | Downloads all declared deps without full build |
| `mvn dependency:copy`                    | 🟡    | Downloads and copies specific dep              |
| `mvn wrapper:download`                   | 🟡    | Downloads Maven Wrapper binary                 |

#### `gradle`

| Command                            | Risk | Notes                                        |
| ---------------------------------- | ---- | -------------------------------------------- |
| `gradle build` / `./gradlew build` | 🔴    | Full build — resolves and downloads all deps |
| `gradle assemble`                  | 🔴    | Downloads and assembles without tests        |
| `gradle dependencies`              | 🟡    | Resolves and **downloads** all deps to cache |
| `gradle :app:dependencies`         | 🟡    | Same scoped to a subproject                  |
| `gradle wrapper`                   | 🟡    | Downloads Gradle Wrapper jar                 |
| `gradle resolveConfigurations`     | 🟡    | Force-resolves all configs                   |

---

### Go

#### `go` toolchain

| Command                       | Risk | Notes                                                  |
| ----------------------------- | ---- | ------------------------------------------------------ |
| `go get <module@version>`     | 🔴    | Downloads and adds a module dep                        |
| `go install <module@version>` | 🔴    | Downloads and installs a binary                        |
| `go mod download`             | 🔴    | Downloads all modules in `go.mod`                      |
| `go mod tidy`                 | 🔴    | Adds missing and removes unused modules — can download |
| `go build`                    | 🟡    | Downloads missing deps as a side effect                |
| `go run <file>`               | 🟡    | Downloads missing deps as a side effect                |

---

### C# / .NET

#### `nuget` CLI

| Command               | Risk | Notes                                        |
| --------------------- | ---- | -------------------------------------------- |
| `nuget install <pkg>` | 🔴    | Downloads and installs a package             |
| `nuget update <pkg>`  | 🔴    | Updates a package                            |
| `nuget restore`       | 🔴    | Restores all packages from `packages.config` |

#### `dotnet` CLI

| Command                         | Risk | Notes                                      |
| ------------------------------- | ---- | ------------------------------------------ |
| `dotnet add package <pkg>`      | 🔴    | Adds and installs a NuGet package          |
| `dotnet restore`                | 🔴    | Restores all NuGet packages                |
| `dotnet build`                  | 🟡    | Triggers implicit restore — downloads deps |
| `dotnet run`                    | 🟡    | Triggers implicit restore — downloads deps |
| `dotnet tool install <tool>`    | 🔴    | Installs a .NET global tool                |
| `dotnet tool update <tool>`     | 🔴    | Updates a .NET global tool                 |
| `dotnet tool install -g <tool>` | 🔴    | Global tool install                        |

---

### Rust

#### `cargo`

| Command                     | Risk | Notes                                           |
| --------------------------- | ---- | ----------------------------------------------- |
| `cargo add <crate>`         | 🔴    | Adds dep to `Cargo.toml` (fetches index)        |
| `cargo install <crate>`     | 🔴    | Installs a binary crate globally                |
| `cargo build`               | 🔴    | Downloads and compiles all deps                 |
| `cargo run`                 | 🟡    | Downloads deps and runs binary                  |
| `cargo update`              | 🔴    | Updates `Cargo.lock` — re-fetches new versions  |
| `cargo fetch`               | 🔴    | Pre-fetches all deps to local cache             |
| `cargo install --git <url>` | 🔴    | Installs directly from git repo — **high risk** |

---

### Swift / Apple Platforms

#### `swift package` (SPM)

| Command                 | Risk | Notes                                       |
| ----------------------- | ---- | ------------------------------------------- |
| `swift package resolve` | 🔴    | Resolves and downloads all declared deps    |
| `swift package update`  | 🔴    | Updates all deps to latest allowed versions |
| `swift build`           | 🟡    | Resolves and downloads deps as side effect  |
| `swift run`             | 🟡    | Same as build                               |

#### `cocoapods` (`pod`)

| Command                | Risk | Notes                                 |
| ---------------------- | ---- | ------------------------------------- |
| `pod install`          | 🔴    | Installs all pods from `Podfile.lock` |
| `pod update`           | 🔴    | Updates all pods                      |
| `pod update <PodName>` | 🔴    | Updates specific pod                  |

#### `carthage`

| Command                       | Risk | Notes                                                  |
| ----------------------------- | ---- | ------------------------------------------------------ |
| `carthage bootstrap`          | 🔴    | Downloads and builds all deps from `Cartfile.resolved` |
| `carthage update`             | 🔴    | Updates all deps                                       |
| `carthage update <framework>` | 🔴    | Updates specific dep                                   |

---

### System / OS Package Managers

#### `brew` (Homebrew)

| Command                    | Risk | Notes                                                  |
| -------------------------- | ---- | ------------------------------------------------------ |
| `brew install <formula>`   | 🔴    | Installs a formula/cask                                |
| `brew upgrade`             | 🔴    | Upgrades all installed packages                        |
| `brew upgrade <formula>`   | 🔴    | Upgrades specific package                              |
| `brew reinstall <formula>` | 🔴    | Reinstalls a package                                   |
| `brew bundle`              | 🔴    | Installs from `Brewfile`                               |
| `brew bundle install`      | 🔴    | Explicit bundle install                                |
| `brew tap <repo>`          | 🟠    | Adds a third-party repository — can introduce packages |

#### `apt` (Debian/Ubuntu/WSL)

> **Note:** `apt-get` commands listed below are intercepted through PKG-Defender's `apt` wrapper. Only `pkgd apt` is a supported invocation — `pkgd apt-get` is not a registered manager alias.

| Command                                | Risk | Notes                               |
| -------------------------------------- | ---- | ----------------------------------- |
| `apt install <pkg>`                    | 🔴    | Installs package                    |
| `apt-get install <pkg>`                | 🔴    | Installs package (traditional form) |
| `apt upgrade`                          | 🔴    | Upgrades all installed packages     |
| `apt full-upgrade`                     | 🔴    | Upgrades + handles dep changes      |
| `apt-get dist-upgrade`                 | 🔴    | Same as full-upgrade                |
| `apt-get install --only-upgrade <pkg>` | 🔴    | Upgrades specific package only      |

#### `dnf` / `yum` (RHEL/Fedora/CentOS)

| Command                       | Risk | Notes                          |
| ----------------------------- | ---- | ------------------------------ |
| `dnf install <pkg>`           | 🔴    | Installs package               |
| `yum install <pkg>`           | 🔴    | Legacy form                    |
| `dnf update` / `dnf upgrade`  | 🔴    | Updates all installed packages |
| `dnf update <pkg>`            | 🔴    | Updates specific package       |
| `dnf localinstall <file.rpm>` | 🟠    | Installs from local RPM file   |
| `dnf group install <group>`   | 🔴    | Installs a group of packages   |

#### `pacman` (Arch Linux)

| Command                | Risk | Notes                   |
| ---------------------- | ---- | ----------------------- |
| `pacman -S <pkg>`      | 🔴    | Install package         |
| `pacman -Sy <pkg>`     | 🔴    | Sync db + install       |
| `pacman -Su`           | 🔴    | System upgrade          |
| `pacman -Syu`          | 🔴    | Sync db + full upgrade  |
| `pacman -U <file.pkg>` | 🔴    | Install from local file |

#### `nix` / `nix-env`

| Command                                        | Risk | Notes                                    |
| ---------------------------------------------- | ---- | ---------------------------------------- |
| `nix-env -i <pkg>` / `nix-env --install <pkg>` | 🔴    | Install package into profile             |
| `nix-env -u` / `nix-env --upgrade`             | 🔴    | Upgrades all packages in profile         |
| `nix profile install <pkg>`                    | 🔴    | Modern nix profile install               |
| `nix profile upgrade <pkg>`                    | 🔴    | Modern nix profile upgrade               |
| `nix build`                                    | 🟡    | Builds derivation — downloads all inputs |
| `nix develop`                                  | 🟡    | Enters dev shell — downloads all deps    |
| `nix run <flake>`                              | 🟠    | Fetches and runs a flake package         |
| `nix shell <pkg>`                              | 🟠    | Temporary shell with package available   |

#### `snap`

| Command                             | Risk | Notes                                |
| ----------------------------------- | ---- | ------------------------------------ |
| `snap install <snap>`               | 🔴    | Installs a snap                      |
| `snap refresh`                      | 🔴    | Updates all installed snaps          |
| `snap refresh <snap>`               | 🔴    | Updates specific snap                |
| `snap switch <snap> --channel <ch>` | 🟠    | Changes channel — can trigger update |

#### `flatpak`

| Command                                    | Risk | Notes                      |
| ------------------------------------------ | ---- | -------------------------- |
| `flatpak install <app>`                    | 🔴    | Installs flatpak app       |
| `flatpak update`                           | 🔴    | Updates all installed apps |
| `flatpak update <app>`                     | 🔴    | Updates specific app       |
| `flatpak install --from <file.flatpakref>` | 🔴    | Installs from ref file     |

---

## Lock File Formats

Lockfiles are the primary audit surface for `pkgd audit` — they provide a complete, pinned snapshot of the dependency tree, including transitive dependencies. The table below provides a quick overview of supported lockfiles by ecosystem. See [Lock File Formats](../reference/lock-file-formats.md) for full details including format information, transitive dependency coverage, auditability notes, and detection guidance.

| Lockfile(s)              | Ecosystem               | Package Manager(s)               |
| ------------------------ | ----------------------- | -------------------------------- |
| `requirements.txt`       | Python / PyPI           | `pip` (pip-tools)                |
| `uv.lock`                | Python / PyPI           | `uv`                             |
| `poetry.lock`            | Python / PyPI           | `poetry`                         |
| `Pipfile.lock`           | Python / PyPI           | `pipenv`                         |
| `pdm.lock`               | Python / PyPI           | `pdm`                            |
| `conda-lock.yml`         | Python / Data Science   | `conda`                          |
| `package-lock.json`      | JavaScript / Node       | `npm`                            |
| `yarn.lock`              | JavaScript / Node       | `yarn` (v1 Classic, v2–v4 Berry) |
| `pnpm-lock.yaml`         | JavaScript / Node       | `pnpm`                           |
| `bun.lockb` / `bun.lock` | JavaScript / Node       | `bun`                            |
| `deno.lock`              | JavaScript / TypeScript | `deno`                           |
| `Gemfile.lock`           | Ruby                    | `bundler`                        |
| `composer.lock`          | PHP                     | `composer`                       |
| `Cargo.lock`             | Rust                    | `cargo`                          |
| `gradle.lockfile`        | Java / Kotlin / JVM     | `gradle`                         |
| `go.sum`                 | Go                      | `go`                             |
| `packages.lock.json`     | .NET / C#               | `nuget`, `dotnet`                |
| `Package.resolved`       | Swift / Apple           | `swift package` (SPM)            |
| `Podfile.lock`           | Swift / Obj-C           | `cocoapods`                      |
| `Cartfile.resolved`      | Swift / Obj-C           | `carthage`                       |
| `Brewfile.lock.json`     | System / Mixed          | `brew` (Homebrew)                |
| `flake.lock`             | System / Mixed          | `nix`                            |

> **Note:** Of the 22 formats listed above, only 7 are currently parseable by PKG-Defender: `package-lock.json`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `yarn.lock`, `pnpm-lock.yaml`, and `uv.lock` (see [`parse_lock_file()` at `parsers.py:52-79`](https://github.com/divisionseven/pkg-defender/blob/main/src/pkg_defender/core/parsers.py)). The remaining formats are aspirational targets for future releases.

---

## Ecosystem Reference

### Python

| Property                    | Details                                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Primary Registry**        | PyPI (pypi.org)                                                                                                    |
| **Advisory Sources**        | PyPI Advisory DB, OSV.dev (PyPI), Safety DB                                                                        |
| **Supported OS**            | macOS, Linux, Windows (all)                                                                                        |
| **Interception Complexity** | Medium — multiple competing tools, many aliases (`pip`, `pip3`, `python -m pip`)                                   |
| **Key Risk Factors**        | Typosquatting is extremely common on PyPI; dependency confusion attacks; malicious `setup.py` execution on install |

**Notes:**

- `python -m pip install` is equivalent to `pip install` and must also be intercepted.
- `uv` is the fastest-growing Python package manager.
- Conda uses a completely separate channel-based ecosystem and pulls from `conda-forge` rather than PyPI. Packages have different names and hashes — requires a separate adapter.
- Editable installs (`pip install -e .`) often pull transitive deps from PyPI and must be audited.

---

### JavaScript / Node.js

| Property                    | Details                                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Primary Registry**        | npmjs.com                                                                                                                      |
| **Advisory Sources**        | npm Advisory DB, OSV.dev (npm), Socket.dev, Snyk                                                                               |
| **Supported OS**            | macOS, Linux, Windows (all)                                                                                                    |
| **Interception Complexity** | High — `npx`, `yarn dlx`, `pnpm dlx`, `bunx` all silently download packages                                                    |
| **Key Risk Factors**        | Largest registry by volume; highest frequency of supply chain incidents; malicious `postinstall` scripts; dependency confusion |

**Notes:**

- **`npx` / `yarn dlx` / `pnpm dlx` / `bunx`** are the highest-risk commands in the ecosystem — they silently download and immediately execute a package in a single step, giving zero opportunity for manual review.
- **Yarn v1 vs Berry** are both still in widespread use and must be version-detected from the `yarn.lock` header comment (`# yarn lockfile v1` indicates Classic).
- **`npm ci`** is the CI-specific install command and is extremely common in automated pipelines — PKG-Defender's `--ci` mode must handle it correctly.
- postinstall scripts are a primary malware vector — an audit of the package's `package.json` lifecycle scripts should be part of the threat analysis.

---

### Ruby

| Property                    | Details                                                                         |
| --------------------------- | ------------------------------------------------------------------------------- |
| **Primary Registry**        | RubyGems.org                                                                    |
| **Advisory Sources**        | RubyGems Advisory Database, OSV.dev (RubyGems), Bundler Audit                   |
| **Supported OS**            | macOS (native), Linux, Windows (limited)                                        |
| **Interception Complexity** | Low — two tools (`gem`, `bundle`) with clear command patterns                   |
| **Key Risk Factors**        | Gem `extconf.rb` / native extensions can execute arbitrary code at install time |

---

### PHP

| Property                    | Details                                                                         |
| --------------------------- | ------------------------------------------------------------------------------- |
| **Primary Registry**        | Packagist.org                                                                   |
| **Advisory Sources**        | FriendsOfPHP/security-advisories, OSV.dev (Packagist)                           |
| **Supported OS**            | macOS, Linux, Windows                                                           |
| **Interception Complexity** | Low — single tool (`composer`) with clean command surface                       |
| **Key Risk Factors**        | Composer scripts (`post-install-cmd`) can execute arbitrary PHP at install time |

---

### JVM (Java / Kotlin / Scala)

| Property                    | Details                                                                                                                                  |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Registry**        | Maven Central (search.maven.org), JCenter (deprecated), GitHub Packages                                                                  |
| **Advisory Sources**        | OSV.dev (Maven), Sonatype OSS Index, GitHub Advisory Database                                                                            |
| **Supported OS**            | macOS, Linux, Windows (all — JVM is cross-platform)                                                                                      |
| **Interception Complexity** | High — downloads happen as a **side effect of build commands**, not explicit install commands                                            |
| **Key Risk Factors**        | No CLI install command to hook; dep resolution happens during `mvn compile` or `gradle build`; Gradle plugins can execute arbitrary code |

**Notes:**

- Java/Kotlin is uniquely difficult to intercept because there is no discrete "install" command. The correct approach is **pre-build lockfile auditing** rather than command interception.
- Gradle's dependency locking is opt-in and often disabled. Without `gradle.lockfile`, auditing requires parsing `build.gradle(.kts)` — consider flagging this in `pkgd audit`.

---

### Go

| Property                    | Details                                                                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Registry**        | proxy.golang.org (GOPROXY), pkg.go.dev                                                                                                                  |
| **Advisory Sources**        | OSV.dev (Go), Go vulnerability database (vuln.go.dev), GitHub Advisory Database                                                                         |
| **Supported OS**            | macOS, Linux, Windows (all)                                                                                                                             |
| **Interception Complexity** | Medium — `go get` and `go install` are the primary intercept points                                                                                     |
| **Key Risk Factors**        | `go install` pulls from arbitrary VCS URLs (not just a central registry); module path spoofing; `replace` directives in `go.mod` can substitute modules |

**Notes:**

- Go modules can be sourced directly from GitHub, GitLab, or any git server — not just a central registry. Threat detection must handle VCS-sourced modules.
- The `GONOSUMCHECK` and `GONOSUMDB` env vars can bypass checksum verification — consider flagging when these are set.

---

### .NET / C #

| Property                    | Details                                                                                      |
| --------------------------- | -------------------------------------------------------------------------------------------- |
| **Primary Registry**        | nuget.org                                                                                    |
| **Advisory Sources**        | OSV.dev (NuGet), GitHub Advisory Database, Microsoft Security Advisories                     |
| **Supported OS**            | Windows (primary), macOS, Linux (.NET 5+)                                                    |
| **Interception Complexity** | Medium — `dotnet add package` is clean; `dotnet restore` / `dotnet build` implicitly restore |
| **Key Risk Factors**        | NuGet packages can include MSBuild targets that execute at build time                        |

---

### Rust

| Property                    | Details                                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Primary Registry**        | crates.io                                                                                                     |
| **Advisory Sources**        | RustSec Advisory Database (rustsec.org), OSV.dev (crates.io), GitHub Advisory Database                        |
| **Supported OS**            | macOS, Linux, Windows (all)                                                                                   |
| **Interception Complexity** | Medium — `cargo install` and `cargo build` are distinct interception points                                   |
| **Key Risk Factors**        | `build.rs` build scripts run arbitrary code at compile time; `cargo install --git` pulls from arbitrary repos |

**Notes:**

- The **RustSec Advisory Database** is one of the most mature and well-maintained security advisory DBs in any ecosystem — excellent OSV.dev integration.
- `Cargo.lock` is always present and pinned for binary crates. Library crates may omit it, but any installed binary will have one.

---

### Swift / Apple Platforms

| Property                    | Details                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| **Primary Registry**        | No central registry — deps sourced from GitHub/GitLab URLs in `Package.swift`              |
| **Advisory Sources**        | GitHub Advisory Database, OSV.dev (limited Swift coverage)                                 |
| **Supported OS**            | macOS (primary), Linux (SPM only — no CocoaPods/Carthage)                                  |
| **Interception Complexity** | Low — limited set of commands; macOS-only largely limits exposure                          |
| **Key Risk Factors**        | No central registry means no centralized advisory data; deps reference arbitrary git repos |

**Notes:**

- CocoaPods and Carthage are both in declining use in favor of SPM, but still present in many large Obj-C/Swift codebases.
- Advisory coverage is sparse compared to npm/PyPI/crates.io — threat intelligence is primarily GitHub Advisory Database data.

---

### System / OS Package Managers

| Property                    | Details                                                                                                                     |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Primary Registries**      | Various (apt repos, RPM repos, AUR, Nixpkgs, Snap Store, Flathub)                                                           |
| **Advisory Sources**        | OS vendor security bulletins (Ubuntu USN, Fedora, Arch, etc.)                                                               |
| **Supported OS**            | Linux (all), macOS (Homebrew only), Windows (WSL via apt)                                                                   |
| **Interception Complexity** | Low — command surface is small and consistent                                                                               |
| **Key Risk Factors**        | Lower risk than language PMs — most have signing infrastructure. Homebrew taps and third-party Snap sources are exceptions. |

**Notes:**

- OS-level package managers generally have **better signing and verification infrastructure** than language package managers and are lower priority for supply chain attack mitigation.
- **Homebrew is the exception** — third-party taps (`brew tap <user/repo>`) can introduce completely unvetted formula files from arbitrary GitHub repos. `brew install` from a tap is a real attack vector.
- **Snap** packages are sandboxed but the Snap Store has had incidents with malicious submissions.
- For `apt`/`dnf`/`yum`, the primary value PKG-Defender adds is **threat checking** against known vulnerability databases, since signature verification is already handled by the OS package manager. Cooldown enforcement is skipped for these `AUDIT`-tier managers, as curated OS repositories publish only vetted packages.

---

## Interception Architecture Notes

### Command Alias Problem

Several managers have **multiple equivalent invocations** that all require interception:

| Canonical Command | Aliases / Equivalents                                             |
| ----------------- | ----------------------------------------------------------------- |
| `pip install`     | `pip3 install`, `python -m pip install`, `python3 -m pip install` |
| `npm install`     | `npm i`, `npm add`                                                |
| `yarn add`        | (v1 and v2/v3/v4 `yarn add` are different internally)             |
| `pnpm install`    | `pnpm i`                                                          |
| `npx`             | `npm exec`, `npm x`                                               |
| `bunx`            | `bun x`                                                           |
| `mvn install`     | `./mvnw install`, `mvn verify`, `mvn package`, `mvn compile`      |
| `gradle build`    | `./gradlew build`, `gradlew.bat build`                            |

### Ecosystem Name Aliases

PKG-Defender accepts both CLI manager names and ecosystem-style names via an internal alias map:

| CLI Name   | Ecosystem Alias |
| ---------- | --------------- |
| `pip`      | `pypi`          |
| `gem`      | `rubygems`      |
| `cargo`    | `crates`        |
| `brew`     | `homebrew`      |
| `composer` | `packagist`     |

For example, `pkgd pypi install requests` is equivalent to `pkgd pip install requests`, and `pkgd rubygems install rails` is equivalent to `pkgd gem install rails`. These aliases are defined in `ECOSYSTEM_ALIAS_MAP` at `src/pkg_defender/registry/__init__.py`.

### Silent Dependency Installation

The following commands download and install packages **without the word "install" appearing** — they are the highest risk for slipping past naive interception:

| Command           | Manager    | What It Does                               |
| ----------------- | ---------- | ------------------------------------------ |
| `npx <pkg>`       | npm        | Downloads + executes a package             |
| `yarn dlx <pkg>`  | yarn Berry | Downloads + executes a package             |
| `pnpm dlx <pkg>`  | pnpm       | Downloads + executes a package             |
| `bunx <pkg>`      | bun        | Downloads + executes a package             |
| `uv run <script>` | uv         | Installs deps silently before running      |
| `hatch run <cmd>` | hatch      | Creates env + installs deps before running |
| `go build`        | go         | Downloads missing modules                  |
| `go run <file>`   | go         | Downloads missing modules                  |
| `dotnet build`    | dotnet     | Triggers implicit restore                  |
| `mvn compile`     | maven      | Resolves + downloads all deps              |
| `gradle build`    | gradle     | Resolves + downloads all deps              |
| `cargo build`     | cargo      | Downloads + compiles all dep crates        |
| `swift build`     | swift      | Resolves + downloads SPM deps              |

---

## Implementation Priority

### Tier 1 — Core

These cover the vast majority of real-world supply chain incidents. Must reach production quality before initial release.

| Manager             | Rationale                                                  |
| ------------------- | ---------------------------------------------------------- |
| `pip` / `pip3`      | Largest Python attack surface; most common PyPI incidents  |
| `uv`                | Fastest-growing Python PM; same PyPI registry as pip       |
| `npm`               | Largest registry in the world; most frequent attack target |
| `yarn` (v1 + Berry) | Massive existing install base; same npm registry           |
| `pnpm`              | Rapidly growing; same npm registry; monorepo standard      |

### Tier 2 — High Value

Significant userbases with real supply chain incidents in the wild.

| Manager           | Rationale                                                                                |
| ----------------- | ---------------------------------------------------------------------------------------- |
| `poetry`          | Growing Python standard; well-used in ML/data science                                    |
| `pipenv`          | Large legacy install base                                                                |
| `bun`             | Fast-growing; silently executing `bunx` is high risk                                     |
| `cargo`           | RustSec DB is excellent; `cargo install --git` is high risk                              |
| `gem` / `bundler` | Ruby ecosystem; active in Rails/DevOps tooling                                           |
| `composer`        | PHP ecosystem; massive CMS install base                                                  |
| `conda`           | Data science standard; separate registry from PyPI; fully implemented with FULL coverage |

### Tier 3 — Extended

Meaningful userbases, lower incident frequency, more complex interception.

| Manager            | Rationale                                             |
| ------------------ | ----------------------------------------------------- |
| `pdm`              | Growing Python PM with excellent lockfile             |
| `maven`            | JVM standard; lockfile-audit-only approach            |
| `gradle`           | JVM alternative; lockfile-audit-only approach         |
| `nuget` / `dotnet` | .NET ecosystem; Windows-primary                       |
| `go`               | Go modules; VCS-direct installs are high risk         |
| `deno`             | Growing; URL-based modules are a unique challenge     |
| `hatch`            | Newer Python PM; growing in the packaging-tools space |

### Tier 4 — Stretch Goals

Lower supply chain incident frequency or OS-level signing handles most risk.

| Manager         | Rationale                                                       |
| --------------- | --------------------------------------------------------------- |
| `swift package` | macOS-only; sparse advisory data                                |
| `cocoapods`     | Declining use; macOS-only                                       |
| `carthage`      | Declining use; macOS-only                                       |
| `brew`          | Homebrew taps are a real risk; large macOS install base         |
| `apt`           | Signed repos reduce risk; WSL use cases exist                   |
| `dnf` / `yum`   | Same as apt                                                     |
| `pacman`        | Same as apt; AUR is higher risk                                 |
| `nix`           | Strong reproducibility model; Nixpkgs is well-audited           |
| `snap`          | Snap Store has had incidents; sandboxed but still installs code |
| `flatpak`       | Same as snap                                                    |
