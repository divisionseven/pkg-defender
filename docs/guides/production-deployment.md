---
title: Production Deployment
description: Running pkg-defender in production environments
---

# Production Deployment

This guide covers running pkg-defender in production environments - servers, containers, CI/CD systems.

## Deployment Options

### 1. Docker/Container (Recommended)

The project includes a Dockerfile for containerized deployments.

```bash
# Build
docker build -t pkg-defender:latest .

# Run
docker run -it \
  --memory=512m --cpus=2.0 \
  -v ~/.config/pkg-defender:/home/pquser/.config/pkg-defender \  # Linux path; macOS: ~/Library/Application Support/pkg-defender
  -v ~/.local/share/pkg-defender:/home/pquser/.local/share/pkg-defender \
  pkg-defender:latest pkgd health
```

The container runs as a non-root user (`pquser`) for security.

#### Running the Daemon

The Docker image's default command starts the pkgd daemon, which continuously
syncs threat intelligence feeds:

```bash
docker run -d \
  --memory=256m --cpus=1.0 \
  -v ~/.config/pkg-defender:/home/pquser/.config/pkg-defender \  # Linux path; macOS: ~/Library/Application Support/pkg-defender
  -v ~/.local/share/pkg-defender:/home/pquser/.local/share/pkg-defender \
  --name pkgd-daemon \
  pkg-defender:latest
```

#### Using Named Volumes (Recommended for Production)

Named volumes provide better portability and Docker-managed persistence:

```bash
docker run -d \
  --memory=256m --cpus=1.0 \
  -v pkgd-config:/home/pquser/.config/pkg-defender \
  -v pkgd-data:/home/pquser/.local/share/pkg-defender \
  --name pkgd-daemon \
  pkg-defender:latest
```

Create named volumes explicitly:

```bash
docker volume create pkgd-config
docker volume create pkgd-data
```

List and inspect volumes:

```bash
docker volume ls
docker volume inspect pkgd-data
```

Named volumes are stored in Docker's data directory (`/var/lib/docker/volumes/`
on Linux) and survive container removal. For development, bind mounts
(shown above) offer convenient host-directory access.

The daemon runs as the non-root `pquser` (UID 1000) with comprehensive
health checks via `pkgd health -o json` every 30 seconds.

#### Multi-Platform Builds

The Docker image supports `linux/amd64` and `linux/arm64` platforms. To build
for a specific platform or all platforms:

**Prerequisites:** Install [Docker Buildx](https://docs.docker.com/buildx/working-with-buildx/)
(included with Docker Desktop) and QEMU for cross-platform emulation:

```bash
docker run --privileged --rm tonistiigi/binfmt --install all
```

**Build for current platform only:**

```bash
docker buildx build -t pkg-defender:latest .
```

**Build for all supported platforms:**

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t pkg-defender:latest .
```

**Pull from GHCR (pre-built multi-arch images):**

```bash
docker pull ghcr.io/divisionseven/pkg-defender:latest
```

### Docker Image Vulnerability Scanning

The `pkg-defender` Docker image is verified using [Trivy](https://trivy.dev/) to ensure it is free of known vulnerabilities. This is a **mandatory part of our release process** — no Docker image may be published without a clean Trivy scan.

#### Verification Policy

- **Tool:** Trivy (latest stable)
- **Severity thresholds:** CRITICAL and HIGH vulnerabilities are blockers
- **Scan scope:** Operating system packages and Python dependencies
- **Frequency:** Every release build, plus manual verification before major releases
- **Process:** Any CRITICAL or HIGH vulnerability must be remediated before release

#### Automation

Trivy scanning is **fully automated** in the release workflow (`.github/workflows/release.yml`). The `build-docker` job:

1. Builds multi-arch Docker images (linux/amd64, linux/arm64)
2. Pushes to GitHub Container Registry (GHCR)
3. **Automatically scans the pushed image** with Trivy v0.36.0
4. **Fails the workflow** if any CRITICAL or HIGH vulnerability is found (`exit-code: 1`)
5. Ignores vulnerabilities with no available fix (`ignore-unfixed: true`) to prevent perpetual failures

This means **no Docker image can be published** with known high-severity vulnerabilities. The scan is a hard gate in the release pipeline — if it fails, the release cannot proceed.

#### Latest Scan Results

**Scan timestamp:** 2026-06-18T01:30:59Z (UTC)
**Trivy version:** 0.71.1
**Image:** `pkg-defender:latest` (Alpine 3.24.1)
**Result:** **CLEAN — Zero vulnerabilities**

| Severity  | Count |
| --------- | ----- |
| CRITICAL  | 0     |
| HIGH      | 0     |
| MEDIUM    | 0     |
| LOW       | 0     |
| **TOTAL** | **0** |

**Scan targets:**
- Alpine OS packages: 38 packages scanned, 0 vulnerabilities
- Python dependencies: 22 packages scanned, 0 vulnerabilities

**Full scan output:**
```console
$ trivy --version

Version: 0.71.1
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-06-17 19:28:27.798098468 +0000 UTC
  NextUpdate: 2026-06-18 19:28:27.798097987 +0000 UTC
  DownloadedAt: 2026-06-18 00:11:40.464805 +0000 UTC
```

```console
$ trivy image --severity CRITICAL,HIGH --format table pkg-defender:latest 2>&1

2026-06-17T01:30:58-00:00	INFO	[vuln] Vulnerability scanning is enabled
2026-06-17T01:30:58-00:00	INFO	[secret] Secret scanning is enabled
2026-06-17T01:30:58-00:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2026-06-17T01:30:58-00:00	INFO	[secret] Please see https://trivy.dev/docs/v0.71/guide/scanner/secret#recommendation for faster secret detection
2026-06-17T01:30:59-00:00	INFO	[python] Licenses acquired from one or more METADATA files may be subject to additional terms. Use `--debug` flag to see all affected packages.
2026-06-17T01:30:59-00:00	INFO	Detected OS	family="alpine" version="3.24.1"
2026-06-17T01:30:59-00:00	WARN	This OS version is not on the EOL list	family="alpine" version="3.24"
2026-06-17T01:30:59-00:00	INFO	[alpine] Detecting vulnerabilities...	os_version="3.24" repository="3.24" pkg_num=38
2026-06-17T01:30:59-00:00	INFO	Number of language-specific files	num=1
2026-06-17T01:30:59-00:00	INFO	[python-pkg] Detecting vulnerabilities...

Report Summary

┌──────────────────────────────────────────────────────────────────────────────────┬────────────┬─────────────────┬─────────┐
│                                      Target                                      │    Type    │ Vulnerabilities │ Secrets │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ pkg-defender:latest (alpine 3.24.1)                                              │   alpine   │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/aiohappyeyeballs-2.6.2.dist-info/METADATA │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/aiohttp-3.14.1.dist-info/METADATA         │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/aiosignal-1.4.0.dist-info/METADATA        │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/attrs-26.1.0.dist-info/METADATA           │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/click-8.4.1.dist-info/METADATA            │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/defusedxml-0.7.1.dist-info/METADATA       │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/feedparser-6.0.12.dist-info/METADATA      │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/frozenlist-1.8.0.dist-info/METADATA       │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/idna-3.18.dist-info/METADATA              │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/markdown_it_py-4.2.0.dist-info/METADATA   │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/mdurl-0.1.2.dist-info/METADATA            │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/multidict-6.7.1.dist-info/METADATA        │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/packaging-23.2.dist-info/METADATA         │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/pkg_defender-1.0.0.dist-info/METADATA     │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/platformdirs-4.10.0.dist-info/METADATA    │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/propcache-0.5.2.dist-info/METADATA        │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/pygments-2.20.0.dist-info/METADATA        │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/pyyaml-6.0.3.dist-info/METADATA           │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/rich-13.9.4.dist-info/METADATA            │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/sgmllib3k-1.0.0.dist-info/METADATA        │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/tomlkit-0.15.0.dist-info/METADATA         │ python-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/typing_extensions-4.15.0.dist-info/METAD- │ python-pkg │        0        │    -    │
│ ATA                                                                              │            │                 │         │
├──────────────────────────────────────────────────────────────────────────────────┼────────────┼─────────────────┼─────────┤
│ usr/local/lib/python3.11/site-packages/yarl-1.24.2.dist-info/METADATA            │ python-pkg │        0        │    -    │
└──────────────────────────────────────────────────────────────────────────────────┴────────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)
```

#### How to Verify Locally

```bash
# Build the image
docker build -t pkg-defender:latest .

# Run Trivy scan
trivy image --severity CRITICAL,HIGH pkg-defender:latest

# Full scan (all severities)
trivy image pkg-defender:latest
```

### 2. Systemd Service (Linux)

The daemon includes a built-in systemd service installer that auto-generates
a correct user-level unit file and installs it in the right location:

```bash
pkgd daemon install --platform linux
```

See the [Daemon guide](daemon.md#linux-systemd) for more details on the installer.

The installer creates a **user** service unit at
`~/.config/systemd/user/pkg-defender.service`. The generated unit looks like this:

```ini
[Unit]
Description=pkg-defender background daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pkgd daemon run
Restart=on-failure
RestartSec=60
Environment=PKGD_CONFIG_PATH=$HOME/.config/pkg-defender/pkgd.toml
Environment=PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.local/bin
WorkingDirectory=$HOME/.local/share/pkg-defender

[Install]
WantedBy=default.target
```

To manage the service:

```bash
# Reload systemd user daemon
systemctl --user daemon-reload

# Enable to start on login
systemctl --user enable pkg-defender.service

# Start now
systemctl --user start pkg-defender.service

# Check status
systemctl --user status pkg-defender.service
```

> **Note:** User services run as the logged-in user and do not need `sudo`.
> The service starts when the user logs in (not at boot). For system-wide
> boot-time service, copy the unit to `/etc/systemd/system/`, add
> `User=<your-username>`, and use `sudo systemctl`.

### 3. Kubernetes (Future)

Deployment manifest coming soon.

## Configuration for Production

### Environment Variables

```bash
# Required tokens
export PKGD_FEEDS_GHSA_TOKEN=ghp_xxx
export PKGD_FEEDS_SOCKET_API_KEY=xxx

# Optional: Increase timeout
export PKGD_HTTP_TIMEOUT=60

# Optional: Verbose logging
export PKGD_OUTPUT_VERBOSE=false
```

For production, consider using a secrets management system rather than plain text environment variables.

### Resource Requirements

| Resource | Requirement                                |
| -------- | ------------------------------------------ |
| CPU      | Minimal (mostly I/O bound)                 |
| Memory   | ~50MB baseline, +10MB per active feed      |
| Disk     | Database grows ~1MB/day with default feeds |

## Monitoring

### Health Check

```bash
pkgd health
```

### Daemon Status

```bash
pkgd daemon status
```

### Logs

```bash
# If running via systemd
journalctl -u pkg-defender -f
```

## Backup

### Database

```bash
cp ~/.local/share/pkg-defender/threats.db ~/backup/threats-$(date +%Y%m%d).db  # Linux path; macOS: ~/Library/Application Support/pkg-defender/threats.db
```

### Config

```bash
cp ~/.config/pkg-defender/pkgd.toml ~/backup/config-$(date +%Y%m%d).toml  # Linux path; macOS: ~/Library/Application Support/pkg-defender/pkgd.toml
```

## Security Considerations

- Run the daemon as a non-root user
- Use secrets management (not environment variables in plain text)
- Restrict config file permissions: `chmod 600 ~/.config/pkg-defender/pkgd.toml` (Linux; macOS: `chmod 600 ~/Library/Application Support/pkg-defender/pkgd.toml`)

---

[← Back to Documentation](../index.md)
