# Security Policy

PKG-Defender is a security tool, and we take its own security posture extremely seriously.
We appreciate the responsible disclosure of vulnerabilities and aim to acknowledge and address them promptly.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Public disclosure before a patch is available puts all PKG-Defender users at risk.
We ask that you follow responsible disclosure practices.

### Preferred Method: GitHub Private Security Advisory

Use GitHub's built-in private advisory system to report vulnerabilities confidentially:

**[Report a vulnerability &rarr;](https://github.com/divisionseven/pkg-defender/security/advisories/new)**

This creates a private, encrypted channel between you and the maintainer. You can include full technical details, proof-of-concept code, and suggested mitigations without any of it being publicly visible.

### What to Include in Your Report

The more information you provide, the faster we can triage and address the issue.
Please include as many of the following as possible:

- **Description** — a clear explanation of the vulnerability and its potential impact
- **Affected component(s)** — which part of PKG-Defender is affected (e.g. feed ingestion, cooldown engine, CLI, daemon)
- **Affected versions** — which version(s) of PKG-Defender are vulnerable
- **Reproduction steps** — step-by-step instructions to reproduce the issue
- **Proof of concept** — code, commands, or a demo that demonstrates the vulnerability
- **Suggested fix** — if you have a patch or proposed mitigation
- **Your preferred attribution** — how you'd like to be credited in the security advisory (or if you prefer to remain anonymous)

---

## Our Commitment to You

When you report a vulnerability responsibly, we commit to:

|                     |                                                                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Acknowledgement** | We aim to acknowledge receipt of your report within **48 hours**.                                                          |
| **Triage**          | We aim to assess severity and confirm whether the issue is valid within **7 days**.                                        |
| **Resolution**      | We will work on a fix and coordinate a release timeline with you.                                                          |
| **Disclosure**      | We will publish a public security advisory once a patch is released, crediting you (if desired).                           |
| **Coordination**    | We aim to keep you informed throughout the process and give you the opportunity to review the advisory before publication. |

---

## Scope

The following are **in scope** for vulnerability reports:

- The `pkgd` CLI and all its subcommands
- The threat intelligence feed ingestion system
- The cooldown engine and enforcement logic
- The SQLite threat database
- The background daemon
- The CI/CD integration components
- Dependency vulnerabilities in PKG-Defender's own dependency tree

The following are generally **out of scope**, unless they have a specific impact on PKG-Defender:

- Vulnerabilities in third-party packages that PKG-Defender depends on (please report those upstream)
- Issues in GitHub Actions runners or the GitHub platform itself
- Social engineering attacks against the maintainer
- Theoretical vulnerabilities without a realistic attack scenario

For a detailed explanation of pkg-defender's security design, threat model, and known limitations, see the [Security Model](docs/explanation/security-model.md) documentation.

---

## Acknowledgements

We are grateful to everyone who has responsibly disclosed vulnerabilities to us.
Contributors will be listed here with their permission.

*(None yet — be the first!)*
