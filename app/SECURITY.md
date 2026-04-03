# Security Policy

ARGOS is a security tool. We take the security of the software itself extremely seriously — a vulnerability in ARGOS could expose the very infrastructure it is meant to protect.

---

## Supported Versions

We actively maintain and patch the following versions:

| Version | Supported |
|---------|-----------|
| 0.x (latest) | ✅ Active development and security patches |
| Older versions | ❌ Please upgrade |

We recommend always running the latest version. Security patches are released as soon as possible after a vulnerability is confirmed.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

A public disclosure before a fix is available could expose ARGOS users to active attacks.

### How to Report

Email **security@argos-security.io** with the following information:

**Required:**
- Description of the vulnerability
- Steps to reproduce — as detailed as possible
- Potential impact — what an attacker could do if they exploited this
- Affected versions — which versions of ARGOS are affected

**Optional but helpful:**
- Proof of concept — code, screenshots, or video
- Suggested fix — if you have ideas about how to address it
- Whether you want to be credited — and if so, how

### PGP Encryption

For sensitive reports, you can encrypt your email with our PGP key:

```
Key ID: [to be published on first release]
Fingerprint: [to be published on first release]
Download: https://argos-security.io/pgp-key.asc
```

---

## What to Expect

### Response Timeline

| Stage | Target Time |
|-------|-------------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 7 days |
| Status update | Every 7 days during investigation |
| Fix released | Within 30 days for critical/high, 90 days for lower severity |

We may ask for clarification or additional details. We will keep you informed throughout the process.

### Severity Assessment

We use the CVSS v3.1 scoring system to assess severity:

| Severity | CVSS Score | Examples |
|----------|-----------|---------|
| Critical | 9.0–10.0 | RCE on ARGOS server, auth bypass, mass data exposure |
| High | 7.0–8.9 | Privilege escalation, significant data exposure, DoS |
| Medium | 4.0–6.9 | Limited data exposure, local privilege escalation |
| Low | 0.1–3.9 | Minimal impact, requires physical access |

### Disclosure

Once a fix is available and deployed:

1. We publish a security advisory on GitHub
2. We release a patched version
3. We credit the reporter in the advisory and release notes (unless anonymity is preferred)
4. We update the CHANGELOG.md

We aim for coordinated disclosure — we ask that reporters wait for our fix before publishing their own writeups. We will work with you on timing if you have a conference presentation or blog post planned.

---

## Scope

### In Scope

Vulnerabilities we want to know about:

- **Remote Code Execution** — any path to executing code on ARGOS server or agent machines
- **Authentication Bypass** — bypassing token authentication on the API
- **Privilege Escalation** — gaining higher privileges than intended within ARGOS
- **Data Exposure** — unauthorized access to threat logs, evidence files, or configuration
- **Injection** — SQL injection, command injection, or similar
- **Denial of Service** — crashing the ARGOS server or agent process
- **WebSocket hijacking** — unauthorized access to real-time event stream
- **Training data poisoning** — injecting malicious data into the AI training pipeline
- **Dependency vulnerabilities** — critical CVEs in our direct dependencies that affect ARGOS

### Out of Scope

- Vulnerabilities in third-party tools ARGOS integrates with (Ollama, PostgreSQL, Redis) — report those to the respective projects
- Issues requiring physical access to the protected machine
- Social engineering attacks
- Self-XSS (you can only attack yourself)
- Issues in test or example code that is clearly not production
- Rate limiting on public endpoints without a realistic attack scenario
- Missing security headers on the dashboard when running without HTTPS

---

## Security Design Principles

Understanding how ARGOS is designed helps contextualize vulnerabilities.

### Agent Security

- The agent runs with elevated privileges because it needs to interact with the OS firewall and monitor network connections. This is intentional and necessary.
- The agent communicates with the central server over TLS. All tokens are transmitted in headers, never in URLs.
- Honeypot listeners run as unprivileged child processes where possible.
- Evidence files are written to `~/.argos/evidence/` with permissions `600`.

### Server Security

- The server performs token validation on every request.
- Database queries use parameterized statements via SQLAlchemy — direct string interpolation into queries is forbidden.
- The AI engine only processes structured threat data, never arbitrary user input in free-form text.
- Training data is validated before being written to disk or used in fine-tuning.

### Known Limitations

We are transparent about current limitations that are known but not yet addressed:

- **No mutual TLS** — agents authenticate to the server, but the server does not authenticate to agents. A compromised network could MITM agent-to-server communication.
- **Token rotation** — API tokens are currently long-lived with no automatic rotation. Manual rotation is supported.
- **Training pipeline** — the fine-tuning pipeline runs as the server user. A malicious training example could potentially influence model behavior.
- **Honeypot fingerprinting** — sophisticated attackers may be able to identify ARGOS honeypots by their behavior patterns.

These are areas of active development. If you find exploitable paths in any of these, we still want to know.

---

## Safe Harbor

We will not pursue legal action against researchers who:

- Report vulnerabilities to us before public disclosure
- Do not access user data beyond what is necessary to demonstrate the vulnerability
- Do not degrade the availability of ARGOS services during research
- Act in good faith and follow this policy

We consider responsible security research a valuable contribution to the project and the community.

---

## Hall of Fame

We recognize security researchers who have responsibly disclosed vulnerabilities to ARGOS.

*ARGOS is in early development. Hall of Fame entries will be listed here as the project matures.*

---

## Contact

- Security reports: **security@argos-security.io**
- General security questions: GitHub Discussions (tag with `security`)
- Urgent issues: Discord `#security-reports` channel (maintainers only)

---

*Last updated: March 2026*
*ARGOS — Security is a right, not a privilege.*
