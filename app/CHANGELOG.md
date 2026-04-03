# Changelog

All notable changes to ARGOS are documented here.

This project follows [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR** — incompatible API or schema changes
- **MINOR** — new features, backward compatible
- **PATCH** — bug fixes, backward compatible

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## [Unreleased]

Changes on `main` not yet in a release.

### Added
- Central server (FastAPI) with REST API and WebSocket support
- PostgreSQL and SQLite database support via SQLAlchemy async
- Redis integration for real-time event streaming
- Device registration and heartbeat system
- AI Engine with Ollama integration (Phi-4 14B default)
- Rule-based fallback engine for offline operation
- Claude API escalation for unprecedented threats (optional)
- Continuous fine-tuning pipeline with LoRA
- Cross-platform agent (Linux, macOS, Windows)
- Network monitor with port scan and repeat offender detection
- Process monitor with cryptominer and ransomware detection
- Native OS firewall integration (iptables / pf / netsh)
- TCP honeypot engine with evidence collection
- Process suspension and isolation
- Three deployment modes: standalone, self-hosted, cloud
- Three autonomy levels: full, semi, supervised
- IP blocking with optional expiry
- IP enrichment via AbuseIPDB and ip-api.com
- React web dashboard with real-time threat feed
- React Native mobile app for iOS and Android
- Docker Compose full stack deployment
- Community intelligence sharing (opt-in, schema defined)

### Planned for 0.1.0
- Filesystem integrity monitor
- Auth log parser (Linux, macOS, Windows)
- DDoS detection module
- Installer scripts (systemd, LaunchDaemon, Windows Service)
- TLS certificate generation helper
- First-run setup wizard
- Automated test suite

---

## [0.1.0] — TBD

*First public release. Alpha — expect breaking changes.*

### Notes

This is the initial public release of ARGOS. The core architecture is stable but many features are still under active development. We recommend running in `supervised` autonomy mode and evaluating the system for at least two weeks before switching to `semi` or `full` autonomy.

Breaking changes between 0.x releases may occur without deprecation notices. We will stabilize the API at 1.0.0.

---

## Version Roadmap

| Version | Target | Focus |
|---------|--------|-------|
| 0.1.0 | Q2 2026 | Core agent + server + dashboard — first public alpha |
| 0.2.0 | Q3 2026 | Filesystem monitor + auth log parser + DDoS module |
| 0.3.0 | Q3 2026 | Baseline learning + false positive reduction |
| 0.4.0 | Q4 2026 | Community intelligence sharing (live) |
| 0.5.0 | Q4 2026 | One-click installers for all platforms |
| 0.6.0 | Q1 2027 | Plugin system for custom detectors |
| 1.0.0 | Q2 2027 | Stable API, production-ready, full test coverage |

---

## How to Read This Changelog

Each release section contains:

- **Added** — new features
- **Changed** — changes to existing functionality
- **Deprecated** — features that will be removed in a future version
- **Removed** — features removed in this release
- **Fixed** — bug fixes
- **Security** — security vulnerability fixes (always upgrade immediately for these)

Security fixes also reference the associated security advisory (ARGOS-SA-YYYY-NNN).

---

*ARGOS — Security is a right, not a privilege.*
