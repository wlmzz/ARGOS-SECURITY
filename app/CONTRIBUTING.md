# Contributing to ARGOS

First of all — thank you. ARGOS exists because people believe that security should be accessible to everyone, not just those who can afford enterprise contracts. Every contribution, no matter how small, is part of making that real.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Contribution Types](#contribution-types)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Community](#community)

---

## Code of Conduct

ARGOS is built on the principle that security is a right. We extend that same principle to our community: everyone is welcome here, regardless of background, experience level, or affiliation.

We ask that all contributors:

- Be respectful and constructive in all communications
- Welcome newcomers and help them get started
- Assume good faith in others' contributions
- Focus criticism on code and ideas, never on people
- Accept that maintainers have final say on architecture and design decisions

Behavior that will not be tolerated: harassment, discrimination, personal attacks, or any conduct that makes contributors feel unwelcome.

If you experience or witness a violation, contact the maintainers at conduct@argos-security.io. All reports are handled confidentially.

---

## How to Contribute

There are many ways to contribute to ARGOS beyond writing code:

- **Fix bugs** — look for issues labeled `bug` or `good first issue`
- **Add threat detectors** — new detection modules are always welcome
- **Improve the AI** — help curate training data, improve prompts, test models
- **Write documentation** — clarify, expand, translate, or fix anything in `/docs`
- **Test on your platform** — especially Windows and macOS, which get less testing
- **Report issues** — a well-written bug report is incredibly valuable
- **Review pull requests** — help others improve their contributions
- **Spread the word** — tell people who need this that it exists

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- Git
- Docker and Docker Compose (for full stack development)
- Ollama (for AI engine development) — https://ollama.ai

### Fork and Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/argos.git
cd argos
git remote add upstream https://github.com/argos-security/argos.git
```

### Agent Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run agent in development mode
python argos_agent.py --mode=standalone --autonomy=supervised --debug
```

### Server Development

```bash
cd server/

# Install server dependencies
pip install -r requirements-server.txt

# Set up environment
cp .env.example .env
# Edit .env with your local settings

# Initialize database (SQLite for dev, no postgres needed)
python -c "import asyncio; from db.database import init_db; asyncio.run(init_db())"

# Run server in dev mode (auto-reload)
DEV=true python server.py
```

### Dashboard Development

```bash
cd dashboard/

# Install dependencies
npm install

# Start dev server with hot reload
npm run dev
# Open http://localhost:5173
```

### Full Stack with Docker

```bash
# Copy and configure environment
cp .env.example .env

# Start everything
docker compose up -d

# Watch logs
docker compose logs -f server

# Server:    https://localhost:8443
# Dashboard: http://localhost:3000
```

### Pull Latest Changes

```bash
git fetch upstream
git rebase upstream/main
```

---

## Project Structure

```
argos/
├── argos_agent.py          # Agent entry point — start here for agent work
├── requirements.txt        # Agent dependencies
├── requirements-dev.txt    # Dev/test dependencies
│
├── agent/                  # Agent modules
│   ├── monitors/           # Data collection (network, process, filesystem, auth)
│   ├── detectors/          # Threat detection logic
│   └── response/           # Defensive action execution
│
├── server/                 # Central server
│   ├── server.py           # FastAPI entry point
│   ├── api/                # HTTP/WebSocket endpoints
│   ├── ai_engine/          # Ollama + Claude API integration
│   ├── intelligence/       # Threat feeds, attribution, community
│   ├── training/           # Model fine-tuning pipeline
│   └── db/                 # Database models and migrations
│
├── dashboard/              # React web dashboard
│   └── src/
│       ├── App.jsx         # Main application
│       ├── components/     # Reusable UI components
│       ├── pages/          # Page components
│       └── hooks/          # Custom React hooks
│
├── mobile/                 # React Native mobile app
│   └── src/
│       ├── App.js          # Main application
│       ├── screens/        # Screen components
│       ├── components/     # Reusable components
│       └── services/       # API and WebSocket services
│
├── tests/                  # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
└── docs/                   # Documentation
```

---

## Contribution Types

### Adding a Threat Detector

Detectors live in `agent/detectors/`. Each detector is a class that:

1. Takes relevant monitor data as input
2. Returns a list of `ThreatEvent` objects (empty if nothing detected)
3. Is stateless between calls (state goes in `__init__` if needed)

```python
# agent/detectors/my_detector.py

from typing import Optional
from dataclasses import dataclass
from agent.monitors.network import ConnectionData
from argos_agent import ThreatEvent

class MyDetector:
    """
    Detects [describe what it detects].
    
    Detection method: [explain the logic]
    Recommended action: [what ARGOS should do when triggered]
    False positive rate: [low/medium/high — and why]
    """

    def __init__(self):
        # Initialize any state needed between scans
        self._state = {}

    def scan(self, data: list[ConnectionData]) -> list[ThreatEvent]:
        events = []
        for item in data:
            event = self._analyze(item)
            if event:
                events.append(event)
        return events

    def _analyze(self, item: ConnectionData) -> Optional[ThreatEvent]:
        # Your detection logic here
        # Return ThreatEvent if threat detected, None otherwise
        pass
```

Then register your detector in `argos_agent.py`:

```python
from agent.detectors.my_detector import MyDetector

class ArgosAgent:
    def __init__(self, config):
        # ... existing code ...
        self.my_detector = MyDetector()
```

Include a unit test in `tests/unit/detectors/test_my_detector.py`.

### Improving the AI Engine

The AI engine lives in `server/ai_engine/`. The most impactful improvements are:

- **Better prompts** — edit `SYSTEM_PROMPT` in `engine.py`. Test changes against the fixture dataset in `tests/fixtures/threats.json`
- **Rule engine updates** — add new entries to `RULE_ENGINE` dict in `engine.py` for threat types not yet covered
- **Training data** — add labeled examples to `tests/fixtures/training_examples.jsonl`

### Contributing Training Data

Training data lives in `tests/fixtures/training_examples.jsonl`. Each line is:

```json
{
  "threat_type": "port_scan",
  "severity": "high",
  "source_ip": "185.220.101.47",
  "description": "27 unique ports probed in 45 seconds",
  "raw_data": {"ports_tried": [22, 80, 443, 3306, 5432, 6379], "window_seconds": 45},
  "correct_action": "deploy_honeypot",
  "reasoning": "Systematic enumeration from Tor exit node — honeypot will gather TTPs without exposing real services",
  "source": "community"
}
```

Please only contribute data from your own systems or from public datasets (CICIDS, UNSW-NB15). Never contribute data that includes personal information or real user credentials.

### Adding a Response Action

Response actions live in `agent/response/`. Each action is a method on the `ResponseEngine` class:

```python
def _my_action(self, event: ThreatEvent) -> str:
    """
    Describe what this action does.
    
    Platform support: Linux ✓ | macOS ✓ | Windows ✗
    Requires root: Yes
    Reversible: Yes — describe how
    """
    # Implementation
    log.warning(f"[ACTION] My action: {event.source_ip}")
    # ... do the thing ...
    return "my_action_result"
```

Document platform support and whether root/admin is required.

---

## Code Standards

### Python

- PEP 8 style — enforced via `ruff`
- Type hints on all public functions and methods
- Docstrings on all public classes and methods (Google style)
- Maximum line length: 100 characters
- No bare `except` clauses — always catch specific exceptions

```bash
# Check style
ruff check .

# Format
ruff format .
```

### JavaScript / TypeScript

- ESLint with the project config
- Prefer functional components and hooks in React
- No `any` types in TypeScript
- Async/await over raw promises

```bash
cd dashboard/
npm run lint
```

### Commit Messages

We use conventional commits:

```
feat: add DDoS detection with rate limiting
fix: handle PermissionError on macOS when scanning network connections
docs: add training data contribution guide
test: add unit tests for port scan detector
refactor: extract IP classification into shared utility
chore: update dependencies
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `style`

Breaking changes: add `!` after the type (`feat!: change event schema`)

### Branch Naming

```
feat/ddos-detection
fix/macos-network-permission
docs/api-reference
test/port-scan-detector
```

---

## Testing

### Running Tests

```bash
# All tests
pytest

# Unit tests only (fast)
pytest tests/unit/

# Integration tests (requires running server)
pytest tests/integration/

# With coverage
pytest --cov=. --cov-report=html
```

### Writing Tests

- Unit tests go in `tests/unit/` — mirror the source structure
- Integration tests go in `tests/integration/`
- Use `pytest` fixtures for shared setup
- Mock external calls (Ollama, Claude API, AbuseIPDB) — don't make real network calls in tests
- Test both the happy path and failure modes

```python
# tests/unit/detectors/test_port_scan.py

import pytest
from agent.detectors.port_scan import PortScanDetector

@pytest.fixture
def detector():
    return PortScanDetector()

def test_detects_port_scan_above_threshold(detector):
    # Arrange — simulate 15 unique ports from same IP in 60s
    connections = [make_connection("185.220.101.47", port) for port in range(15)]
    
    # Act
    events = detector.scan(connections)
    
    # Assert
    assert len(events) == 1
    assert events[0].threat_type == "port_scan"
    assert events[0].severity == "high"
    assert events[0].source_ip == "185.220.101.47"

def test_ignores_private_ips(detector):
    connections = [make_connection("192.168.1.100", port) for port in range(20)]
    events = detector.scan(connections)
    assert len(events) == 0

def test_resets_window_after_timeout(detector):
    # Test that the time window resets correctly
    ...
```

### Test Requirements

- All new detectors must have unit tests
- All API endpoints must have integration tests
- Minimum coverage for new code: 80%
- CI will fail if tests fail or coverage drops

---

## Submitting a Pull Request

1. **Create a branch** from `main` with a descriptive name
2. **Make your changes** — keep PRs focused on one thing
3. **Write or update tests** for your changes
4. **Run the full test suite** and fix any failures
5. **Update documentation** if you changed behavior or added features
6. **Push your branch** and open a pull request on GitHub

### PR Description Template

```markdown
## What this PR does
[Clear description of the change]

## Why
[Motivation — link to issue if applicable]

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation
- [ ] Refactoring

## Testing
[How you tested this — what scenarios you covered]

## Platform tested
- [ ] Linux
- [ ] macOS  
- [ ] Windows

## Checklist
- [ ] Tests pass
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] No hardcoded credentials or secrets
```

### Review Process

- At least one maintainer must approve before merging
- Security-sensitive code (response actions, auth, AI escalation) requires two reviewers
- CI must pass (tests, linting, coverage)
- PRs stay open for at least 24h to allow community review

---

## Reporting Bugs

Use the GitHub issue tracker with the `bug` label. Please include:

- **ARGOS version** — `python argos_agent.py --version`
- **Operating system and version**
- **Python version**
- **Steps to reproduce** — as minimal as possible
- **Expected behavior**
- **Actual behavior** — include the full error message and traceback
- **Relevant logs** — from `~/.argos/logs/`

If the bug is a **security vulnerability**, do not open a public issue. See [Security Vulnerabilities](#security-vulnerabilities).

---

## Requesting Features

Open a GitHub issue with the `enhancement` label. Include:

- **Use case** — what problem does this solve? Who benefits?
- **Proposed solution** — how you imagine it working
- **Alternatives considered** — other approaches you thought about
- **Willingness to implement** — are you able to work on this yourself?

Feature requests are discussed openly. We prioritize features that:
- Benefit the most users
- Fit the ARGOS philosophy (privacy-first, self-hostable, free)
- Are technically feasible without major architectural changes
- Have someone willing to implement them

---

## Security Vulnerabilities

**Please do not open public GitHub issues for security vulnerabilities in ARGOS itself.**

If you find a vulnerability, email **security@argos-security.io** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional but appreciated)

We will:
- Acknowledge receipt within 48 hours
- Investigate and confirm within 7 days
- Publish a fix and credit you (unless you prefer anonymity) within 30 days

We do not have a formal bug bounty program, but we deeply appreciate responsible disclosure and will acknowledge all reporters in the release notes.

---

## Community

- **GitHub Discussions** — questions, ideas, show and tell
- **Discord** — real-time chat with contributors and users (link in README)
- **Issues** — bug reports and feature requests

We are a small team and respond as fast as we can. Thank you for your patience and for being part of this.

---

*ARGOS — Security is a right, not a privilege.*
