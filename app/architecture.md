# Architecture

This document describes the technical architecture of ARGOS in detail — how the components fit together, why they were designed this way, and what trade-offs were made.

---

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [System Overview](#system-overview)
- [The Agent](#the-agent)
- [The Server](#the-server)
- [The AI Engine](#the-ai-engine)
- [The Honeypot Engine](#the-honeypot-engine)
- [The Training Pipeline](#the-training-pipeline)
- [The Dashboard and Mobile App](#the-dashboard-and-mobile-app)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Scalability](#scalability)
- [Design Decisions and Trade-offs](#design-decisions-and-trade-offs)

---

## Design Philosophy

ARGOS is built around four principles that inform every architectural decision:

**1. Privacy by default.** No data should leave a device unless the user explicitly chooses to share it. Even in cloud mode, only structured threat metadata is transmitted — never raw network traffic, file contents, or credentials.

**2. Graceful degradation.** Every component must have a fallback. If Ollama is offline, the rule engine takes over. If the server is unreachable, the agent continues protecting the device locally. If the Claude API is unavailable, the human is notified instead. The system never stops protecting.

**3. Transparency over magic.** Every action ARGOS takes is logged with a reason. The AI's reasoning is always surfaced to the user. Decisions that affect the network are always auditable.

**4. Self-improvement without dependency.** The system learns from experience, but that learning happens locally. There is no requirement to send data to an external AI provider to improve. The model gets better on your data, on your hardware.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PROTECTED ENVIRONMENT                         │
│                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │   Agent       │    │   Agent       │    │   Agent       │          │
│  │  (Linux)      │    │  (Windows)    │    │  (macOS)      │          │
│  │               │    │               │    │               │          │
│  │ • Net monitor │    │ • Net monitor │    │ • Net monitor │          │
│  │ • Proc monitor│    │ • Proc monitor│    │ • Proc monitor│          │
│  │ • Response    │    │ • Response    │    │ • Response    │          │
│  │ • Honeypots   │    │ • Honeypots   │    │ • Honeypots   │          │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘           │
│         └────────────────────┼────────────────────┘                   │
│                              │ HTTPS / WSS (TLS)                       │
└──────────────────────────────┼─────────────────────────────────────────┘
                               │
┌──────────────────────────────▼─────────────────────────────────────────┐
│                        ARGOS SERVER                                     │
│                                                                          │
│  ┌─────────────────────┐    ┌─────────────────────┐                    │
│  │   FastAPI            │    │   AI Engine          │                    │
│  │                      │    │                      │                    │
│  │ REST API             │◄──►│ Phi-4 14B (Ollama)  │                    │
│  │ WebSocket            │    │ Rule-based fallback  │                    │
│  │ Auth middleware      │    │ Claude API escalation│                    │
│  └──────────┬──────────┘    └──────────────────────┘                   │
│             │                                                            │
│  ┌──────────▼──────────┐    ┌─────────────────────┐                    │
│  │   Database           │    │  Training Pipeline   │                    │
│  │                      │    │                      │                    │
│  │ PostgreSQL (prod)    │◄──►│ LoRA fine-tuning     │                    │
│  │ SQLite (dev)         │    │ Dataset management   │                    │
│  └─────────────────────┘    └─────────────────────┘                    │
│                                                                          │
│  ┌─────────────────────┐                                                │
│  │   Intelligence       │                                                │
│  │                      │                                                │
│  │ AbuseIPDB            │                                                │
│  │ ip-api.com           │                                                │
│  │ Community intel      │                                                │
│  └─────────────────────┘                                                │
└────────────────────────────────────────────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                  │
   ┌──────────▼──────────┐          ┌────────────▼───────────┐
   │   Web Dashboard      │          │   Mobile App            │
   │   (React)            │          │   (React Native)        │
   │                      │          │                          │
   │ Real-time threat feed│          │ Push notifications       │
   │ Device management    │          │ Human decision flow      │
   │ Intelligence panel   │          │ Remote device control    │
   └─────────────────────┘          └─────────────────────────┘
```

---

## The Agent

The agent is the component that runs on every protected device. It is designed to be:

- **Lightweight** — minimal resource footprint, runs in the background without impact
- **Cross-platform** — a single Python codebase for Linux, macOS, and Windows
- **Autonomous** — continues working if the server is unreachable
- **Transparent** — every action is logged locally

### Agent Internals

```
argos_agent.py (ArgosAgent)
│
├── NetworkMonitor
│   ├── Scans active connections via psutil every 5 seconds
│   ├── Maintains state: _seen_connections, _port_scan_tracker, _brute_force_tracker
│   ├── Produces: ThreatEvent objects for detected threats
│   └── Detectors:
│       ├── Port scan (>10 unique ports in 60s from same IP)
│       ├── Repeat offender (IP in local threat DB)
│       └── [planned] Brute force, DDoS, C2 beacon, exfiltration
│
├── ProcessMonitor
│   ├── Iterates running processes via psutil every 10 seconds
│   ├── Checks: name, cmdline, CPU usage, open connections
│   ├── Produces: ThreatEvent objects
│   └── Detectors:
│       ├── Known malware names (cryptominers, reverse shells)
│       ├── High CPU (>85% sustained)
│       └── [planned] Ransomware (mass file modification), privilege escalation
│
├── AIEngine
│   ├── Sends ThreatEvent to Ollama for analysis
│   ├── Falls back to rule-based engine if Ollama unavailable
│   ├── Returns: action, reasoning, confidence, escalate_to_human
│   └── Stores response for training data if applicable
│
├── ResponseEngine
│   ├── Receives: ThreatEvent + AI decision
│   ├── Applies autonomy level (full / semi / supervised)
│   ├── Executes: block_ip, deploy_honeypot, isolate_process, close_port
│   └── Returns: action result string for logging
│
└── ThreatDB
    ├── SQLite database at ~/.argos/threats.db
    ├── Tables: threats, blocked_ips
    └── Used for: history lookup, repeat offender detection, evidence storage
```

### Event Pipeline

Every detected threat follows the same pipeline:

```
Detection (Monitor) 
    ↓ ThreatEvent created
IP in blocklist? → Yes → Skip (already handled)
    ↓ No
Log warning
    ↓
AI analysis (Ollama or rules)
    ↓ decision: {action, confidence, reasoning}
Autonomy check:
  supervised → log recommended action, notify server
  semi → confidence < 0.7 → escalate; else execute
  full → always execute
    ↓
Execute action (ResponseEngine)
    ↓ result string
Save to ThreatDB
    ↓
Report to server (if connected mode)
```

### Cross-Platform Compatibility

The agent uses platform-independent APIs wherever possible:

| Function | Library | Notes |
|----------|---------|-------|
| Network connections | psutil | Works on all platforms |
| Process listing | psutil | Works on all platforms |
| File system events | watchdog (planned) | Cross-platform |
| IP blocking | subprocess | Platform-specific commands |
| Socket operations | socket | Standard library |

Platform-specific paths are handled in `agent/response/firewall.py` using the `PLATFORM` constant.

---

## The Server

The server is a FastAPI application that acts as the central coordination hub in self-hosted and cloud modes.

### Request Lifecycle

```
HTTP Request
    ↓
Nginx (TLS termination, reverse proxy)
    ↓
FastAPI application
    ↓
Auth middleware (token validation)
    ↓
Route handler
    ↓
Business logic
    ↓
SQLAlchemy (async)
    ↓
PostgreSQL
    ↓
Response + WebSocket broadcast
```

### WebSocket Architecture

The server maintains a dict of active WebSocket connections keyed by device/client ID. When a new threat event arrives:

1. Event is saved to database
2. Server iterates all connections and sends the event as JSON
3. Dead connections are detected and removed

This is a simple broadcast model suitable for the expected scale (tens to low hundreds of concurrent connections). At larger scale, Redis Pub/Sub would be used as the message bus.

### Database Schema

Core tables and their relationships:

```
devices ─────────────────────────────────────────────────────┐
  id (PK)                                                      │
  name, platform, ip, version, autonomy, status               │
  last_seen, created_at                                        │
                                                               │
threat_events ──────────────────────────────────────────── device_id (FK)
  id (PK, SHA256 hash)
  device_id (FK → devices)
  timestamp, threat_type, severity
  source_ip, source_port, target_port, protocol
  description, raw_data (JSON)
  action_taken, ai_analysis, ai_confidence
  evidence_path, resolved

blocked_ips
  ip (PK)
  reason, device_id, blocked_at, expires_at, community

honeypot_sessions
  id (PK)
  device_id, attacker_ip, port
  started_at, ended_at, interactions, bytes_received
  evidence_path

training_examples
  id (PK, autoincrement)
  event_id, prompt, response, source (human/ai/claude)
  created_at, used_in_training

api_tokens
  token (PK)
  device_id, name, created_at, active
```

---

## The AI Engine

The AI engine is a three-layer system that balances speed, accuracy, and cost.

### Layer 1: Phi-4 14B via Ollama

Ollama runs the model locally on CPU or GPU. The engine sends a structured threat description and expects a JSON response with action, reasoning, and confidence.

Why Phi-4 14B:
- Excellent reasoning ability per parameter compared to larger models
- Fits in 10 GB RAM quantized — accessible without GPU
- Strong performance on classification and analysis tasks
- Microsoft's research focus on small, capable models

Why Ollama:
- Simplest possible local LLM deployment
- Handles quantization, memory management, and model serving
- Cross-platform
- Active development and growing model library

### Layer 2: Rule-Based Fallback

When Ollama is unreachable (startup, restart, resource exhaustion), the rule engine provides instant decisions without AI:

```python
RULE_ENGINE = {
    "port_scan":       {"action": "deploy_honeypot", "confidence": 0.92},
    "brute_force":     {"action": "block_ip",        "confidence": 0.97},
    "repeat_offender": {"action": "block_ip",        "confidence": 0.99},
    ...
}
```

Rules are intentionally conservative — high confidence for well-understood threats, low confidence (→ human escalation) for ambiguous ones.

### Layer 3: Claude API Escalation

For threats with confidence below 0.5 and where a Claude API key is configured, the server escalates to Claude. The same JSON response format is expected.

This layer has two purposes:
1. Handle genuinely novel attacks that the local model cannot classify
2. Generate high-quality training data that improves the local model over time

The design intent is that Claude API calls become progressively rarer as the local model learns from them. A well-tuned deployment should rarely need to escalate after a few months of operation.

### Prompt Engineering

The system prompt instructs the model to return only JSON. The user prompt contains structured threat data. Temperature is set to 0.1 for deterministic, consistent outputs.

```
System: You are ARGOS... [instructions] ...Respond ONLY with valid JSON.

User: Threat Type: port_scan
      Severity: high
      Source IP: 185.220.101.47
      Description: 15 unique ports probed in 42 seconds
      Raw data: {"ports_tried": [...], "window_seconds": 42}
```

The JSON schema is enforced by the system prompt, not by the model's native JSON mode, for maximum compatibility across model versions.

---

## The Honeypot Engine

Honeypots are context-aware deception services that lure attackers away from real systems.

### Lifecycle

```
Port scan detected on port P
    ↓
ResponseEngine._deploy_honeypot() called
    ↓
Check: is honeypot already active on P? → skip if yes
    ↓
Start daemon thread: _run_honeypot(port=P, target_ip=attacker_ip)
    ↓
Bind TCP socket on port P
    ↓
Listen for connections (5 minute timeout)
    ↓
Accept connections:
    - Log connection source
    - Receive up to 4096 bytes
    - Send realistic service banner
    - Log all interaction data
    ↓
Write evidence file to ~/.argos/evidence/
    ↓
Close after timeout or explicit close
    ↓
Remove from _honeypots_active dict
```

### Evidence Collection

Each honeypot session produces a timestamped log file:

```
ARGOS Honeypot Evidence
Port: 22
Target attacker: 185.220.101.47
Started: 2026-03-19T03:42:11.000Z

[03:42:13] Connection from 185.220.101.47:54821
  Data received (38 bytes): b'SSH-2.0-libssh-0.9.6\r\n'
[03:42:14] Connection from 185.220.101.47:54822
  Data received (52 bytes): b'\x00\x00\x00...'  (SSH key exchange)
```

These files are suitable for submission to law enforcement and include timestamps, source information, and raw interaction data.

### Service Banners

The honeypot presents realistic service banners based on the port:

| Port | Service | Banner |
|------|---------|--------|
| 22 | SSH | `SSH-2.0-OpenSSH_8.9` |
| 21 | FTP | `220 FTP server ready` |
| 80/8080 | HTTP | `HTTP/1.1 200 OK` + fake HTML |
| 3306 | MySQL | MySQL greeting packet |
| 5432 | PostgreSQL | PostgreSQL startup response |
| 6379 | Redis | `+PONG\r\n` |

---

## The Training Pipeline

The system continuously improves the local AI model using incident data.

### Data Sources

| Source | Quality | Volume |
|--------|---------|--------|
| Human decisions via mobile/dashboard | Highest | Low (occasional) |
| Claude API escalation responses | High | Low (occasional) |
| High-confidence AI decisions (>0.9) | Good | Medium |
| Public datasets (CICIDS, UNSW-NB15) | Good | High (one-time) |

### Fine-Tuning Approach

LoRA (Low-Rank Adaptation) is used because:
- Requires significantly less VRAM than full fine-tuning
- Faster training (hours vs days)
- Preserves the base model's general capabilities
- Adapters can be swapped without replacing the full model
- Works on consumer hardware

The pipeline runs automatically when enough new training examples accumulate (default: 50). It:

1. Collects unused examples from the database
2. Formats them as Alpaca-style instruction pairs
3. Runs LoRA fine-tuning via Unsloth
4. Validates the new adapter on a held-out set
5. Deploys atomically (zero downtime)
6. Marks examples as used

---

## The Dashboard and Mobile App

Both interfaces consume the same REST API and WebSocket stream.

### Real-Time Architecture

```
Server (new threat event)
    ↓ broadcast via WebSocket
Dashboard (React)
    ↓ receives JSON message
    ↓ updates state
    ↓ re-renders affected components
User sees new threat within < 100ms
```

The dashboard polls `/api/dashboard/overview` every 15 seconds as a fallback, but the primary update path is WebSocket.

### Mobile Push Notifications

Firebase Cloud Messaging (FCM) is used for mobile push notifications. When the server determines an event requires human decision (`escalate_to_human: true`), it:

1. Looks up the FCM token for the device owner
2. Sends a high-priority push notification with event details
3. On tap, the app opens to the specific event with approve/reject buttons
4. The decision is POSTed to `/api/events/{id}/decide`

---

## Data Flow

### Standalone Mode

```
Network traffic → psutil
    → NetworkMonitor (agent)
        → PortScanDetector
        → ThreatEvent
            → AIEngine (local Ollama)
                → ResponseEngine
                    → iptables / pf / netsh
                    → HoneypotEngine
                    → ThreatDB (local SQLite)
```

Nothing leaves the device.

### Self-Hosted Mode

```
Network traffic → psutil
    → NetworkMonitor (agent)
        → ThreatEvent
            → AIEngine (local rules only if no local Ollama)
                → ResponseEngine (acts locally)
                    → ThreatEvent POSTed to central server
                        → Server AIEngine (Ollama + Claude API)
                            → WebSocket broadcast
                                → Dashboard / Mobile App
                            → TrainingPipeline
                                → Model improves
```

All data stays within your infrastructure.

### Cloud Mode

```
Network traffic → psutil
    → NetworkMonitor (agent)
        → ThreatEvent (structured metadata only)
            → HTTPS POST to cloud server
                → Server AIEngine
                    → Decision returned to agent
                        → Agent executes action locally
                    → Push notification to mobile
```

Raw traffic never leaves the device — only structured threat metadata.

---

## Security Architecture

### Transport Security

All agent-to-server communication is TLS 1.2+. We recommend TLS 1.3 in production.

The server presents a certificate. Agents verify it by default (configurable).

WebSocket connections use WSS (TLS-wrapped WebSocket).

### Authentication

Every API request includes a Bearer token. Tokens are:
- 48 bytes of cryptographically random data (URL-safe base64 encoded)
- Stored as-is in the database (no hashing — they are already high-entropy)
- Scoped to a single device
- Long-lived (no automatic expiry — manual rotation supported)

### Data at Rest

- SQLite databases: file permissions `600`
- Evidence files: directory permissions `700`, file permissions `600`
- PostgreSQL: standard PostgreSQL access control
- API tokens: stored in database, accessible only via authenticated API

### Agent Privilege Model

The agent runs as root (Linux/macOS) or Administrator (Windows) because:
- `iptables` and `pf` require root
- `psutil.net_connections()` requires root for full visibility
- Binding to low-numbered ports (for honeypots) requires root

This is an accepted trade-off. Future work will explore capability-based privilege reduction.

---

## Scalability

The current architecture is designed for:
- Up to 100 connected agents per server instance
- Up to 10,000 threat events per day
- Up to 10 concurrent dashboard/mobile clients

For larger deployments:

| Bottleneck | Solution |
|------------|---------|
| WebSocket broadcast | Replace with Redis Pub/Sub |
| AI inference | Add GPU, use larger batch sizes, or run multiple Ollama instances |
| Database | Migrate to PostgreSQL with read replicas |
| Agent connections | Horizontal scaling with load balancer |

---

## Design Decisions and Trade-offs

### Why Python for the Agent?

Pros: cross-platform without recompilation, excellent library ecosystem (psutil, scapy), readable and accessible to contributors.

Cons: slower startup, higher memory than compiled languages, GIL limits parallelism.

We chose Python because accessibility and cross-platform compatibility are more important than raw performance for this use case. Detection latency of 5 seconds is acceptable; developer friction is not.

### Why SQLite for Local Storage?

SQLite is serverless, zero-configuration, and surprisingly fast for single-writer workloads. The agent writes are serialized through a threading lock. For the expected event volume (hundreds to thousands per day), SQLite is ideal.

### Why Not Use a Vector Database for AI Memory?

Vector databases enable semantic search over past incidents — a useful capability. We chose not to include one in the initial architecture because:
1. It adds significant operational complexity
2. The training pipeline achieves the same goal differently (structured learning vs retrieval)
3. It can be added later without architectural changes

### Why Ollama Instead of Direct Model Loading?

Ollama handles quantization, memory management, model loading/unloading, and provides a consistent API across model types. Writing equivalent functionality ourselves would be significant work for no user benefit.

### Why LoRA Instead of Full Fine-Tuning?

Full fine-tuning would overwrite the model's general capabilities and require significantly more compute. LoRA trains adapter layers while keeping base weights frozen, achieving domain specialization at a fraction of the cost.

---

*ARGOS Architecture — v0.1.0*
