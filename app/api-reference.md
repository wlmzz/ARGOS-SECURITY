# API Reference

ARGOS exposes a REST API and a WebSocket endpoint. All HTTP endpoints return JSON. All requests to protected endpoints require a Bearer token obtained during device registration.

**Base URL:** `https://your-argos-server.com`
**Interactive docs:** `https://your-argos-server.com/docs` (Swagger UI)
**OpenAPI schema:** `https://your-argos-server.com/openapi.json`

---

## Authentication

All API endpoints (except `/health` and `/api/auth/me`) require a Bearer token in the Authorization header.

```http
Authorization: Bearer <your-token>
```

Tokens are obtained by registering a device via `POST /api/devices/register`.

Tokens are long-lived and do not expire automatically. Rotate them manually by registering a new device and deleting the old token.

---

## Health

### GET /health

Check server status. No authentication required.

**Response**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

## Authentication Endpoints

### GET /api/auth/me

Verify token and return associated device.

**Response**
```json
{
  "device_id": "a1b2c3d4e5f6...",
  "authenticated": true
}
```

**Errors**
- `401` — Missing or invalid token

---

## Devices

### POST /api/devices/register

Register a new agent device. Returns a token for subsequent requests.

**Request**
```json
{
  "name": "web-server-01",
  "platform": "linux",
  "version": "0.1.0",
  "autonomy": "semi"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | ✅ | Human-readable device name |
| platform | string | ✅ | `linux` \| `darwin` \| `windows` |
| version | string | ❌ | Agent version (default: `0.1.0`) |
| autonomy | string | ❌ | `full` \| `semi` \| `supervised` (default: `semi`) |

**Response**
```json
{
  "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Save both values. The token cannot be retrieved again after registration.

---

### GET /api/devices

List all registered devices.

**Response**
```json
[
  {
    "id": "a1b2c3d4e5f6...",
    "name": "web-server-01",
    "platform": "linux",
    "ip": "10.0.1.5",
    "version": "0.1.0",
    "autonomy": "semi",
    "status": "online",
    "last_seen": "2026-03-19T14:22:31.000Z",
    "created_at": "2026-03-01T09:00:00.000Z"
  }
]
```

---

### GET /api/devices/{device_id}

Get a single device with threat statistics.

**Response**
```json
{
  "id": "a1b2c3d4e5f6...",
  "name": "web-server-01",
  "platform": "linux",
  "ip": "10.0.1.5",
  "version": "0.1.0",
  "autonomy": "semi",
  "status": "online",
  "last_seen": "2026-03-19T14:22:31.000Z",
  "created_at": "2026-03-01T09:00:00.000Z",
  "threats_total": 847,
  "threats_today": 12
}
```

**Errors**
- `404` — Device not found

---

### PATCH /api/devices/{device_id}

Update device configuration.

**Request** (all fields optional)
```json
{
  "name": "web-server-primary",
  "autonomy": "full",
  "status": "online"
}
```

**Response** — Updated device object

---

### DELETE /api/devices/{device_id}

Remove a device and all associated data.

**Response**
```json
{
  "status": "deleted"
}
```

---

### POST /api/devices/{device_id}/heartbeat

Agent sends this every 30 seconds to signal it is alive.

**Response**
```json
{
  "status": "ok"
}
```

---

## Events

### POST /api/events

Ingest a threat event from an agent.

**Request**
```json
{
  "device_id": "a1b2c3d4e5f6...",
  "threat_type": "port_scan",
  "severity": "high",
  "source_ip": "185.220.101.47",
  "source_port": 54821,
  "target_port": 22,
  "protocol": "tcp",
  "description": "Port scan detected: 15 unique ports probed in 42 seconds",
  "raw_data": {
    "ports_tried": [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443, 9200, 11211, 2181, 50070, 4848, 7001],
    "window_seconds": 42
  },
  "action_taken": "honeypot_deployed:22",
  "ai_analysis": "Systematic enumeration from Tor exit node — honeypot deployed.",
  "ai_confidence": 0.94
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| device_id | string | ✅ | Reporting device ID |
| threat_type | string | ✅ | See [Threat Types](#threat-types) |
| severity | string | ✅ | `critical` \| `high` \| `medium` \| `low` |
| source_ip | string | ✅ | Attacker IP address |
| source_port | integer | ❌ | Attacker source port |
| target_port | integer | ❌ | Targeted local port |
| protocol | string | ❌ | `tcp` \| `udp` \| `process` (default: `tcp`) |
| description | string | ✅ | Human-readable description |
| raw_data | object | ❌ | Raw detection data for context |
| action_taken | string | ❌ | Action already taken by agent |
| ai_analysis | string | ❌ | AI reasoning from local model |
| ai_confidence | float | ❌ | Confidence 0.0–1.0 |

**Response**
```json
{
  "event_id": "a1b2c3d4e5f6a1b2",
  "ai_decision": {
    "severity_confirmed": true,
    "action": "deploy_honeypot",
    "reasoning": "Systematic port enumeration — honeypot deployed to gather TTPs.",
    "confidence": 0.94,
    "escalate_to_human": false
  },
  "status": "accepted"
}
```

The `ai_decision` field contains the server-side AI analysis if the agent's confidence was below 0.5.

---

### GET /api/events

List threat events with optional filters.

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| limit | integer | Max results (default: 50, max: 500) |
| offset | integer | Pagination offset (default: 0) |
| severity | string | Filter by severity level |
| device_id | string | Filter by device |
| threat_type | string | Filter by threat type |

**Example**
```
GET /api/events?severity=critical&limit=20&device_id=a1b2c3d4
```

**Response**
```json
[
  {
    "id": "a1b2c3d4e5f6a1b2",
    "device_id": "a1b2c3d4e5f6...",
    "timestamp": "2026-03-19T14:22:31.000Z",
    "threat_type": "port_scan",
    "severity": "high",
    "source_ip": "185.220.101.47",
    "source_port": 54821,
    "target_port": 22,
    "protocol": "tcp",
    "description": "Port scan detected: 15 unique ports probed in 42 seconds",
    "action_taken": "honeypot_deployed:22",
    "ai_analysis": "Systematic enumeration from Tor exit node.",
    "ai_confidence": 0.94,
    "resolved": false
  }
]
```

---

### GET /api/events/{event_id}

Get a single event by ID.

**Errors**
- `404` — Event not found

---

### POST /api/events/{event_id}/decide

Record a human decision on a pending event. This feeds back as training data.

**Request**
```json
{
  "action": "block_ip",
  "reasoning": "Confirmed attacker — IP appears in multiple threat feeds.",
  "source": "human"
}
```

| Field | Type | Description |
|-------|------|-------------|
| action | string | The decided action |
| reasoning | string | Why this decision was made |
| source | string | `human` \| `claude_api` |

**Response**
```json
{
  "status": "decision_recorded",
  "training_example_saved": true
}
```

---

### GET /api/events/stats/summary

Aggregate statistics across all events.

**Response**
```json
{
  "total": 14291,
  "critical": 42,
  "high": 1847,
  "blocked_ips": 381,
  "today": 127
}
```

---

## Dashboard

### GET /api/dashboard/overview

Complete dashboard data in a single request. Used by the web dashboard on load and every 15 seconds.

**Response**
```json
{
  "stats": {
    "total_threats": 14291,
    "threats_today": 127,
    "threats_week": 891,
    "blocked_ips": 381,
    "devices_online": 4,
    "devices_total": 5,
    "critical_today": 2,
    "active_honeypots": 3
  },
  "recent_events": [ /* last 20 events */ ],
  "threat_types": [
    { "type": "port_scan",    "count": 8421 },
    { "type": "brute_force",  "count": 3214 },
    { "type": "ddos",         "count": 1847 }
  ],
  "hourly_chart": [
    { "hour": "00:00", "count": 3 },
    { "hour": "01:00", "count": 1 },
    ...
    { "hour": "23:00", "count": 18 }
  ]
}
```

---

## Intelligence

### GET /api/intelligence/blocked

List all blocked IP addresses.

**Response**
```json
[
  {
    "ip": "185.220.101.47",
    "reason": "port_scan",
    "device_id": "a1b2c3d4...",
    "blocked_at": "2026-03-19T14:22:31.000Z",
    "expires_at": "2026-03-19T15:22:31.000Z",
    "community": false
  }
]
```

---

### POST /api/intelligence/blocked

Manually block an IP address.

**Request**
```json
{
  "ip": "185.220.101.47",
  "reason": "Confirmed attacker — seen in multiple threat feeds",
  "duration_minutes": 1440,
  "community": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ip | string | ✅ | IP address to block |
| reason | string | ✅ | Human-readable reason |
| duration_minutes | integer | ❌ | Block duration. Omit for permanent. |
| community | boolean | ❌ | Share with community intel (default: false) |

---

### DELETE /api/intelligence/blocked/{ip}

Unblock an IP address.

**Response**
```json
{
  "status": "unblocked",
  "ip": "185.220.101.47"
}
```

---

### GET /api/intelligence/lookup/{ip}

Enrich an IP with threat intelligence from public sources.

**Response**
```json
{
  "ip": "185.220.101.47",
  "sources": {
    "abuseipdb": {
      "abuse_score": 100,
      "total_reports": 847,
      "country": "DE",
      "isp": "Tor Project",
      "domain": "torproject.org",
      "is_tor": true
    },
    "geolocation": {
      "country": "Germany",
      "region": "Hesse",
      "city": "Frankfurt",
      "isp": "Tor Project",
      "org": "Tor exit node",
      "asn": "AS213151 BERBER-ANYCAST-AS",
      "hosting": true
    }
  }
}
```

---

## WebSocket

### WS /ws/{device_id}

Real-time event stream. Connect from the dashboard or monitoring tools.

**Connection**
```javascript
const ws = new WebSocket("wss://your-argos-server.com/ws/dashboard-client");
```

**Incoming Messages**

New threat event:
```json
{
  "type": "new_threat",
  "event_id": "a1b2c3d4e5f6a1b2",
  "device_id": "a1b2c3d4e5f6...",
  "threat_type": "port_scan",
  "severity": "high",
  "source_ip": "185.220.101.47",
  "description": "Port scan detected: 15 unique ports probed",
  "action_taken": "honeypot_deployed:22",
  "timestamp": "2026-03-19T14:22:31.000Z"
}
```

Device status change:
```json
{
  "type": "device_status",
  "device_id": "a1b2c3d4e5f6...",
  "status": "offline",
  "timestamp": "2026-03-19T14:22:31.000Z"
}
```

---

## Threat Types

| Threat Type | Description |
|-------------|-------------|
| `port_scan` | Multiple ports probed by same source in short window |
| `brute_force` | Repeated authentication failures from same source |
| `ddos` | High-volume traffic flood targeting a service |
| `repeat_offender` | IP with prior incident history reconnecting |
| `suspicious_process` | Process matching known malware patterns |
| `high_cpu_process` | Abnormal CPU consumption, possible cryptominer |
| `ransomware` | Mass file modification pattern on local filesystem |
| `c2_beacon` | Regular outbound beaconing pattern suggesting C2 |
| `lateral_movement` | Unexpected internal network traversal |
| `exfiltration` | Unusual outbound data volume to new destinations |
| `credential_stuffing` | Systematic valid credential attempts from many IPs |
| `honeypot_interaction` | Attacker interacted with a deployed honeypot |
| `anomaly` | General behavioral anomaly not matching known patterns |

---

## Error Responses

All errors return a consistent JSON structure:

```json
{
  "detail": "Human-readable error description"
}
```

| Status Code | Meaning |
|-------------|---------|
| 400 | Bad Request — invalid request body or parameters |
| 401 | Unauthorized — missing or invalid token |
| 403 | Forbidden — token valid but insufficient permissions |
| 404 | Not Found — resource does not exist |
| 409 | Conflict — resource already exists |
| 422 | Unprocessable Entity — validation error (see detail) |
| 500 | Internal Server Error — something went wrong on the server |

---

## Rate Limiting

API endpoints are rate limited per token:

| Endpoint group | Limit |
|----------------|-------|
| POST /api/events | 1000 requests/minute |
| GET endpoints | 300 requests/minute |
| POST /api/devices/register | 10 requests/minute |
| GET /api/intelligence/lookup | 60 requests/minute |

When rate limited, the response is `429 Too Many Requests` with a `Retry-After` header indicating seconds to wait.

---

## Pagination

List endpoints support cursor-based pagination via `limit` and `offset`:

```
GET /api/events?limit=50&offset=0   # First page
GET /api/events?limit=50&offset=50  # Second page
```

The response does not include total count by default. Use `/api/events/stats/summary` for aggregate counts.

---

*ARGOS API Reference — v0.1.0*
