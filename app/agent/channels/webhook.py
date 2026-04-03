"""
ARGOS Webhook Server — HTTP API endpoint for receiving messages from any source.
Inspired by OpenClaw's webhook-targets and webhook-request-guards.

Exposes:
  POST /argos/message  → send a message to the agent, get a response
  GET  /argos/health   → liveness check
  GET  /argos/audit    → last 50 audit log entries (requires X-ARGOS-Key header)

Protections:
  - Shared secret (X-ARGOS-Key header)
  - Rate limiting: 10 requests / 60s per IP
  - Request size limit: 32KB
  - No secrets in responses

Usage:
    python main.py --mode webhook --port 9000 --webhook-key mysecret
"""
from __future__ import annotations
import json, logging, os, time, threading
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable
from urllib.parse import urlparse

log = logging.getLogger("argos.webhook")

# Rate limiter: max N requests per window per IP
_rate_window = 60       # seconds
_rate_max    = 10       # requests per window
_rate_hits: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()


def _check_rate(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_hits[ip] = [t for t in _rate_hits[ip] if now - t < _rate_window]
        if len(_rate_hits[ip]) >= _rate_max:
            return False
        _rate_hits[ip].append(now)
        return True


def make_handler(on_message: Callable[[str, str], str],
                 secret_key: str,
                 audit_fn: Callable | None = None) -> type:

    class ArgosHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _ip(self) -> str:
            forwarded = self.headers.get("X-Forwarded-For", "")
            return forwarded.split(",")[0].strip() if forwarded else self.client_address[0]

        def _auth(self) -> bool:
            if not secret_key:
                return True
            provided = self.headers.get("X-ARGOS-Key", "") or self.headers.get("Authorization", "").replace("Bearer ", "")
            return provided == secret_key

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/argos/health":
                self._send(200, {"status": "ok", "agent": "ARGOS"})
            elif path == "/argos/audit":
                if not self._auth():
                    self._send(401, {"error": "Unauthorized"})
                    return
                entries = audit_fn() if audit_fn else []
                self._send(200, {"entries": entries})
            else:
                self._send(404, {"error": "Not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            ip = self._ip()

            if path != "/argos/message":
                self._send(404, {"error": "Not found"})
                return

            if not self._auth():
                log.warning("Unauthorized webhook request from %s", ip)
                self._send(401, {"error": "Unauthorized — set X-ARGOS-Key header"})
                return

            if not _check_rate(ip):
                self._send(429, {"error": f"Rate limit: max {_rate_max} requests per {_rate_window}s"})
                return

            length = int(self.headers.get("Content-Length", 0))
            if length > 32768:
                self._send(413, {"error": "Request too large (max 32KB)"})
                return

            try:
                body = json.loads(self.rfile.read(length).decode())
            except Exception:
                self._send(400, {"error": "Invalid JSON body"})
                return

            message = body.get("message", "").strip()
            session_id = body.get("session_id", f"webhook-{ip}")
            if not message:
                self._send(400, {"error": "message field required"})
                return

            log.info("Webhook message from %s [%s]: %s", ip, session_id, message[:80])
            try:
                response = on_message(message, session_id)
                self._send(200, {"response": response, "session_id": session_id})
            except Exception as e:
                log.exception("Agent error: %s", e)
                self._send(500, {"error": "Agent error", "detail": str(e)})

    return ArgosHandler


class WebhookServer:
    def __init__(self, port: int, secret_key: str,
                 on_message: Callable[[str, str], str],
                 audit_fn: Callable | None = None):
        self.port = port
        handler = make_handler(on_message, secret_key, audit_fn)
        self.server = HTTPServer(("0.0.0.0", port), handler)

    def run(self) -> None:
        log.info("ARGOS Webhook server listening on port %d", self.port)
        log.info("Endpoint: POST /argos/message  |  GET /argos/health")
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            log.info("Webhook server stopped.")
