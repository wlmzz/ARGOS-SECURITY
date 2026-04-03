import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .models import ThreatEvent


class ThreatDB:
    def __init__(self):
        db_path = Path.home() / ".argos" / "threats.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_schema()
        self._lock = threading.Lock()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                threat_type TEXT,
                severity TEXT,
                source_ip TEXT,
                source_port INTEGER,
                target_port INTEGER,
                protocol TEXT,
                description TEXT,
                raw_data TEXT,
                action_taken TEXT,
                ai_analysis TEXT,
                evidence_path TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at TEXT,
                expires_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_ip ON threats(source_ip)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON threats(timestamp)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_type ON threats(threat_type)
        """)
        self.conn.commit()

    def save_threat(self, event: ThreatEvent):
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.id, event.timestamp, event.threat_type, event.severity,
                event.source_ip, event.source_port, event.target_port,
                event.protocol, event.description, json.dumps(event.raw_data),
                event.action_taken, event.ai_analysis, event.evidence_path
            ))
            self.conn.commit()

    def get_ip_history(self, ip: str) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM threats WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 50",
                (ip,)
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "SELECT ip FROM blocked_ips WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)",
                (ip, datetime.now().isoformat())
            )
            return cur.fetchone() is not None

    def block_ip(self, ip: str, reason: str, duration_minutes: Optional[int] = None):
        expires = None
        if duration_minutes:
            expires = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?,?)
            """, (ip, reason, datetime.now().isoformat(), expires))
            self.conn.commit()

    def get_recent_threats(self, hours: int = 24) -> list[dict]:
        """Return all threats recorded in the last `hours` hours."""
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM threats WHERE timestamp >= ? ORDER BY timestamp DESC",
                (since,)
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_blocked_ips(self) -> list[dict]:
        """Return list of currently blocked IPs with ip, reason, blocked_at."""
        with self._lock:
            cur = self.conn.execute(
                "SELECT ip, reason, blocked_at FROM blocked_ips "
                "WHERE expires_at IS NULL OR expires_at > ?",
                (datetime.now().isoformat(),)
            )
            return [{"ip": row[0], "reason": row[1], "blocked_at": row[2]}
                    for row in cur.fetchall()]

    def cleanup_expired_blocks(self):
        """Remove all expired IP blocks from the database."""
        with self._lock:
            self.conn.execute(
                "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (datetime.now().isoformat(),)
            )
            self.conn.commit()

    def count_threats_by_type(self) -> dict:
        """Return {threat_type: count} for threats recorded in the last 24 hours."""
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        with self._lock:
            cur = self.conn.execute(
                "SELECT threat_type, COUNT(*) FROM threats "
                "WHERE timestamp >= ? GROUP BY threat_type",
                (since,)
            )
            return {row[0]: row[1] for row in cur.fetchall()}
