"""Session history management with context compaction (inspired by OpenClaw)."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

SESSION_DIR = Path("/opt/argos/agent/sessions")
MAX_HISTORY_CHARS = 24_000   # compact when history exceeds this
KEEP_RECENT = 6              # always keep last N message pairs


class Session:
    def __init__(self, session_id: str):
        self.session_id = session_id
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self.path = SESSION_DIR / f"{session_id}.jsonl"
        self.history: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        messages = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    messages.append(json.loads(line))
                except Exception:
                    pass
        return messages

    def add(self, role: str, content: str | list) -> None:
        msg = {"role": role, "content": content}
        self.history.append(msg)
        with open(self.path, "a") as f:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")

    def get_messages(self) -> list[dict]:
        return list(self.history)

    def needs_compaction(self) -> bool:
        total = sum(
            len(json.dumps(m)) for m in self.history
        )
        return total > MAX_HISTORY_CHARS

    def compact(self, summary: str) -> None:
        """Replace old history with a summary + keep recent messages."""
        recent = self.history[-(KEEP_RECENT * 2):]
        self.history = [
            {"role": "user", "content": f"[CONTEXT SUMMARY]\n{summary}"},
            {"role": "assistant", "content": "Understood. I have the context summary."},
        ] + recent
        # Rewrite file
        with open(self.path, "w") as f:
            for msg in self.history:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")

    def clear(self) -> None:
        self.history = []
        if self.path.exists():
            self.path.unlink()
