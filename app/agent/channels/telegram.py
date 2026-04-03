"""Telegram bot channel for ARGOS — remote access via bot."""
from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.parse
from typing import Any

log = logging.getLogger("argos.telegram")

BASE_URL = "https://api.telegram.org/bot{token}"


class TelegramBot:
    def __init__(self, token: str, allowed_chat_ids: list[int] | None = None):
        self.token = token
        self.base = f"https://api.telegram.org/bot{token}"
        self.allowed_ids = set(allowed_chat_ids or [])
        self.offset = 0

    def _post(self, method: str, data: dict) -> dict:
        url = f"{self.base}/{method}"
        payload = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            log.warning("Telegram API error (%s): %s", method, e)
            return {"ok": False, "error": str(e)}

    def send_message(self, chat_id: int, text: str, parse_mode: str = "Markdown") -> dict:
        # Telegram has 4096 char limit per message
        if len(text) <= 4096:
            return self._post("sendMessage", {
                "chat_id": chat_id, "text": text, "parse_mode": parse_mode
            })
        # Split long messages
        chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
        result = {}
        for chunk in chunks:
            result = self._post("sendMessage", {
                "chat_id": chat_id, "text": chunk, "parse_mode": parse_mode
            })
            time.sleep(0.5)
        return result

    def send_typing(self, chat_id: int) -> None:
        self._post("sendChatAction", {"chat_id": chat_id, "action": "typing"})

    def get_updates(self, timeout: int = 30) -> list[dict]:
        data = {"offset": self.offset, "timeout": timeout, "allowed_updates": ["message"]}
        result = self._post("getUpdates", data)
        if not result.get("ok"):
            return []
        updates = result.get("result", [])
        if updates:
            self.offset = updates[-1]["update_id"] + 1
        return updates

    def is_allowed(self, chat_id: int) -> bool:
        if not self.allowed_ids:
            return True  # open to all if no allowlist
        return chat_id in self.allowed_ids

    def run(self, on_message_callback) -> None:
        """Long-poll loop. Calls on_message_callback(chat_id, text) for each message."""
        log.info("Telegram bot started (long polling)")
        me = self._post("getMe", {})
        if me.get("ok"):
            username = me["result"].get("username", "unknown")
            log.info("Bot @%s is ready", username)

        while True:
            try:
                updates = self.get_updates(timeout=30)
                for update in updates:
                    msg = update.get("message", {})
                    if not msg:
                        continue
                    chat_id = msg["chat"]["id"]
                    text = msg.get("text", "").strip()
                    if not text:
                        continue
                    if not self.is_allowed(chat_id):
                        self.send_message(chat_id, "⛔ Unauthorized. Contact ARGOS admin.")
                        log.warning("Rejected message from unauthorized chat_id: %d", chat_id)
                        continue
                    log.info("Message from chat %d: %s", chat_id, text[:80])
                    try:
                        on_message_callback(chat_id, text)
                    except Exception as e:
                        log.exception("Error handling message: %s", e)
                        self.send_message(chat_id, f"[ARGOS ERROR] {e}")
            except KeyboardInterrupt:
                log.info("Telegram bot stopping")
                break
            except Exception as e:
                log.warning("Polling error: %s — retrying in 5s", e)
                time.sleep(5)
