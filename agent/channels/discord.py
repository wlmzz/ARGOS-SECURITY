"""
ARGOS Discord channel — bot that listens to messages and responds via the agent loop.
Inspired by OpenClaw's Discord extension plugin architecture.

Setup:
  1. Create bot at discord.com/developers → copy token
  2. Enable "Message Content Intent" in Bot settings
  3. Invite bot with scopes: bot + applications.commands
  4. Set DISCORD_BOT_TOKEN env var or pass --token

Usage:
    python main.py --mode discord --token YOUR_BOT_TOKEN
    python main.py --mode discord --token TOKEN --allowed-guilds 123456 789012
"""
from __future__ import annotations
import json, logging, os, threading, time, urllib.request, urllib.parse
from typing import Callable

log = logging.getLogger("argos.discord")

DISCORD_API = "https://discord.com/api/v10"


class DiscordBot:
    def __init__(self, token: str, allowed_guild_ids: list[int] | None = None,
                 allowed_channel_ids: list[int] | None = None):
        if not token:
            raise ValueError("Discord bot token required")
        self.token = token
        self.allowed_guilds = set(allowed_guild_ids or [])
        self.allowed_channels = set(allowed_channel_ids or [])
        self.headers = {
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "ARGOS-Bot (cybersecurity-agent, 1.0)",
        }
        self._gateway_url: str = ""
        self._session_id: str = ""
        self._sequence: int | None = None
        self._running = False

    def _api(self, method: str, path: str, data: dict | None = None) -> dict:
        url = f"{DISCORD_API}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def send_message(self, channel_id: int | str, content: str) -> dict:
        """Send a message to a Discord channel. Splits long messages automatically."""
        # Discord max message length is 2000 chars
        content = str(content)
        if len(content) <= 1990:
            return self._api("POST", f"/channels/{channel_id}/messages",
                             {"content": content})
        # Split into chunks
        chunks = [content[i:i+1990] for i in range(0, len(content), 1990)]
        result = {}
        for chunk in chunks:
            result = self._api("POST", f"/channels/{channel_id}/messages",
                               {"content": chunk})
            time.sleep(0.5)
        return result

    def send_typing(self, channel_id: int | str) -> None:
        """Show typing indicator."""
        self._api("POST", f"/channels/{channel_id}/typing")

    def _is_allowed(self, guild_id: int | None, channel_id: int | None) -> bool:
        if self.allowed_guilds and guild_id not in self.allowed_guilds:
            return False
        if self.allowed_channels and channel_id not in self.allowed_channels:
            return False
        return True

    def run(self, on_message: Callable[[int, str, str], None]) -> None:
        """
        Start the bot using Discord's Gateway (WebSocket).
        on_message(channel_id, user_id, message_text) called for each message.
        Falls back to HTTP long-polling if websockets not available.
        """
        try:
            import websocket
            self._run_gateway(on_message)
        except ImportError:
            log.warning("websocket-client not installed — using HTTP polling fallback")
            log.warning("Install for better performance: pip install websocket-client")
            self._run_polling(on_message)

    def _run_gateway(self, on_message: Callable) -> None:
        """WebSocket gateway connection (preferred)."""
        import websocket

        # Get gateway URL
        gw = self._api("GET", "/gateway/bot")
        ws_url = gw.get("url", "wss://gateway.discord.gg") + "?v=10&encoding=json"
        log.info("Connecting to Discord Gateway: %s", ws_url)

        heartbeat_interval = None
        heartbeat_thread = None

        def on_ws_message(ws, raw):
            nonlocal heartbeat_interval, heartbeat_thread
            msg = json.loads(raw)
            op = msg.get("op")
            data = msg.get("d", {})
            t = msg.get("t")
            s = msg.get("s")
            if s:
                self._sequence = s

            if op == 10:  # Hello
                heartbeat_interval = data["heartbeat_interval"] / 1000
                # Send identify
                ws.send(json.dumps({
                    "op": 2,
                    "d": {
                        "token": self.token,
                        "intents": 33280,  # GUILDS + GUILD_MESSAGES + MESSAGE_CONTENT
                        "properties": {"os": "linux", "browser": "argos", "device": "argos"},
                    }
                }))
                # Start heartbeating
                def heartbeat():
                    while self._running:
                        time.sleep(heartbeat_interval)
                        ws.send(json.dumps({"op": 1, "d": self._sequence}))
                heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
                heartbeat_thread.start()

            elif op == 0 and t == "READY":
                self._session_id = data.get("session_id", "")
                user = data.get("user", {})
                log.info("Discord connected as %s#%s", user.get("username"), user.get("discriminator"))

            elif op == 0 and t == "MESSAGE_CREATE":
                author = data.get("author", {})
                if author.get("bot"):
                    return  # Ignore bot messages
                guild_id = int(data["guild_id"]) if data.get("guild_id") else None
                channel_id = int(data["channel_id"])
                if not self._is_allowed(guild_id, channel_id):
                    return
                content = data.get("content", "").strip()
                if not content:
                    return
                user_id = author.get("id", "unknown")
                log.info("Discord message from %s in #%s: %s", user_id, channel_id, content[:80])
                threading.Thread(
                    target=on_message,
                    args=(channel_id, user_id, content),
                    daemon=True
                ).start()

        def on_ws_error(ws, error):
            log.error("Discord WS error: %s", error)

        def on_ws_close(ws, code, msg):
            log.warning("Discord WS closed: %s %s — reconnecting in 5s", code, msg)
            self._running = False

        self._running = True
        ws = websocket.WebSocketApp(ws_url,
                                    on_message=on_ws_message,
                                    on_error=on_ws_error,
                                    on_close=on_ws_close)
        while True:
            self._running = True
            ws.run_forever(ping_interval=30)
            time.sleep(5)
            log.info("Reconnecting to Discord...")

    def _run_polling(self, on_message: Callable) -> None:
        """HTTP polling fallback (no websocket-client)."""
        log.info("Discord HTTP polling started")
        last_message_id: dict[int, int] = {}

        # Get bot's own user ID to avoid self-replies
        me = self._api("GET", "/users/@me")
        my_id = me.get("id")

        while True:
            try:
                # Get list of guilds
                guilds = self._api("GET", "/users/@me/guilds")
                if isinstance(guilds, list):
                    for guild in guilds:
                        gid = int(guild["id"])
                        if self.allowed_guilds and gid not in self.allowed_guilds:
                            continue
                        channels = self._api("GET", f"/guilds/{gid}/channels")
                        if not isinstance(channels, list):
                            continue
                        for ch in channels:
                            if ch.get("type") != 0:  # text channels only
                                continue
                            cid = int(ch["id"])
                            if self.allowed_channels and cid not in self.allowed_channels:
                                continue
                            params = "?limit=5"
                            if cid in last_message_id:
                                params += f"&after={last_message_id[cid]}"
                            messages = self._api("GET", f"/channels/{cid}/messages{params}")
                            if not isinstance(messages, list):
                                continue
                            for msg in reversed(messages):
                                mid = int(msg["id"])
                                if mid <= last_message_id.get(cid, 0):
                                    continue
                                last_message_id[cid] = mid
                                author = msg.get("author", {})
                                if author.get("bot") or author.get("id") == my_id:
                                    continue
                                content = msg.get("content", "").strip()
                                if content:
                                    threading.Thread(
                                        target=on_message,
                                        args=(cid, author.get("id", "unknown"), content),
                                        daemon=True
                                    ).start()
            except Exception as e:
                log.error("Discord polling error: %s", e)
            time.sleep(3)
