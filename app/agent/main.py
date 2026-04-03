"""
ARGOS Autonomous Agent — Entry point.

Usage:
  python main.py --mode cli                              # interactive CLI
  python main.py --mode telegram --token BOT_TOKEN [--allowed-ids 123456 789012]
  python main.py --mode discord  --token BOT_TOKEN [--allowed-guilds 123 456]
  python main.py --mode webhook  --port 9000 --webhook-key mysecret
  python main.py --mode cli --session my-session         # named session
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

# Add agent dir to path
sys.path.insert(0, os.path.dirname(__file__))

import agent
from session import Session

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.main")


def run_cli(session_id: str = "cli-default") -> None:
    sess = Session(session_id)
    print("\n╔══════════════════════════════════════╗")
    print("║   ARGOS Cybersecurity Agent (CLI)    ║")
    print("║   Type 'exit' or Ctrl-C to quit      ║")
    print("╚══════════════════════════════════════╝\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[ARGOS] Goodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            print("[ARGOS] Goodbye.")
            break
        if user_input.lower() == "/clear":
            sess.clear()
            print("[ARGOS] Session cleared.")
            continue
        if user_input.lower() == "/history":
            for m in sess.get_messages():
                role = m.get("role", "?")
                content = m.get("content", "")
                if isinstance(content, list):
                    content = str(content)
                print(f"  [{role}] {content[:200]}")
            continue

        print("ARGOS: ", end="", flush=True)
        response = agent.run(user_input, sess,
                             on_chunk=lambda t: print(t, flush=True))
        if not response:
            print()


def run_discord(token: str, allowed_guilds: list[int], allowed_channels: list[int],
                session_prefix: str = "dc") -> None:
    from channels.discord import DiscordBot

    bot = DiscordBot(token=token, allowed_guild_ids=allowed_guilds,
                     allowed_channel_ids=allowed_channels)
    sessions: dict[str, Session] = {}

    def on_message(channel_id: int, user_id: str, text: str) -> None:
        sess_key = f"{session_prefix}-{channel_id}-{user_id}"
        if sess_key not in sessions:
            sessions[sess_key] = Session(sess_key)
        sess = sessions[sess_key]

        if text.startswith("/"):
            if text == "/start":
                bot.send_message(channel_id, "🔐 **ARGOS Cybersecurity Agent** online.\nSend a security question, log to analyze, or IP to investigate.")
                return
            if text == "/clear":
                sess.clear()
                bot.send_message(channel_id, "🗑️ Session cleared.")
                return
            if text == "/status":
                from audit import verify_audit_integrity
                integrity = verify_audit_integrity()
                bot.send_message(channel_id, f"✅ ARGOS online | Audit log: {integrity.get('status')} ({integrity.get('entries', 0)} entries)")
                return

        bot.send_message(channel_id, "🔍 **ARGOS** analyzing…")
        response = agent.run(text, sess)
        if response:
            bot.send_message(channel_id, response)
        else:
            bot.send_message(channel_id, "[ARGOS] No response generated.")

    bot.run(on_message)


def run_webhook(port: int, secret_key: str) -> None:
    from channels.webhook import WebhookServer
    from audit import tail_audit

    def on_message(message: str, session_id: str) -> str:
        sess = Session(session_id)
        return agent.run(message, sess) or "[ARGOS] No response."

    server = WebhookServer(
        port=port,
        secret_key=secret_key,
        on_message=on_message,
        audit_fn=lambda: tail_audit(50),
    )
    server.run()


def run_telegram(token: str, allowed_ids: list[int], session_prefix: str = "tg") -> None:
    from channels.telegram import TelegramBot

    bot = TelegramBot(token=token, allowed_chat_ids=allowed_ids)
    sessions: dict[int, Session] = {}

    def on_message(chat_id: int, text: str) -> None:
        if chat_id not in sessions:
            sessions[chat_id] = Session(f"{session_prefix}-{chat_id}")

        sess = sessions[chat_id]
        bot.send_typing(chat_id)

        if text.startswith("/"):
            if text == "/start":
                bot.send_message(chat_id, "🔐 *ARGOS Cybersecurity Agent* online.\n\nSend me a security question, log to analyze, or target to investigate.")
                return
            if text == "/clear":
                sess.clear()
                bot.send_message(chat_id, "🗑️ Session cleared.")
                return
            if text == "/help":
                help_text = (
                    "*ARGOS Commands:*\n"
                    "/clear — clear conversation history\n"
                    "/help — show this help\n\n"
                    "*Capabilities:*\n"
                    "• Analyze logs for threats\n"
                    "• CVE lookups (CVE-2024-XXXXX)\n"
                    "• IP reputation & geolocation\n"
                    "• File hash lookup (malware)\n"
                    "• Port scanning (authorized targets)\n"
                    "• DNS, WHOIS recon\n"
                    "• IOC extraction from text\n"
                    "• Security report generation"
                )
                bot.send_message(chat_id, help_text)
                return

        log.info("Processing message from %d: %s", chat_id, text[:80])
        bot.send_message(chat_id, "🔍 *ARGOS* analyzing… _(may take 1-2 min)_")
        response = agent.run(text, sess)
        if response:
            bot.send_message(chat_id, response)
        else:
            bot.send_message(chat_id, "[ARGOS] No response generated.")

    bot.run(on_message)


def main() -> None:
    p = argparse.ArgumentParser(description="ARGOS Autonomous Cybersecurity Agent")
    p.add_argument("--mode", choices=["cli", "telegram", "discord", "webhook"], default="cli")
    p.add_argument("--session", default="cli-default", help="Session ID for CLI mode")
    p.add_argument("--token", help="Bot token (Telegram or Discord)")
    p.add_argument("--allowed-ids", nargs="*", type=int, default=[],
                   help="Allowed Telegram chat IDs (empty = allow all)")
    p.add_argument("--allowed-guilds", nargs="*", type=int, default=[],
                   help="Allowed Discord guild/server IDs (empty = allow all)")
    p.add_argument("--allowed-channels", nargs="*", type=int, default=[],
                   help="Allowed Discord channel IDs (empty = allow all)")
    p.add_argument("--port", type=int, default=9000, help="Port for webhook server")
    p.add_argument("--webhook-key", default=os.environ.get("ARGOS_WEBHOOK_KEY", ""),
                   help="Secret key for webhook authentication (X-ARGOS-Key header)")
    p.add_argument("--fast", action="store_true",
                   help="Use fast professor model on port 8090 (no API key, 7B)")
    args = p.parse_args()

    if args.fast:
        os.environ["ARGOS_LLM_URL"] = "http://localhost:8090/v1/chat/completions"
        os.environ["ARGOS_LLM_KEY"] = ""
        os.environ["ARGOS_LLM_MODEL"] = "professor-7b"
        log.info("Using fast professor model at port 8090")

    if args.mode == "cli":
        run_cli(session_id=args.session)
    elif args.mode == "telegram":
        args.token = args.token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        if not args.token:
            print("[ERROR] --token required for telegram mode (or set TELEGRAM_BOT_TOKEN env var)")
            sys.exit(1)
        run_telegram(args.token, args.allowed_ids)
    elif args.mode == "discord":
        args.token = args.token or os.environ.get("DISCORD_BOT_TOKEN", "")
        if not args.token:
            print("[ERROR] --token required for discord mode (or set DISCORD_BOT_TOKEN env var)")
            sys.exit(1)
        run_discord(args.token, args.allowed_guilds, args.allowed_channels)
    elif args.mode == "webhook":
        if not args.webhook_key:
            print("[WARN] No --webhook-key set — webhook server is open to anyone!")
        run_webhook(args.port, args.webhook_key)


if __name__ == "__main__":
    main()
