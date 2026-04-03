"""
ARGOS — Weekly dataset preparation
Raccoglie gli eventi da Qdrant (usato_in_training: false, confidence > 0.85)
e prepara un JSONL per il training.

Eseguito ogni domenica alle 02:00 dal systemd timer.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.prepare_dataset")

QDRANT_URL    = os.getenv("QDRANT_URL", "http://localhost:6333")
OUTPUT_DIR    = Path(os.getenv("DATASETS_WEEKLY_DIR", "/opt/argos/training/datasets/weekly"))
MIN_EXAMPLES  = int(os.getenv("MIN_TRAINING_EXAMPLES", "50"))
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.85"))
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT  = os.getenv("TELEGRAM_CHAT_ID", "")

TRAINING_READY_FLAG = Path("/opt/argos/training/.training_ready")


def telegram(msg: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "Markdown"},
            timeout=10,
        )
    except Exception:
        pass


def fetch_unused_events() -> list[dict]:
    """Fetch events not yet used in training from Qdrant."""
    examples = []
    offset = None
    while True:
        payload: dict = {
            "filter": {
                "must": [
                    {"key": "usato_in_training", "match": {"value": False}},
                ]
            },
            "with_payload": True,
            "limit": 100,
        }
        if offset:
            payload["offset"] = offset

        try:
            r = requests.post(
                f"{QDRANT_URL}/collections/argos_attacks/points/scroll",
                json=payload,
                timeout=30,
            )
            data = r.json()
        except Exception as e:
            log.error("Qdrant error: %s", e)
            break

        points = data.get("result", {}).get("points", [])
        if not points:
            break

        for p in points:
            pl = p.get("payload", {})
            confidence = pl.get("confidence", 0.0)
            if confidence >= MIN_CONFIDENCE:
                examples.append(p)

        next_page = data.get("result", {}).get("next_page_offset")
        if not next_page:
            break
        offset = next_page

    log.info("Found %d events with confidence >= %.2f", len(examples), MIN_CONFIDENCE)
    return examples


def event_to_training_example(event: dict) -> dict | None:
    """Convert a Qdrant event payload to Alpaca training format."""
    pl = event.get("payload", {})
    tipo    = pl.get("tipo", pl.get("threat_type", "unknown"))
    ip      = pl.get("ip", pl.get("source_ip", "?"))
    details = pl.get("dettagli", pl.get("reasoning", ""))
    actions = pl.get("azioni", pl.get("actions", []))
    level   = pl.get("threat_level", "HIGH")
    conf    = pl.get("confidence", 0.9)

    if not details:
        return None

    instruction = "Analyze this cybersecurity threat and return a JSON decision."
    inp = (
        f"Threat Type: {tipo}\n"
        f"Severity: {level}\n"
        f"Source IP: {ip}\n"
        f"Description: {details}"
    )
    output = json.dumps({
        "threat_level": level,
        "attack_type": tipo,
        "confidence": conf,
        "actions": actions,
        "reasoning": details,
    }, ensure_ascii=False)

    return {"instruction": instruction, "input": inp, "output": output}


def mark_events_used(event_ids: list[str]) -> None:
    """Mark events as used_in_training in Qdrant."""
    if not event_ids:
        return
    try:
        requests.post(
            f"{QDRANT_URL}/collections/argos_attacks/points/payload",
            json={
                "payload": {"usato_in_training": True},
                "points": event_ids,
            },
            timeout=30,
        )
        log.info("Marked %d events as used_in_training", len(event_ids))
    except Exception as e:
        log.error("Failed to mark events: %s", e)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"dataset_{timestamp}.jsonl"

    log.info("Fetching unused events from Qdrant...")
    events = fetch_unused_events()

    if len(events) < MIN_EXAMPLES:
        log.info("Not enough examples (%d / %d). Skipping.", len(events), MIN_EXAMPLES)
        telegram(
            f"📊 *ARGOS Dataset Check*\n"
            f"• {len(events)}/{MIN_EXAMPLES} esempi disponibili\n"
            f"• Training non schedulato (dati insufficienti)"
        )
        return

    # Convert to training format
    training_examples = []
    used_ids = []
    for event in events:
        ex = event_to_training_example(event)
        if ex:
            training_examples.append(ex)
            used_ids.append(event["id"])

    # Write JSONL
    with open(output_path, "w") as f:
        for ex in training_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    log.info("Dataset saved: %s (%d examples)", output_path, len(training_examples))

    # Set training_ready flag with dataset path
    TRAINING_READY_FLAG.write_text(str(output_path))
    log.info("Training ready flag set: %s", TRAINING_READY_FLAG)

    telegram(
        f"📊 *ARGOS Dataset Pronto*\n"
        f"• {len(training_examples)} esempi\n"
        f"• File: `{output_path.name}`\n"
        f"• Training schedulato al prossimo trigger mensile"
    )


if __name__ == "__main__":
    main()
