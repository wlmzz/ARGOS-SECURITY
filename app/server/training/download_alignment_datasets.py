"""
ARGOS — Download Alignment Datasets
Scarica dataset pubblici uncensored/unfiltered da HuggingFace
e li converte in formato Alpaca per il training di alignment.

Usage:
    python download_alignment_datasets.py
"""

import json
import os
import sys
import requests
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "alignment" / "downloaded"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

HF_TOKEN = os.getenv("HF_TOKEN", "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

DATASETS = [
    {
        "id":   "xzuyn/open-instruct-uncensored-alpaca",
        "name": "open_instruct_uncensored",
        "max":  50_000,   # ne prendiamo 50k su 3.66M
        "fmt":  "alpaca", # instruction / input / output
    },
    {
        "id":   "QuixiAI/WizardLM_alpaca_evol_instruct_70k_unfiltered",
        "name": "wizardlm_unfiltered",
        "max":  55_000,   # tutto
        "fmt":  "alpaca", # instruction / output
    },
    {
        "id":   "digitalpipelines/wizard_vicuna_70k_uncensored",
        "name": "wizard_vicuna_uncensored",
        "max":  34_000,   # tutto
        "fmt":  "conversations", # conversations [{from, value}]
    },
    {
        "id":   "jondurbin/airoboros-3.2",
        "name": "airoboros_uncensored",
        "max":  20_000,
        "fmt":  "conversations",
    },
]


def to_alpaca(example: dict, fmt: str) -> dict | None:
    """Converte vari formati in Alpaca standard."""
    try:
        if fmt == "alpaca":
            instruction = str(example.get("instruction", "") or "").strip()
            output = str(example.get("output", "") or "").strip()
            if not instruction or not output:
                return None
            return {
                "instruction": instruction[:2000],
                "input":       str(example.get("input", "") or "").strip()[:500],
                "output":      output[:4000],
            }

        if fmt == "conversations":
            convs = example.get("conversations", [])
            if not convs:
                return None
            human = next((c.get("value", "") for c in convs
                         if c.get("from") in ("human", "user")), "")
            gpt   = next((c.get("value", "") for c in convs
                         if c.get("from") in ("gpt", "assistant")), "")
            if not human or not gpt:
                return None
            return {
                "instruction": str(human).strip()[:2000],
                "input":       "",
                "output":      str(gpt).strip()[:4000],
            }

    except Exception:
        return None
    return None


def download_hf(dataset_id: str, name: str, max_examples: int, fmt: str):
    out_path = OUTPUT_DIR / f"{name}.jsonl"
    if out_path.exists():
        count = sum(1 for _ in out_path.open())
        print(f"  SKIP (già presente: {count} esempi) — {out_path.name}")
        return count

    print(f"  Scaricamento {dataset_id} (max {max_examples:,} esempi)...")

    try:
        from datasets import load_dataset
    except ImportError:
        print("  ERRORE: installa datasets → pip install datasets")
        return 0

    try:
        ds = load_dataset(dataset_id, split="train", streaming=True,
                          token=HF_TOKEN)
    except Exception as e:
        print(f"  ERRORE caricamento: {e}")
        return 0

    written = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for example in ds:
            converted = to_alpaca(example, fmt)
            if converted and converted.get("output", "").strip():
                f.write(json.dumps(converted, ensure_ascii=False) + "\n")
                written += 1
                if written >= max_examples:
                    break
                if written % 5000 == 0:
                    print(f"    {written:,} esempi...")

    print(f"  OK: {written:,} esempi → {out_path.name}")
    return written


def download_ptaas():
    """Scarica il dataset pentest da GitHub ptaas-tool."""
    out_path = OUTPUT_DIR / "ptaas_pentest.jsonl"
    if out_path.exists():
        count = sum(1 for _ in out_path.open())
        print(f"  SKIP (già presente: {count} esempi) — {out_path.name}")
        return count

    print("  Scaricamento ptaas-tool/dataset (pentest vulnerabilità→attacchi)...")

    base = "https://raw.githubusercontent.com/ptaas-tool/dataset/main"
    versions = ["v0.1/dataset.json", "v0.2/dataset.json",
                "v0.3/dataset.json", "v0.4/dataset.json"]

    written = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for v in versions:
            try:
                r = requests.get(f"{base}/{v}", timeout=30)
                if r.status_code != 200:
                    print(f"    SKIP {v}: HTTP {r.status_code}")
                    continue
                data = r.json()
                entries = data if isinstance(data, list) else data.get("data", [])
                for entry in entries:
                    vulns   = entry.get("vulnerabilities", [])
                    attacks = entry.get("attacks", [])
                    if not vulns or not attacks:
                        continue
                    instruction = (
                        f"Given these vulnerabilities: {', '.join(vulns)}. "
                        f"What penetration testing attacks can be performed?"
                    )
                    output = (
                        f"Based on the identified vulnerabilities, the following "
                        f"attacks can be performed: {', '.join(attacks)}. "
                        f"Each attack targets the specific weakness exposed by the "
                        f"corresponding vulnerability."
                    )
                    ex = {"instruction": instruction, "input": "", "output": output}
                    f.write(json.dumps(ex, ensure_ascii=False) + "\n")
                    written += 1
                print(f"    {v}: {len(entries)} esempi")
            except Exception as e:
                print(f"    ERRORE {v}: {e}")

    print(f"  OK: {written} esempi → {out_path.name}")
    return written


def merge_to_alignment():
    """Unisce tutti i file scaricati in un unico file per il training."""
    merged_path = Path(__file__).parent / "alignment" / "05_uncensored_base_DOWNLOADED.jsonl"
    files = list(OUTPUT_DIR.glob("*.jsonl"))
    if not files:
        print("\nNessun file da unire.")
        return

    total = 0
    with open(merged_path, "w", encoding="utf-8") as out:
        for f in files:
            count = 0
            for line in f.open(encoding="utf-8"):
                line = line.strip()
                if line:
                    out.write(line + "\n")
                    count += 1
            total += count
            print(f"  Aggiunto {f.name}: {count:,} esempi")

    print(f"\nMerge completato: {total:,} esempi totali → {merged_path.name}")


def main():
    print("=== ARGOS Alignment Dataset Downloader ===\n")

    total = 0

    # HuggingFace datasets
    for ds in DATASETS:
        n = download_hf(ds["id"], ds["name"], ds["max"], ds["fmt"])
        total += n
        print()

    # GitHub pentest dataset
    n = download_ptaas()
    total += n
    print()

    print(f"=== Totale esempi scaricati: {total:,} ===\n")

    # Unisci tutto
    merge_to_alignment()

    print("\nProssimo step:")
    print("  python build_alignment_dataset.py")


if __name__ == "__main__":
    main()
