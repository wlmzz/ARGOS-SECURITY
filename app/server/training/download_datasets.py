"""
ARGOS — Bulk download cybersecurity datasets from HuggingFace.
Downloads to /opt/argos/training/datasets/foundational/
Converte tutto in JSONL alpaca-format compatibile con train_argos.py

Usage:
    python download_datasets.py [--dry-run] [--max-size-mb 500]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import traceback
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.download_datasets")

OUTPUT_DIR = Path(os.getenv("DATASETS_FOUNDATIONAL_DIR", "/opt/argos/training/datasets/foundational"))

# ── Dataset list ───────────────────────────────────────────────────────────────
# Curated list: priorità a instruction-tuning, Q&A, MITRE ATT&CK, CVE, threat intel
DATASETS = [
    # ─── Instruction tuning / Q&A ─────────────────────────────────────────────
    {"id": "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset", "format": "alpaca",   "priority": 1},
    {"id": "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0",              "format": "alpaca",   "priority": 1},
    {"id": "AlicanKiraz0/Cybersecurity-Dataset-v1",                       "format": "alpaca",   "priority": 1},
    {"id": "AlicanKiraz0/Cybersecurity-Dataset-Heimdall-v1.1",            "format": "alpaca",   "priority": 1},
    {"id": "Vanessasml/cybersecurity_32k_instruction_input_output",       "format": "alpaca",   "priority": 1},
    {"id": "ChaoticNeutrals/Cybersecurity-ShareGPT",                      "format": "sharegpt", "priority": 1},
    {"id": "ystemsrx/Cybersecurity-ShareGPT-Chinese",                     "format": "sharegpt", "priority": 2},
    {"id": "Tiamz/cybersecurity-instruction-dataset",                     "format": "alpaca",   "priority": 1},
    {"id": "Chemically-motivated/CyberSecurityDataset",                   "format": "alpaca",   "priority": 1},
    {"id": "ethanolivertroy/nist-cybersecurity-training",                 "format": "alpaca",   "priority": 1},
    {"id": "luckwa/cybersecurity-dataset",                                "format": "alpaca",   "priority": 2},
    {"id": "Druva-S-Kumar/cybersecurity-qa-dataset",                      "format": "alpaca",   "priority": 2},
    {"id": "Rowden/CybersecurityQAA",                                     "format": "alpaca",   "priority": 2},
    {"id": "Zeo6/CyberSecurity-FineTune",                                 "format": "alpaca",   "priority": 2},
    {"id": "Mohabahmed03/Alpaca_Dataset_CyberSecurity_2.0",               "format": "alpaca",   "priority": 2},
    {"id": "Mohabahmed03/Alpaca_Dataset_CyberSecurity_Smaller_2.0",       "format": "alpaca",   "priority": 2},
    {"id": "Bouquets/DeepSeek-V3-Distill-Cybersecurity-en",               "format": "alpaca",   "priority": 2},
    {"id": "CyberNative/CyberSecurityEval",                               "format": "alpaca",   "priority": 2},
    {"id": "clydeiii/cybersecurity",                                      "format": "alpaca",   "priority": 1},
    {"id": "zeroshot/cybersecurity-corpus",                               "format": "text",     "priority": 2},
    {"id": "Canstralian/Purple-Team-Cybersecurity-Dataset",               "format": "alpaca",   "priority": 1},
    {"id": "jcordon5/cybersecurity-rules",                                "format": "alpaca",   "priority": 2},
    {"id": "theResearchNinja/violentutf_cybersecurityBehavior",           "format": "alpaca",   "priority": 2},

    # ─── CVE / Vulnerabilità ──────────────────────────────────────────────────
    {"id": "AlicanKiraz0/All-CVE-Records-Training-Dataset",              "format": "alpaca",   "priority": 1},
    {"id": "lambdasec/cve-single-line-fixes",                            "format": "alpaca",   "priority": 1},
    {"id": "morpheuslord/cve-llm-training",                              "format": "alpaca",   "priority": 1},
    {"id": "Trendyol/All-CVE-Chat-MultiTurn-1999-2025-Dataset",          "format": "sharegpt", "priority": 1},
    {"id": "Bouquets/Cybersecurity-LLM-CVE",                             "format": "alpaca",   "priority": 1},
    {"id": "yahoo-inc/cve-impacts",                                      "format": "alpaca",   "priority": 2},
    {"id": "DetectVul/CVEFixes",                                         "format": "alpaca",   "priority": 2},
    {"id": "MickyMike/cvefixes_bigvul",                                  "format": "alpaca",   "priority": 2},
    {"id": "icantiemyshoe/cve-to-metasploit-module",                     "format": "alpaca",   "priority": 2},
    {"id": "cvelist/CISA_Enrichment",                                    "format": "alpaca",   "priority": 2},

    # ─── MITRE ATT&CK / Threat Intel ─────────────────────────────────────────
    {"id": "sarahwei/cyber_MITRE_CTI_dataset_v15",                       "format": "alpaca",   "priority": 1},
    {"id": "dattaraj/security-attacks-MITRE",                            "format": "alpaca",   "priority": 1},
    {"id": "HoangCuongNguyen/CTI-to-MITRE-dataset",                     "format": "alpaca",   "priority": 1},
    {"id": "cobo512/Mitre-ATTACK-reasoning-dataset",                     "format": "alpaca",   "priority": 1},
    {"id": "mrmoor/cyber-threat-intelligence",                           "format": "alpaca",   "priority": 1},
    {"id": "VincentPai/encoded-MITRE-small",                             "format": "alpaca",   "priority": 2},
    {"id": "sarahwei/cyber_MITRE_attack_tactics-and-techniques",         "format": "alpaca",   "priority": 2},
    {"id": "reloading0101/threat-intelligence-dataset",                  "format": "alpaca",   "priority": 2},
    {"id": "AYI-NEDJIMI/threat-intelligence",                            "format": "alpaca",   "priority": 2},

    # ─── Network intrusion / attacchi ─────────────────────────────────────────
    {"id": "vinitvek/cybersecurityattacks",                              "format": "tabular",  "priority": 2},
    {"id": "pyToshka/network-intrusion-detection",                       "format": "tabular",  "priority": 2},
    {"id": "torchsight/cybersecurity-classification-benchmark",          "format": "alpaca",   "priority": 2},
    {"id": "onurkya7/NADW-network-attacks-dataset",                      "format": "tabular",  "priority": 2},
    {"id": "MrBinit/network-intrusion-detection",                        "format": "tabular",  "priority": 2},

    # ─── Pentest / Red Team ───────────────────────────────────────────────────
    {"id": "Canstralian/pentesting_dataset",                             "format": "alpaca",   "priority": 1},
    {"id": "preemware/pentesting-eval",                                  "format": "alpaca",   "priority": 2},
    {"id": "cowWhySo/pentest-redteam-steering",                          "format": "alpaca",   "priority": 2},
    {"id": "7h3-R3v3n4n7/pentest-agent-dataset-alpaca",                  "format": "alpaca",   "priority": 2},
    {"id": "7h3-R3v3n4n7/pentest-agent-dataset-chatml",                  "format": "sharegpt", "priority": 2},
    {"id": "AYI-NEDJIMI/bug-bounty-pentest-en",                          "format": "alpaca",   "priority": 2},
    {"id": "AYI-NEDJIMI/pentest-checklist-en",                           "format": "alpaca",   "priority": 2},
    {"id": "oksanany/pentest-cheatsheet",                                "format": "alpaca",   "priority": 2},
    {"id": "oksanany/pentest_tools_v2",                                  "format": "alpaca",   "priority": 2},
    {"id": "0dAI/PentestingCommandLogic",                                "format": "alpaca",   "priority": 2},
    {"id": "mikoube/pentest",                                            "format": "alpaca",   "priority": 2},
    {"id": "CJJones/Synthetic_PenTest_Reports",                          "format": "alpaca",   "priority": 2},
    {"id": "suryanshp1/kali-linux-pentesting-data",                      "format": "alpaca",   "priority": 2},

    # ─── CTF ──────────────────────────────────────────────────────────────────
    {"id": "ethz-spylab/ctf-satml24",                                    "format": "alpaca",   "priority": 2},
    {"id": "autogenCTF/CTFAIA",                                          "format": "alpaca",   "priority": 2},
    {"id": "justinwangx/CTFtime",                                        "format": "alpaca",   "priority": 2},

    # ─── NER / classificazione ────────────────────────────────────────────────
    {"id": "bnsapa/cybersecurity-ner",                                   "format": "ner",      "priority": 2},
    {"id": "naorm/malware-text-db",                                      "format": "alpaca",   "priority": 2},
    {"id": "naorm/malware-text-db-cyner-512",                            "format": "alpaca",   "priority": 2},

    # ─── Malware (aggiuntivi) ─────────────────────────────────────────────────
    {"id": "rr4433/Powershell_Malware_Detection_Dataset",                "format": "alpaca",   "priority": 1},
    {"id": "mahmud0x/malware-datasets",                                  "format": "alpaca",   "priority": 2},
    {"id": "ddl0620/malware-dataset",                                    "format": "alpaca",   "priority": 2},
    {"id": "mikosovsky/malware-vxunderground-2024-code-decompiled",      "format": "alpaca",   "priority": 2},
    {"id": "thang261104/js_code_slice_malware_dataset",                  "format": "alpaca",   "priority": 2},
    {"id": "nzeyzz/community-malware-samples",                           "format": "alpaca",   "priority": 2},

    # ─── Reverse Engineering ──────────────────────────────────────────────────
    {"id": "atul10/reverse_engineering_code_dataset_O2_x64_O2",          "format": "alpaca",   "priority": 1},
    {"id": "atul10/reverse_engineering_code_dataset_O2_mips_O2",         "format": "alpaca",   "priority": 2},
    {"id": "atul10/reverse_engineering_code_dataset_O2_arm_O2",          "format": "alpaca",   "priority": 2},
    {"id": "atul10/prompt_reverse_engineering_code_dataset_O3_arm_O3_advanced_custom_test", "format": "alpaca", "priority": 2},
    {"id": "bshada/reverseengineering.stackexchange.com",                "format": "alpaca",   "priority": 2},

    # ─── Vulnerability Detection (code) ───────────────────────────────────────
    {"id": "SecCoderX/SecCoderX_Reasoning_Vulnerability_Detection_SFT_Cold_Start_Dataset", "format": "alpaca", "priority": 1},
    {"id": "athrv/megavul-vulnerability-detection",                      "format": "alpaca",   "priority": 1},
    {"id": "athrv/megavul-vulnerability-detection-java",                 "format": "alpaca",   "priority": 1},
    {"id": "DanCip/github-issues-vulnerability-detection",               "format": "alpaca",   "priority": 2},
    {"id": "lynchorange/SARD_Vulnerability_Detection_C",                 "format": "alpaca",   "priority": 2},
    {"id": "crmamede/vulnerability_detection__explainability",           "format": "alpaca",   "priority": 2},

    # ─── Exploit code ─────────────────────────────────────────────────────────
    {"id": "mlfoundations-dev/seed_code_magicoder_exploit",              "format": "alpaca",   "priority": 2},
    {"id": "mlfoundations-dev/stackexchange_reverseengineering",         "format": "alpaca",   "priority": 2},
    {"id": "icantiemyshoe/cve-to-metasploit-module",                     "format": "alpaca",   "priority": 2},

    # ─── Pentesting (aggiuntivi) ──────────────────────────────────────────────
    {"id": "resk-fr/pentesting-for-agents",                              "format": "alpaca",   "priority": 1},
    {"id": "kuladeepmantri/4-Security-Tools-Pentesting",                 "format": "alpaca",   "priority": 2},
    {"id": "boapro/pentesting-dataset",                                  "format": "alpaca",   "priority": 2},
    {"id": "AshishFugare/Pentesting_Dataset",                            "format": "alpaca",   "priority": 2},
    {"id": "infinite-dataset-hub/PenTestingScenarioSimulation",          "format": "alpaca",   "priority": 2},
    {"id": "cpagac/venomx-pentesting-harmful",                           "format": "alpaca",   "priority": 2},

    # ─── Agent skills (security-relevant only) ────────────────────────────────
    # 600K prompt di agente white-hat cybersecurity — molto rilevante per ARGOS
    {"id": "yatin-superintelligence/White-Hat-Security-Agent-Prompts-600K", "format": "alpaca", "priority": 1},
    {"id": "yoonholee/agent-skill-malware",                              "format": "alpaca",   "priority": 1},
]


# ── Converters ─────────────────────────────────────────────────────────────────

def to_alpaca(example: dict) -> dict | None:
    """Try to extract instruction/input/output from various dataset formats."""
    # Standard alpaca
    if "instruction" in example and "output" in example:
        return {
            "instruction": str(example.get("instruction", "")),
            "input":       str(example.get("input", "") or ""),
            "output":      str(example.get("output", "")),
        }
    # Q&A style
    if "question" in example and "answer" in example:
        return {
            "instruction": str(example["question"]),
            "input":       "",
            "output":      str(example["answer"]),
        }
    # Prompt/response
    if "prompt" in example and "response" in example:
        return {
            "instruction": str(example["prompt"]),
            "input":       "",
            "output":      str(example["response"]),
        }
    # ChatML: system + user + assistant
    if "user" in example and "assistant" in example:
        system = str(example.get("system", "") or "")
        instruction = str(example["user"])[:2000]
        output = str(example["assistant"])[:4000]
        if system:
            instruction = f"[System: {system[:500]}]\n\n{instruction}"
        return {"instruction": instruction, "input": "", "output": output}
    # Text/label classification → convert to Q&A
    if "text" in example and "label" in example:
        return {
            "instruction": "Classify this cybersecurity event.",
            "input":       str(example["text"])[:2000],
            "output":      str(example["label"]),
        }
    # ShareGPT
    if "conversations" in example:
        convs = example["conversations"]
        if len(convs) >= 2:
            human = next((c.get("value", "") for c in convs if c.get("from") in ("human", "user")), "")
            assistant = next((c.get("value", "") for c in convs if c.get("from") in ("gpt", "assistant")), "")
            if human and assistant:
                return {"instruction": str(human)[:2000], "input": "", "output": str(assistant)[:4000]}
    # Messages list (OpenAI format)
    if "messages" in example:
        msgs = example["messages"]
        user_msg = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        asst_msg = next((m.get("content", "") for m in msgs if m.get("role") == "assistant"), "")
        if user_msg and asst_msg:
            return {"instruction": str(user_msg)[:2000], "input": "", "output": str(asst_msg)[:4000]}
    return None


def to_network_threat_qa(example: dict, label_col: str = "label") -> dict | None:
    """Convert tabular network traffic dataset to Q&A."""
    label = example.get(label_col, example.get("Label", example.get("attack_type", "")))
    if not label:
        return None
    features = {k: v for k, v in example.items() if k not in (label_col, "Label", "attack_type")}
    feature_str = ", ".join(f"{k}={v}" for k, v in list(features.items())[:20])
    return {
        "instruction": "Classify this network traffic as a threat or benign.",
        "input":       feature_str[:1000],
        "output":      str(label),
    }


# ── Download ───────────────────────────────────────────────────────────────────

def download_one(ds_info: dict, max_size_mb: int, dry_run: bool) -> int:
    """Download a single dataset and convert to JSONL. Returns example count."""
    ds_id = ds_info["id"]
    fmt   = ds_info.get("format", "alpaca")
    name  = ds_id.replace("/", "_")
    out_path = OUTPUT_DIR / f"{name}.jsonl"

    if out_path.exists():
        log.info("SKIP (exists): %s", ds_id)
        return 0

    if dry_run:
        log.info("DRY-RUN: would download %s", ds_id)
        return 0

    try:
        from datasets import load_dataset
    except ImportError:
        log.error("datasets library not installed")
        return 0

    log.info("Downloading: %s ...", ds_id)
    try:
        ds = load_dataset(ds_id, split="train")
    except Exception:
        try:
            ds = load_dataset(ds_id)
            split = list(ds.keys())[0]
            ds = ds[split]
        except Exception as e:
            log.warning("FAILED: %s — %s", ds_id, e)
            return 0

    # Size guard
    approx_mb = len(ds) * 0.002  # very rough: 2KB per example
    if approx_mb > max_size_mb:
        log.warning("SKIP (too large ~%dMB): %s", int(approx_mb), ds_id)
        return 0

    written = 0
    with open(out_path, "w") as f:
        for example in ds:
            if fmt == "tabular":
                converted = to_network_threat_qa(example)
            else:
                converted = to_alpaca(example)

            if converted and converted["output"].strip():
                f.write(json.dumps(converted, ensure_ascii=False) + "\n")
                written += 1

    if written == 0:
        out_path.unlink(missing_ok=True)
        log.warning("NO EXAMPLES converted: %s", ds_id)
    else:
        log.info("OK: %s -> %s (%d examples)", ds_id, out_path.name, written)

    return written


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--max-size-mb", type=int, default=500,
                   help="Skip datasets larger than this (approx)")
    p.add_argument("--priority", type=int, default=2,
                   help="Max priority to download (1=high, 2=all)")
    args = p.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    to_download = [d for d in DATASETS if d.get("priority", 2) <= args.priority]
    log.info("Dataset da scaricare: %d (priority <= %d)", len(to_download), args.priority)

    total = 0
    failed = []
    for i, ds_info in enumerate(to_download, 1):
        log.info("[%d/%d] %s", i, len(to_download), ds_info["id"])
        try:
            n = download_one(ds_info, args.max_size_mb, args.dry_run)
            total += n
        except Exception as e:
            log.error("ERROR on %s: %s", ds_info["id"], e)
            traceback.print_exc()
            failed.append(ds_info["id"])

    log.info("=" * 60)
    log.info("DONE: %d esempi totali da %d dataset", total, len(to_download) - len(failed))
    if failed:
        log.warning("Falliti (%d): %s", len(failed), ", ".join(failed))

    # Merge tutto in un unico file base
    if not args.dry_run:
        merge_all()


def merge_all() -> None:
    """Merge all downloaded JSONL into a single base_dataset.jsonl."""
    files = sorted(OUTPUT_DIR.glob("*.jsonl"))
    base_path = OUTPUT_DIR.parent / "base_dataset.jsonl"
    total = 0
    with open(base_path, "w") as out:
        for f in files:
            with open(f) as inp:
                for line in inp:
                    out.write(line)
                    total += 1
    log.info("Merged %d examples into %s", total, base_path)


if __name__ == "__main__":
    main()
