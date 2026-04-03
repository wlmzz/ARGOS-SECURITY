"""
ARGOS — QLoRA fine-tuning script
CPU-only training using PEFT + TRL + HuggingFace Transformers.

Usage:
    python train_argos.py --dataset /opt/argos/training/datasets/weekly/dataset.jsonl
    python train_argos.py --dataset /opt/argos/training/datasets/weekly/dataset.jsonl --merge-gguf
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.train")

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_MODEL_ID = os.getenv(
    "ARGOS_BASE_MODEL", "sainikhiljuluri2015/GPT-OSS-Cybersecurity-20B-Merged"
)
MODELS_DIR      = Path(os.getenv("ARGOS_MODELS_DIR", "/opt/argos/models"))
ADAPTERS_DIR    = Path(os.getenv("ARGOS_ADAPTERS_DIR", "/opt/argos/training/adapters"))
LLAMA_CPP_DIR   = Path(os.getenv("LLAMA_CPP_DIR", "/opt/llama.cpp"))
TELEGRAM_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT   = os.getenv("TELEGRAM_CHAT_ID", "")

LORA_R          = int(os.getenv("LORA_R", "16"))
LORA_ALPHA      = int(os.getenv("LORA_ALPHA", "32"))
EPOCHS          = int(os.getenv("TRAIN_EPOCHS", "3"))
BATCH_SIZE      = int(os.getenv("TRAIN_BATCH_SIZE", "1"))
GRAD_ACCUM      = int(os.getenv("TRAIN_GRAD_ACCUM", "8"))
LEARNING_RATE   = float(os.getenv("TRAIN_LR", "2e-4"))
MAX_SEQ_LEN     = int(os.getenv("TRAIN_MAX_SEQ_LEN", "2048"))
MIN_EXAMPLES    = int(os.getenv("MIN_TRAINING_EXAMPLES", "50"))


# ── Telegram ───────────────────────────────────────────────────────────────────

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


# ── Dataset ────────────────────────────────────────────────────────────────────

def load_dataset_file(path: Path) -> list[dict]:
    examples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    log.info("Loaded %d examples from %s", len(examples), path)
    return examples


def format_alpaca(example: dict) -> str:
    """Convert Alpaca-style dict to training text."""
    instruction = example.get("instruction", "Analyze this cybersecurity threat.")
    inp = example.get("input", example.get("prompt", ""))
    output = example.get("output", example.get("response", ""))
    if inp:
        return (
            f"### Instruction:\n{instruction}\n\n"
            f"### Input:\n{inp}\n\n"
            f"### Response:\n{output}"
        )
    return (
        f"### Instruction:\n{instruction}\n\n"
        f"### Response:\n{output}"
    )


# ── Training ───────────────────────────────────────────────────────────────────

def run_training(dataset_path: Path, output_dir: Path) -> None:
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            TrainingArguments,
        )
        from trl import SFTTrainer
    except ImportError as e:
        log.error("Missing dependency: %s. Run: pip install transformers peft trl datasets bitsandbytes", e)
        raise

    log.info("Loading dataset...")
    raw_examples = load_dataset_file(dataset_path)
    if len(raw_examples) < MIN_EXAMPLES:
        log.warning("Only %d examples (min %d) — skipping training.", len(raw_examples), MIN_EXAMPLES)
        return

    formatted = [{"text": format_alpaca(ex)} for ex in raw_examples]
    dataset = Dataset.from_list(formatted)
    log.info("Dataset ready: %d examples", len(dataset))

    log.info("Loading base model: %s", BASE_MODEL_ID)
    telegram(f"🔄 *ARGOS Training avviato*\n• Modello: `{BASE_MODEL_ID}`\n• Dataset: {len(raw_examples)} esempi\n• Output: `{output_dir}`")

    # 4-bit quantization config (uses CPU with bitsandbytes>=0.44)
    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float32,
        bnb_4bit_use_double_quant=True,
    )

    try:
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            quantization_config=quant_config,
            device_map="cpu",
            trust_remote_code=True,
            cache_dir="/opt/argos/models/hf_cache",
        )
    except Exception:
        # Fallback: load in float16 without quantization
        log.warning("4-bit loading failed, trying float16...")
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            torch_dtype=torch.float16,
            device_map="cpu",
            trust_remote_code=True,
            cache_dir="/opt/argos/models/hf_cache",
        )

    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID,
        trust_remote_code=True,
        cache_dir="/opt/argos/models/hf_cache",
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    output_dir.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LEARNING_RATE,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        fp16=False,
        bf16=False,
        logging_steps=10,
        save_strategy="epoch",
        save_total_limit=2,
        report_to="none",
        dataloader_num_workers=0,
        no_cuda=True,
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        args=training_args,
        max_seq_length=MAX_SEQ_LEN,
    )

    log.info("Starting LoRA training (%d epochs)...", EPOCHS)
    trainer.train()

    log.info("Saving adapter to %s", output_dir)
    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    log.info("Training complete!")


# ── GGUF conversion ────────────────────────────────────────────────────────────

def convert_to_gguf(adapter_dir: Path, version: int) -> Path | None:
    """Merge LoRA adapter and convert to GGUF using llama.cpp tools."""
    merged_dir = adapter_dir / "merged"
    gguf_path = MODELS_DIR / f"argos-custom-v{version}.gguf"

    log.info("Merging LoRA adapter with base model...")
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        base = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            torch_dtype=torch.float16,
            device_map="cpu",
            trust_remote_code=True,
            cache_dir="/opt/argos/models/hf_cache",
        )
        tokenizer = AutoTokenizer.from_pretrained(
            BASE_MODEL_ID,
            trust_remote_code=True,
            cache_dir="/opt/argos/models/hf_cache",
        )
        model = PeftModel.from_pretrained(base, str(adapter_dir))
        model = model.merge_and_unload()
        merged_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(merged_dir), safe_serialization=True)
        tokenizer.save_pretrained(str(merged_dir))
        log.info("Merged model saved to %s", merged_dir)
    except Exception as e:
        log.error("Merge failed: %s", e)
        return None

    # Convert to GGUF with llama.cpp
    convert_script = LLAMA_CPP_DIR / "convert_hf_to_gguf.py"
    if not convert_script.exists():
        log.error("convert_hf_to_gguf.py not found at %s", convert_script)
        return None

    log.info("Converting to GGUF...")
    result = subprocess.run(
        [
            "python", str(convert_script),
            str(merged_dir),
            "--outfile", str(gguf_path),
            "--outtype", "q4_k_s",
        ],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error("GGUF conversion failed: %s", result.stderr)
        return None

    log.info("GGUF saved to %s", gguf_path)
    return gguf_path


# ── Llama.cpp service reload ───────────────────────────────────────────────────

def reload_llama_server(gguf_path: Path) -> None:
    """Update symlink to new model and reload systemd service."""
    symlink = MODELS_DIR / "argos-current.gguf"
    if symlink.is_symlink():
        symlink.unlink()
    symlink.symlink_to(gguf_path)
    log.info("Updated symlink: %s -> %s", symlink, gguf_path)

    result = subprocess.run(
        ["systemctl", "restart", "argos-llama"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("argos-llama service restarted with new model")
    else:
        log.warning("Failed to restart service: %s", result.stderr)


# ── Main ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ARGOS QLoRA fine-tuning")
    p.add_argument("--dataset", required=True, help="Path to JSONL dataset")
    p.add_argument("--merge-gguf", action="store_true",
                   help="Merge adapter and convert to GGUF after training")
    p.add_argument("--version", type=int, default=None,
                   help="Model version number for GGUF output (auto-detected if not set)")
    return p.parse_args()


def next_version() -> int:
    existing = sorted(MODELS_DIR.glob("argos-custom-v*.gguf"))
    if not existing:
        return 1
    last = existing[-1].stem  # argos-custom-v3
    return int(last.split("v")[-1]) + 1


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        log.error("Dataset not found: %s", dataset_path)
        raise SystemExit(1)

    version = args.version or next_version()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    adapter_dir = ADAPTERS_DIR / f"run_{timestamp}_v{version}"

    log.info("=" * 60)
    log.info("ARGOS Training — v%d", version)
    log.info("Dataset:  %s", dataset_path)
    log.info("Adapter:  %s", adapter_dir)
    log.info("=" * 60)

    try:
        run_training(dataset_path, adapter_dir)
    except Exception as e:
        log.error("Training failed: %s", e)
        telegram(f"❌ *ARGOS Training FALLITO* v{version}\nErrore: `{e}`")
        raise SystemExit(1)

    if args.merge_gguf:
        gguf_path = convert_to_gguf(adapter_dir, version)
        if gguf_path:
            reload_llama_server(gguf_path)
            telegram(
                f"✅ *ARGOS v{version} attivo*\n"
                f"• Modello: `{gguf_path.name}`\n"
                f"• Adapter: `{adapter_dir.name}`\n"
                f"• Dataset: {Path(args.dataset).stat().st_size // 1024}KB"
            )
        else:
            telegram(f"⚠️ *ARGOS v{version} addestrato ma conversione GGUF fallita*\nAdapter salvato in `{adapter_dir}`")
    else:
        telegram(
            f"✅ *ARGOS Training v{version} completato*\n"
            f"• Adapter: `{adapter_dir.name}`\n"
            f"Usa `--merge-gguf` per convertire in GGUF."
        )

    log.info("All done.")


if __name__ == "__main__":
    main()
