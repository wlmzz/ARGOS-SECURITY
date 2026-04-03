"""
ARGOS — GPU Training con Unsloth (RunPod / Colab / qualsiasi GPU)
3-5x più veloce del training HuggingFace standard.

Usage:
    python train_gpu.py --dataset /workspace/datasets/merged_training.jsonl
    python train_gpu.py --dataset /workspace/datasets/merged_training.jsonl --max-examples 500000
    python train_gpu.py --dataset /workspace/datasets/merged_training.jsonl --merge-gguf --push-to-server

Requisiti:
    pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
    pip install transformers peft trl datasets bitsandbytes accelerate xformers
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import subprocess
from datetime import datetime
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.train_gpu")

# ── Config ──────────────────────────────────────────────────────────────────────
BASE_MODEL_ID   = os.getenv("ARGOS_BASE_MODEL", "sainikhiljuluri2015/GPT-OSS-Cybersecurity-20B-Merged")
ORIGINAL_MODEL  = BASE_MODEL_ID  # usato solo se non esiste ancora un modello locale addestrato
HF_TOKEN        = os.getenv("HF_TOKEN", "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
TELEGRAM_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT   = os.getenv("TELEGRAM_CHAT_ID", "")
IONOS_IP        = os.getenv("IONOS_IP", "")
IONOS_USER      = os.getenv("IONOS_USER", "root")
IONOS_PASS      = os.getenv("IONOS_PASS", "")

OUTPUT_DIR      = Path("/workspace/output")
MODELS_DIR      = Path("/workspace/models")

LORA_R          = int(os.getenv("LORA_R", "64"))        # più alto = più capace
LORA_ALPHA      = int(os.getenv("LORA_ALPHA", "128"))
EPOCHS          = int(os.getenv("TRAIN_EPOCHS", "3"))
BATCH_SIZE      = int(os.getenv("TRAIN_BATCH_SIZE", "4"))
GRAD_ACCUM      = int(os.getenv("TRAIN_GRAD_ACCUM", "4"))
LEARNING_RATE   = float(os.getenv("TRAIN_LR", "2e-4"))
MAX_SEQ_LEN     = int(os.getenv("TRAIN_MAX_SEQ_LEN", "2048"))


# ── Telegram ────────────────────────────────────────────────────────────────────

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


# ── Dataset ─────────────────────────────────────────────────────────────────────

def load_and_format(path: Path, max_examples: int | None = None) -> list[dict]:
    examples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ex = json.loads(line)
                instruction = ex.get("instruction", "")
                inp         = ex.get("input", "")
                output      = ex.get("output", "")
                if not instruction or not output:
                    continue

                if inp:
                    text = (
                        f"### Instruction:\n{instruction}\n\n"
                        f"### Input:\n{inp}\n\n"
                        f"### Response:\n{output}"
                    )
                else:
                    text = (
                        f"### Instruction:\n{instruction}\n\n"
                        f"### Response:\n{output}"
                    )
                examples.append({"text": text})
            except Exception:
                continue

    log.info("Loaded %d valid examples from %s", len(examples), path)

    if max_examples and len(examples) > max_examples:
        log.info("Capping to %d examples (shuffled)", max_examples)
        random.shuffle(examples)
        examples = examples[:max_examples]

    return examples


# ── Training ────────────────────────────────────────────────────────────────────

def run_training(dataset_path: Path, output_dir: Path, max_examples: int | None, epochs: int, batch: int) -> None:
    try:
        from unsloth import FastLanguageModel
        USE_UNSLOTH = True
        log.info("Unsloth disponibile — training ottimizzato")
    except ImportError:
        USE_UNSLOTH = False
        log.warning("Unsloth non trovato — fallback a HuggingFace standard (più lento)")

    import torch
    from datasets import Dataset
    from transformers import TrainingArguments
    from trl import SFTTrainer

    # Usa l'ultimo modello addestrato come base (accumulo progressivo)
    base_model = latest_merged_model()

    # Load dataset
    raw = load_and_format(dataset_path, max_examples)
    if not raw:
        log.error("Dataset vuoto!")
        raise SystemExit(1)

    dataset = Dataset.from_list(raw)
    log.info("Dataset pronto: %d esempi", len(dataset))

    telegram(
        f"🚀 *ARGOS GPU Training avviato*\n"
        f"• Modello: `{BASE_MODEL_ID}`\n"
        f"• Esempi: {len(dataset):,}\n"
        f"• Epoche: {epochs}\n"
        f"• GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}"
    )

    # Load model
    if USE_UNSLOTH:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=base_model,
            max_seq_length=MAX_SEQ_LEN,
            load_in_4bit=True,
            token=HF_TOKEN,
        )
        model = FastLanguageModel.get_peft_model(
            model,
            r=LORA_R,
            lora_alpha=LORA_ALPHA,
            lora_dropout=0,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                            "gate_proj", "up_proj", "down_proj"],
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=42,
        )
    else:
        from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=quant_config,
            device_map="auto",
            token=HF_TOKEN,
        )
        tokenizer = AutoTokenizer.from_pretrained(base_model, token=HF_TOKEN)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = prepare_model_for_kbit_training(model)
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=LORA_R,
            lora_alpha=LORA_ALPHA,
            lora_dropout=0.05,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                            "gate_proj", "up_proj", "down_proj"],
            bias="none",
        )
        model = get_peft_model(model, lora_config)

    model.print_trainable_parameters()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Detect bf16 support
    use_bf16 = torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False
    use_fp16 = not use_bf16 and torch.cuda.is_available()

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LEARNING_RATE,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        fp16=use_fp16,
        bf16=use_bf16,
        logging_steps=50,
        save_strategy="epoch",
        save_total_limit=2,
        report_to="none",
        dataloader_num_workers=4,
        optim="adamw_8bit" if USE_UNSLOTH else "adamw_torch",
        group_by_length=True,
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        args=training_args,
        max_seq_length=MAX_SEQ_LEN,
    )

    log.info("Avvio training (%d epoche, batch=%d, accum=%d)...", epochs, batch, GRAD_ACCUM)
    trainer.train()

    log.info("Salvataggio adapter in %s", output_dir)
    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    log.info("Training completato!")


# ── GGUF Conversion ─────────────────────────────────────────────────────────────

def convert_to_gguf(adapter_dir: Path, version: int) -> Path | None:
    """Merge adapter + converti in GGUF usando llama.cpp."""
    merged_dir = adapter_dir / "merged"
    gguf_path  = MODELS_DIR / f"argos-custom-v{version}.gguf"
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Merge LoRA adapter con base model...")
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        base = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            torch_dtype=torch.float16,
            device_map="auto",
            token=HF_TOKEN,
        )
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, token=HF_TOKEN)
        model = PeftModel.from_pretrained(base, str(adapter_dir))
        model = model.merge_and_unload()
        merged_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(merged_dir), safe_serialization=True)
        tokenizer.save_pretrained(str(merged_dir))
        log.info("Merged model salvato in %s", merged_dir)
    except Exception as e:
        log.error("Merge fallito: %s", e)
        return None

    # Cerca convert_hf_to_gguf.py
    convert_script = None
    for p in [Path("/workspace/llama.cpp/convert_hf_to_gguf.py"),
              Path("/opt/llama.cpp/convert_hf_to_gguf.py")]:
        if p.exists():
            convert_script = p
            break

    if not convert_script:
        log.warning("convert_hf_to_gguf.py non trovato — clono llama.cpp...")
        subprocess.run(
            ["git", "clone", "--depth=1",
             "https://github.com/ggerganov/llama.cpp.git",
             "/workspace/llama.cpp"],
            check=True
        )
        subprocess.run(
            ["pip", "install", "-r", "/workspace/llama.cpp/requirements.txt", "-q"],
            check=True
        )
        convert_script = Path("/workspace/llama.cpp/convert_hf_to_gguf.py")

    log.info("Conversione GGUF Q4_K_S...")
    result = subprocess.run(
        ["python3", str(convert_script),
         str(merged_dir),
         "--outfile", str(gguf_path),
         "--outtype", "q4_k_s"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error("GGUF conversion fallita: %s", result.stderr[-500:])
        return None

    log.info("GGUF salvato: %s (%.1f GB)", gguf_path, gguf_path.stat().st_size / 1e9)
    return gguf_path


# ── Push to IONOS ────────────────────────────────────────────────────────────────

def push_to_server(gguf_path: Path) -> bool:
    """Invia il modello GGUF al server IONOS via rsync."""
    if not IONOS_PASS:
        log.warning("IONOS_PASS non impostato — skip push")
        return False

    log.info("Invio modello al server IONOS...")
    result = subprocess.run(
        ["sshpass", "-p", IONOS_PASS,
         "rsync", "-avz", "--progress",
         str(gguf_path),
         f"{IONOS_USER}@{IONOS_IP}:/opt/argos/models/"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log.info("Modello inviato al server con successo")
        # Aggiorna symlink e riavvia llama.cpp
        cmd = (
            f"ln -sf /opt/argos/models/{gguf_path.name} /opt/argos/models/argos-current.gguf && "
            f"systemctl restart argos-llama"
        )
        subprocess.run(
            ["sshpass", "-p", IONOS_PASS,
             "ssh", f"{IONOS_USER}@{IONOS_IP}", cmd],
            capture_output=True
        )
        log.info("Symlink aggiornato e servizio riavviato")
        return True
    else:
        log.error("Push fallito: %s", result.stderr[:200])
        return False


# ── Main ─────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="ARGOS GPU Training (Unsloth)")
    p.add_argument("--dataset",       required=True, help="Path al JSONL merged")
    p.add_argument("--max-examples",  type=int, default=None,
                   help="Limita esempi (es. 500000 per un run veloce)")
    p.add_argument("--epochs",        type=int, default=EPOCHS)
    p.add_argument("--batch",         type=int, default=BATCH_SIZE)
    p.add_argument("--merge-gguf",    action="store_true",
                   help="Merge adapter e converti in GGUF dopo training")
    p.add_argument("--push-to-server", action="store_true",
                   help="Invia il GGUF al server IONOS dopo conversione")
    p.add_argument("--version",       type=int, default=None)
    return p.parse_args()


def next_version() -> int:
    existing = sorted(MODELS_DIR.glob("argos-custom-v*.gguf"))
    if not existing:
        return 1
    return int(existing[-1].stem.split("v")[-1]) + 1


def latest_merged_model() -> str:
    """
    Ritorna l'ultimo modello merged locale come base per il prossimo training.
    Se non esiste ancora nessun modello addestrato, usa il modello originale HF.
    """
    # Cerca merged HF (directory con config.json)
    merged_dirs = sorted(OUTPUT_DIR.glob("adapter_v*/merged"), reverse=True)
    for d in merged_dirs:
        if (d / "config.json").exists():
            log.info("Base model: ultimo merged locale → %s", d)
            return str(d)

    # Nessun modello locale → usa originale HF
    log.info("Base model: originale HuggingFace → %s", ORIGINAL_MODEL)
    return ORIGINAL_MODEL


def main():
    args    = parse_args()
    dataset = Path(args.dataset)
    if not dataset.exists():
        log.error("Dataset non trovato: %s", dataset)
        raise SystemExit(1)

    version     = args.version or next_version()
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    adapter_dir = OUTPUT_DIR / f"adapter_v{version}_{timestamp}"

    log.info("=" * 60)
    log.info("ARGOS GPU Training — v%d", version)
    log.info("Dataset:      %s", dataset)
    log.info("Max esempi:   %s", args.max_examples or "tutti")
    log.info("Epoche:       %d", args.epochs)
    log.info("Batch size:   %d (accum=%d → effective=%d)", args.batch, GRAD_ACCUM, args.batch * GRAD_ACCUM)
    log.info("Adapter out:  %s", adapter_dir)
    log.info("=" * 60)

    try:
        run_training(dataset, adapter_dir, args.max_examples, args.epochs, args.batch)
    except Exception as e:
        log.error("Training fallito: %s", e)
        telegram(f"❌ *ARGOS GPU Training FALLITO* v{version}\nErrore: `{str(e)[:200]}`")
        raise SystemExit(1)

    if args.merge_gguf:
        gguf_path = convert_to_gguf(adapter_dir, version)
        if gguf_path:
            telegram(
                f"✅ *ARGOS v{version} GGUF pronto*\n"
                f"• File: `{gguf_path.name}`\n"
                f"• Dimensione: {gguf_path.stat().st_size / 1e9:.1f} GB"
            )
            if args.push_to_server:
                ok = push_to_server(gguf_path)
                if ok:
                    telegram(f"🚀 *ARGOS v{version} attivo sul server IONOS!*\nModello aggiornato automaticamente.")
        else:
            telegram(f"⚠️ *ARGOS v{version} addestrato ma GGUF fallito*\nAdapter in `{adapter_dir}`")
    else:
        telegram(
            f"✅ *ARGOS GPU Training v{version} completato*\n"
            f"• Adapter: `{adapter_dir.name}`\n"
            f"Usa `--merge-gguf --push-to-server` per deployare."
        )

    log.info("Tutto fatto.")


if __name__ == "__main__":
    main()
