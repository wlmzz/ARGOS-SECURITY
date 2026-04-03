# Training Guide

This guide explains how to train and fine-tune the ARGOS AI model — both using public datasets to bootstrap a capable model from scratch, and using your own incident data to continuously improve it over time.

---

## Table of Contents

- [Overview](#overview)
- [How the AI Learns](#how-the-ai-learns)
- [Bootstrapping with Public Datasets](#bootstrapping-with-public-datasets)
- [Continuous Learning from Incidents](#continuous-learning-from-incidents)
- [Manual Fine-Tuning](#manual-fine-tuning)
- [Evaluating Model Quality](#evaluating-model-quality)
- [Baseline Learning](#baseline-learning)
- [Reducing False Positives](#reducing-false-positives)
- [Contributing Training Data](#contributing-training-data)
- [Hardware Requirements](#hardware-requirements)

---

## Overview

ARGOS uses a two-stage AI approach:

**Stage 1 — Base model (Phi-4 14B):** A general-purpose language model that already understands cybersecurity concepts from its pretraining. It can reason about threats out of the box, but it has no knowledge of your specific environment.

**Stage 2 — Fine-tuned adapter (LoRA):** A lightweight adapter trained on cybersecurity-specific incident data that improves the model's accuracy on threat classification and response decisions.

The fine-tuning process:
- Takes 2–6 hours on a modern CPU server (faster with GPU)
- Does not modify the base model — changes are isolated to the LoRA adapter
- Runs automatically when enough new training data accumulates
- Can be triggered manually at any time

---

## How the AI Learns

Every threat event that passes through ARGOS contributes to training data in one of three ways:

### 1. Human Decisions

When you approve or reject a decision via the mobile app or dashboard, that decision becomes a training example. These are the highest-quality examples because they represent ground truth.

```
Event: port scan from 185.220.101.47
AI suggested: deploy_honeypot (confidence: 0.72)
You decided: block_ip (the IP is a known Tor exit node you've seen before)
→ Training example saved: "correct action = block_ip"
```

### 2. Claude API Escalations

When the local model has low confidence, it escalates to Claude API. Claude's decision becomes a training example.

```
Event: unusual outbound traffic pattern (first time seen)
Local model: confidence 0.31 → escalates
Claude decides: alert_human (potential exfiltration, needs investigation)
→ Training example saved with Claude's reasoning
```

### 3. High-Confidence Local Decisions

When the local model is very confident (>0.9) and the action is taken, the event is saved as a training example to reinforce correct behavior.

```
Event: brute force SSH from 45.33.32.156
Local model: block_ip, confidence 0.97
Action taken: block_ip
→ Training example saved (reinforcement)
```

---

## Bootstrapping with Public Datasets

Before you have your own incident data, you can train on public cybersecurity datasets. This gives the model a strong foundation for threat classification.

### Recommended Datasets

| Dataset | Size | Contents | Use |
|---------|------|----------|-----|
| CIC-IDS-2018 | 16 GB | Network traffic with labeled attacks | Network threat classification |
| UNSW-NB15 | 2.5 GB | Network intrusion data | Intrusion detection |
| CICIDS 2017 | 50 GB | Realistic network traffic | Comprehensive threat coverage |
| EMBER | 1.1 GB | Malware PE features | Malware classification |
| PhishTank | Variable | Phishing URLs | URL-based threat detection |

### Download and Prepare CIC-IDS-2018

```bash
cd server/training/

# Download (requires registration at unb.ca)
wget https://www.unb.ca/cic/datasets/ids-2018.html
# Follow instructions to access the dataset

# Or use the Kaggle mirror
pip install kaggle
kaggle datasets download -d solarmainframe/ids-intrusion-csv

# Prepare the dataset for ARGOS format
python scripts/prepare_cicids.py \
  --input ./raw/CICIDS2018/ \
  --output ./prepared/cicids2018.jsonl
```

### Conversion Script

The `prepare_cicids.py` script converts CSV rows into ARGOS training format:

```python
# Input (CIC-IDS CSV row):
# "192.168.1.1","185.220.101.47","22","54821","TCP",
# 0.5,1024,0,0,"PortScan"

# Output (ARGOS training example):
{
  "instruction": "Analyze the cybersecurity threat and return a JSON decision.",
  "input": "Threat Type: port_scan\nSeverity: high\nSource IP: 185.220.101.47\n...",
  "output": "{\"action\": \"deploy_honeypot\", \"confidence\": 0.95, ...}",
  "source": "cicids2018"
}
```

### Run Initial Training

```bash
# Prepare combined dataset from all sources
python scripts/prepare_dataset.py \
  --sources cicids2018 unsw_nb15 custom \
  --output ./training_data/bootstrap.jsonl \
  --shuffle \
  --split 0.9  # 90% train, 10% validation

# Run fine-tuning
python training/pipeline.py --dataset ./training_data/bootstrap.jsonl

# This takes 2-8 hours depending on hardware
# Output: ./argos_finetuned/ (LoRA adapter files)
```

### Load the Fine-Tuned Adapter

After training, register the adapter with Ollama:

```bash
# Create a Modelfile that loads Phi-4 with your LoRA adapter
cat > Modelfile << EOF
FROM phi4:14b
ADAPTER ./argos_finetuned/adapter_model.bin
SYSTEM "You are ARGOS, a cybersecurity AI. Analyze threats and return JSON decisions."
EOF

# Register the model
ollama create argos-cyber:v1 -f Modelfile

# Update your server config to use the fine-tuned model
# In .env:
# AI_MODEL=argos-cyber:v1
```

---

## Continuous Learning from Incidents

The automatic training pipeline runs weekly (or when triggered manually) and uses all unprocessed training examples from the database.

### Configuration

In `.env`:

```env
# Minimum examples before triggering training
MIN_TRAINING_EXAMPLES=50

# Training data directory
TRAINING_DIR=/data/training

# Schedule (cron expression) — runs every Sunday at 2 AM
TRAINING_SCHEDULE="0 2 * * 0"
```

### Manual Trigger

```bash
# Via API
curl -X POST https://your-server:8443/api/training/run \
  -H "Authorization: Bearer YOUR_TOKEN"

# Via Docker
docker compose exec server python -c "
import asyncio
from training.pipeline import run_training_pipeline
from db.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        result = await run_training_pipeline(db)
        print(result)

asyncio.run(main())
"
```

### Training Progress

Monitor training progress in the server logs:

```
[TRAINING] Found 127 unused training examples
[TRAINING] Dataset saved: /data/training/argos_training_20260319_020000.jsonl
[TRAINING] Fine-tuning script generated: /data/training/run_finetune.py
[TRAINING] Starting LoRA fine-tuning...
[TRAINING] Epoch 1/3 — loss: 0.847
[TRAINING] Epoch 2/3 — loss: 0.312
[TRAINING] Epoch 3/3 — loss: 0.184
[TRAINING] Validation accuracy: 94.2%
[TRAINING] Deploying new adapter...
[TRAINING] Complete. 127 examples marked as used.
```

---

## Manual Fine-Tuning

For full control over the training process:

### Setup

```bash
# Install training dependencies
pip install unsloth transformers datasets trl peft accelerate bitsandbytes

# GPU recommended but not required
# For CPU-only training, add: --no-gpu flag
```

### Training Script

```python
# train.py — full control fine-tuning

from unsloth import FastLanguageModel
from trl import SFTTrainer
from transformers import TrainingArguments
from datasets import load_dataset
import json

# ─── CONFIG ──────────────────────────────────────────────────────────────────
MODEL_NAME    = "phi4:14b"           # Base model
DATASET_PATH  = "./training_data/combined.jsonl"
OUTPUT_DIR    = "./argos_finetuned"
MAX_SEQ_LEN   = 2048
LORA_RANK     = 16                   # Higher = more parameters = more capable but slower
LORA_ALPHA    = 16
EPOCHS        = 3
BATCH_SIZE    = 2
LEARNING_RATE = 2e-4

# ─── MODEL ───────────────────────────────────────────────────────────────────
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL_NAME,
    max_seq_length=MAX_SEQ_LEN,
    load_in_4bit=True,               # 4-bit quantization — saves ~60% VRAM
    dtype=None,                       # Auto-detect
)

model = FastLanguageModel.get_peft_model(
    model,
    r=LORA_RANK,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_alpha=LORA_ALPHA,
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing="unsloth",  # Saves more VRAM
)

# ─── DATASET ─────────────────────────────────────────────────────────────────
def format_example(example):
    return {
        "text": (
            f"### Instruction:\n{example['instruction']}\n\n"
            f"### Input:\n{example['input']}\n\n"
            f"### Response:\n{example['output']}"
        )
    }

raw = load_dataset("json", data_files=DATASET_PATH, split="train")
dataset = raw.map(format_example)

# ─── TRAINING ────────────────────────────────────────────────────────────────
trainer = SFTTrainer(
    model=model,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LEN,
    tokenizer=tokenizer,
    args=TrainingArguments(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=4,
        num_train_epochs=EPOCHS,
        learning_rate=LEARNING_RATE,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        save_strategy="epoch",
        warmup_ratio=0.1,
        lr_scheduler_type="cosine",
        report_to="none",           # Set to "wandb" if you want experiment tracking
    ),
)

trainer.train()

# ─── SAVE ────────────────────────────────────────────────────────────────────
model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"Training complete. Adapter saved to {OUTPUT_DIR}")
```

Run with:
```bash
python train.py
```

---

## Evaluating Model Quality

After training, evaluate the model before deploying it.

### Automated Evaluation

```bash
python training/evaluate.py \
  --model argos-cyber:v1 \
  --dataset tests/fixtures/evaluation_set.jsonl \
  --output ./eval_results.json
```

The evaluation script measures:
- **Action accuracy** — does the model choose the correct action?
- **Severity accuracy** — does it correctly confirm or deny severity?
- **Escalation precision** — does it correctly identify when to escalate?
- **JSON validity** — does it always return valid JSON?
- **Confidence calibration** — is confidence proportional to accuracy?

### Minimum Thresholds for Deployment

| Metric | Minimum | Target |
|--------|---------|--------|
| Action accuracy | 85% | 95%+ |
| JSON validity | 99% | 100% |
| Escalation precision | 90% | 95%+ |
| Confidence calibration | 0.80 ECE | 0.90+ |

If thresholds are not met, the pipeline does not deploy the new adapter.

### Manual Evaluation

Test the model with known scenarios:

```bash
# Interactive testing
ollama run argos-cyber:v1

# Paste this prompt:
Threat Type: brute_force
Severity: high
Source IP: 45.33.32.156
Description: 47 failed SSH authentication attempts in 28 seconds
Raw data: {"attempts": 47, "window_seconds": 28, "usernames_tried": ["root", "admin", "ubuntu"]}

# Expected output:
{
  "severity_confirmed": true,
  "action": "block_ip",
  "reasoning": "Classic brute force SSH attack — blocking IP immediately to prevent credential compromise.",
  "confidence": 0.97,
  "escalate_to_human": false
}
```

---

## Baseline Learning

One of the most important improvements in development is baseline learning — the ability for the agent to learn what "normal" looks like on your specific network before it starts flagging anomalies.

### Why It Matters

A fresh ARGOS installation will initially generate many false positives because it has no baseline:
- A developer connecting to a staging database at midnight looks like C2 traffic
- A backup job doing high CPU looks like a cryptominer
- An internal scanner looks like a port scan

### Current Workaround

Until baseline learning is implemented, reduce false positives with whitelisting:

```json
{
  "whitelisted_ips": [
    "10.0.1.0/24",
    "192.168.0.0/16"
  ],
  "whitelisted_processes": [
    "restic",
    "rclone",
    "duplicati"
  ],
  "whitelisted_ports": [8080, 8443, 9200]
}
```

Start in `supervised` mode for the first 2–4 weeks. Every false positive you dismiss is a training example that improves the model.

---

## Reducing False Positives

If you are seeing too many false positives:

### Short-Term

1. Switch to `supervised` autonomy — no automatic actions, just alerts
2. Whitelist known-good IPs and processes
3. Increase the port scan threshold:
   ```json
   { "port_scan_threshold": 20, "port_scan_window": 120 }
   ```

### Medium-Term

4. Dismiss false positives via the mobile app — each dismissal trains the model
5. Run manual fine-tuning with your accumulated examples: `POST /api/training/run`

### Long-Term

6. The baseline learning system (planned for v0.3.0) will automatically reduce false positives by learning your environment

---

## Contributing Training Data

You can contribute anonymized training examples to help improve ARGOS for everyone.

### How to Export

```bash
# Export your high-confidence examples as anonymized training data
python scripts/export_training_data.py \
  --min-confidence 0.9 \
  --anonymize \              # Replaces real IPs with synthetic ones
  --output ./export.jsonl
```

The anonymization script:
- Replaces real IP addresses with synthetic ones
- Removes device IDs and internal hostnames
- Preserves threat patterns and context
- Adds noise to timestamps

### How to Submit

1. Fork the repository
2. Add your exported JSONL to `tests/fixtures/community_training/`
3. Submit a pull request with a brief description of the threat types included

We review all contributions before including them in the public dataset.

---

## Hardware Requirements

### Inference (Running the Model)

The minimum hardware to run Phi-4 14B for real-time threat analysis:

| Configuration | Specs | Inference Speed |
|---------------|-------|-----------------|
| CPU only | 16 cores, 32 GB RAM | 2–5 tokens/sec |
| CPU recommended | 32 cores, 64 GB RAM | 5–15 tokens/sec |
| GPU (consumer) | RTX 4090, 24 GB VRAM | 30–60 tokens/sec |
| GPU (enterprise) | A100 80 GB | 100+ tokens/sec |

For a threat event, ARGOS typically generates 50–150 tokens. At 5 tokens/sec, this is 10–30 seconds per event — acceptable for non-real-time analysis but too slow for high-volume environments. A GPU speeds this up significantly.

Your reference server (AMD EPYC 7302P, 128 GB RAM) can run Phi-4 14B quantized comfortably at ~8–12 tokens/sec — good for analysis of up to a few events per second.

### Training (Fine-Tuning)

| Configuration | Dataset Size | Training Time |
|---------------|-------------|---------------|
| CPU only (32 cores) | 1,000 examples | 4–8 hours |
| CPU only (32 cores) | 10,000 examples | 40–80 hours |
| GPU (RTX 4090) | 1,000 examples | 20–40 minutes |
| GPU (RTX 4090) | 10,000 examples | 3–6 hours |

LoRA fine-tuning is far more efficient than full fine-tuning. The adapter adds only ~50 MB of parameters to a 8 GB model.

---

*ARGOS Training Guide — v0.1.0*
