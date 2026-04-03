#!/bin/bash
# ============================================================
# ARGOS — RunPod Setup Script
# Esegui questo PRIMA di train_gpu.py sul pod RunPod
#
# Usage:
#   bash runpod_setup.sh <IONOS_PASSWORD>
#
# Esempio:
#   bash runpod_setup.sh 'iZmm*a$5@C'
# ============================================================

set -e

IONOS_IP="${IONOS_IP:-<SERVER_IP>}"
IONOS_USER="root"
IONOS_PASS="${1:-}"
DATASETS_DIR="/workspace/datasets"
MERGED_FILE="/workspace/datasets/merged_training.jsonl"

echo "============================================================"
echo " ARGOS RunPod Setup"
echo "============================================================"

# ── 1. Installa dipendenze ──────────────────────────────────────
echo "[1/5] Installazione dipendenze..."
pip install --quiet "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
pip install --quiet \
    transformers \
    peft \
    trl \
    datasets \
    bitsandbytes \
    accelerate \
    xformers \
    sentencepiece \
    huggingface_hub \
    sshpass \
    requests

echo "      Dipendenze OK"

# ── 2. Sync datasets da server IONOS ───────────────────────────
echo "[2/5] Sync datasets da IONOS (<SERVER_IP>)..."
mkdir -p "$DATASETS_DIR"

if [ -z "$IONOS_PASS" ]; then
    echo "      ATTENZIONE: password IONOS non fornita, skip sync"
    echo "      Usa: bash runpod_setup.sh 'TUA_PASSWORD'"
else
    sshpass -p "$IONOS_PASS" rsync -avz --progress \
        "${IONOS_USER}@${IONOS_IP}:/opt/argos/training/datasets/" \
        "$DATASETS_DIR/" \
        --include="*.jsonl" \
        --exclude="*" \
        2>&1 | tail -5
    echo "      Sync completato"
fi

# ── 3. Conta i file scaricati ───────────────────────────────────
echo "[3/5] File dataset disponibili:"
echo "      foundational: $(ls $DATASETS_DIR/foundational/*.jsonl 2>/dev/null | wc -l) file"
echo "      code:         $(ls $DATASETS_DIR/code/*.jsonl 2>/dev/null | wc -l) file"
echo "      agent:        $(ls $DATASETS_DIR/agent/*.jsonl 2>/dev/null | wc -l) file"
echo "      weekly:       $(ls $DATASETS_DIR/weekly/*.jsonl 2>/dev/null | wc -l) file"

# ── 4. Merge tutti i JSONL in un unico file ─────────────────────
echo "[4/5] Merge di tutti i JSONL in $MERGED_FILE..."
rm -f "$MERGED_FILE"
total=0
for subdir in foundational code agent weekly; do
    dir="$DATASETS_DIR/$subdir"
    if [ -d "$dir" ]; then
        for f in "$dir"/*.jsonl; do
            [ -f "$f" ] || continue
            cat "$f" >> "$MERGED_FILE"
            count=$(wc -l < "$f")
            total=$((total + count))
        done
    fi
done
echo "      Totale esempi mergiati: $total"
echo "      File: $MERGED_FILE ($(du -sh $MERGED_FILE 2>/dev/null | cut -f1))"

# ── 5. Verifica GPU ─────────────────────────────────────────────
echo "[5/5] Info GPU:"
python3 -c "
import torch
if torch.cuda.is_available():
    gpu = torch.cuda.get_device_properties(0)
    print(f'      GPU: {gpu.name}')
    print(f'      VRAM: {gpu.total_memory // 1024**3} GB')
    print(f'      CUDA: {torch.version.cuda}')
else:
    print('      ATTENZIONE: nessuna GPU trovata!')
"

echo ""
echo "============================================================"
echo " Setup completato! Ora lancia:"
echo "   python3 train_gpu.py --dataset $MERGED_FILE"
echo ""
echo " Opzioni consigliate:"
echo "   python3 train_gpu.py --dataset $MERGED_FILE --max-examples 500000"
echo "   python3 train_gpu.py --dataset $MERGED_FILE --epochs 2 --batch 4"
echo "============================================================"
