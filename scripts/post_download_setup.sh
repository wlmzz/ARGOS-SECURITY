#!/bin/bash
set -e
MODELS_DIR=/opt/argos/models
GGUF_FILE="$MODELS_DIR/GPT-OSS-Cybersecurity-20B-Merged.Q4_K_S.gguf"
SYMLINK="$MODELS_DIR/argos-current.gguf"

if [ -f "$GGUF_FILE" ]; then
    ln -sf "$GGUF_FILE" "$SYMLINK"
    echo "Symlink created: $SYMLINK -> $GGUF_FILE"
    systemctl enable argos-llama
    systemctl start argos-llama
    echo "argos-llama service started"
else
    echo "Model file not found: $GGUF_FILE"
    exit 1
fi
