#!/bin/bash
TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
DIR=/opt/argos/models/professors
LOG=/opt/argos/models/professors/download.log

download() {
    local name=$1
    local url=$2
    local out=$3
    if [ -f "$DIR/$out" ]; then
        echo "[$(date +%H:%M)] SKIP (già presente): $out" | tee -a $LOG
        return
    fi
    echo "[$(date +%H:%M)] Scarico: $name → $out" | tee -a $LOG
    wget --header="Authorization: Bearer $TOKEN"          --continue --quiet --show-progress          -O "$DIR/$out" "$url" 2>&1 | tee -a $LOG
    echo "[$(date +%H:%M)] FATTO: $out ($(du -sh $DIR/$out | cut -f1))" | tee -a $LOG
}

echo "=== Download Professori ARGOS - $(date) ===" | tee $LOG

download "cai_cybersecurity_agent"   "https://huggingface.co/Umesh1212/cai_cybersecurity_agent_gguf_fixed/resolve/main/qwen2.5-coder-7b-instruct.Q4_0.gguf"   "cai_cybersecurity_agent.gguf"

download "ELISARCyberAIEdge7B-LoRA"   "https://huggingface.co/sallani/ELISARCyberAIEdge7B-LoRA-GGUF/resolve/main/ELISARCyberAIEdge7B-LoRA.gguf"   "ELISAR_cyber_edge_7b.gguf"

download "Lily-Cybersecurity-7B"   "https://huggingface.co/NiroshanDb23/Lily-Cybersecurity-7B-Uncensored-GGUF/resolve/main/Lily-Uncensored-Q4_K_M.gguf"   "lily_cybersecurity_7b.gguf"

download "GPT-OSS-Cybersecurity-20B-i1"   "https://huggingface.co/mradermacher/GPT-OSS-Cybersecurity-20B-Merged-i1-GGUF/resolve/main/GPT-OSS-Cybersecurity-20B-Merged.i1-Q4_K_S.gguf"   "gpt_oss_cybersecurity_20b.gguf"

download "Pentest_AI"   "https://huggingface.co/risataim/Pentest_AI_gguf/resolve/main/Pentest_AI.gguf"   "pentest_ai.gguf"

download "Pentesting-GPT-v1.0"   "https://huggingface.co/mradermacher/Pentesting-GPT-v1.0-GGUF/resolve/main/Pentesting-GPT-v1.0.Q4_K_S.gguf"   "pentesting_gpt_v1.gguf"

download "security-attacks-MITRE"   "https://huggingface.co/dattaraj/security-attacks-MITRE/resolve/main/security-attacks-MITRE.gguf"   "security_attacks_mitre.gguf"

download "ZySec-SecurityLLM"   "https://huggingface.co/RichardErkhov/ZySec-AI_-_SecurityLLM-gguf/resolve/main/SecurityLLM.Q4_K_S.gguf"   "zysec_security_llm.gguf"

echo "=== COMPLETATO: $(ls $DIR/*.gguf 2>/dev/null | wc -l) modelli scaricati ==="  | tee -a $LOG
