#!/usr/bin/env python3
import os
from huggingface_hub import hf_hub_download

TOKEN = 'hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
DIR   = '/opt/argos/models/professors'
os.makedirs(DIR, exist_ok=True)

PROFESSORS = [
    ('Umesh1212/cai_cybersecurity_agent_gguf_fixed',          'qwen2.5-coder-7b-instruct.Q4_0.gguf'),
    ('sallani/ELISARCyberAIEdge7B-LoRA-GGUF',                 'ELISARCyberAIEdge7B-LoRA.gguf'),
    ('NiroshanDb23/Lily-Cybersecurity-7B-Uncensored-GGUF',    'Lily-Uncensored-Q4_K_M.gguf'),
    ('mradermacher/GPT-OSS-Cybersecurity-20B-Merged-i1-GGUF', 'GPT-OSS-Cybersecurity-20B-Merged.i1-Q4_K_S.gguf'),
    ('risataim/Pentest_AI_gguf',                               'Pentest_AI.gguf'),
    ('mradermacher/Pentesting-GPT-v1.0-GGUF',                 'Pentesting-GPT-v1.0.Q4_K_S.gguf'),
    ('dattaraj/security-attacks-MITRE',                        'security-attacks-MITRE.gguf'),
    ('RichardErkhov/ZySec-AI_-_SecurityLLM-gguf',             'SecurityLLM.Q4_K_S.gguf'),
]

for repo_id, filename in PROFESSORS:
    dest = os.path.join(DIR, filename)
    if os.path.exists(dest) and os.path.getsize(dest) > 1_000_000:
        print(f'SKIP (già presente): {filename}')
        continue
    print(f'Scarico: {repo_id}/{filename}')
    try:
        path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            local_dir=DIR,
            token=TOKEN,
        )
        size_gb = os.path.getsize(path) / 1e9
        print(f'OK: {filename} ({size_gb:.1f} GB)')
    except Exception as e:
        print(f'ERRORE {filename}: {e}')

print('Tutti i professori scaricati.')
