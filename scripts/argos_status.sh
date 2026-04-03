#!/bin/bash
echo "========== ARGOS DOWNLOAD STATUS =========="
echo ""
echo "=== Sessioni attive ==="
screen -ls

echo ""
echo "=== Dataset scaricati ==="
echo "Foundational (cyber): $(ls /opt/argos/training/datasets/foundational/ 2>/dev/null | wc -l) file"
echo "Code:                 $(ls /opt/argos/training/datasets/code/ 2>/dev/null | wc -l) file"
echo "Agent:                $(ls /opt/argos/training/datasets/agent/ 2>/dev/null | wc -l) file"
echo "Opus:                 $(ls /opt/argos/training/datasets/opus/ 2>/dev/null | wc -l) file"
echo ""
du -sh /opt/argos/training/datasets/*/ 2>/dev/null

echo ""
echo "=== Disk ==="
df -h /

echo ""
echo "=== Download stats ==="
python3 -c "
import json
try:
    s = json.load(open('/opt/argos/training/download_stats.json'))
    print(f'  Done:     {len(s[\"done\"])}')
    print(f'  Failed:   {len(s[\"failed\"])}')
    print(f'  Skipped:  {len(s[\"skipped\"])}')
    print(f'  Examples: {s[\"total_examples\"]:,}')
except: print('  (stats not ready yet)')
" 2>/dev/null

echo ""
echo "=== Ultimi log cybersecurity ==="
grep -v "HTTP Request" /opt/argos/logs/dataset_download.log 2>/dev/null | grep -E "(OK\(|FAIL|SKIP|\[)" | tail -5

echo ""
echo "=== Ultimi log code/agent ==="
grep -v "HTTP Request" /opt/argos/logs/download_code_agents.log 2>/dev/null | grep -E "(OK\(|FAIL|SKIP|PROGRESS|\[)" | tail -5

echo ""
echo "=== Servizi ARGOS ==="
systemctl is-active argos-llama && echo "  llama-server: RUNNING" || echo "  llama-server: STOPPED"
docker ps --format "  {{.Names}}: {{.Status}}" 2>/dev/null
