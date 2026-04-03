"""
ARGOS — Status Dashboard
Serve una dashboard HTML su porta 7070.
Accesso: http://<SERVER_IP>:7070
"""
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

PORT = 7070

DATASETS_DIR  = Path("/opt/argos/training/datasets")
STATS_FILE    = Path("/opt/argos/training/download_stats.json")
CATALOG_FILE  = Path("/opt/argos/scripts/all_datasets_found.json")
GEN_LOG       = Path("/opt/argos/training/gen_professors.log")
CODE_LOG      = Path("/opt/argos/training/dl_code.log")
AGENT_LOG     = Path("/opt/argos/training/dl_agent.log")
OPUS_LOG      = Path("/opt/argos/training/dl_opus.log")
MODELS_DIR    = Path("/opt/argos/models")
PROF_DIR      = Path("/opt/argos/models/professors")

CATALOG_TOTALS = {"code": 2760, "agent": 516, "opus": 600, "cybersecurity": 4}


def sh(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


def read_tail(path: Path, n: int = 8) -> str:
    try:
        lines = path.read_text().splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return "— nessun log —"


def load_stats() -> dict:
    try:
        return json.loads(STATS_FILE.read_text())
    except Exception:
        return {"done": [], "failed": [], "skipped": [], "total_examples": 0}


def count_files(path: Path) -> int:
    try:
        return len(list(path.glob("*.jsonl")))
    except Exception:
        return 0


def dir_size(path: Path) -> str:
    return sh(f"du -sh {path} 2>/dev/null | cut -f1") or "0"


def disk_info() -> dict:
    out = sh("df -h /opt/argos | tail -1")
    parts = out.split()
    if len(parts) >= 5:
        return {"size": parts[1], "used": parts[2], "avail": parts[3], "pct": parts[4]}
    return {"size": "?", "used": "?", "avail": "?", "pct": "?"}


def screen_sessions() -> list[str]:
    out = sh("screen -ls")
    sessions = []
    for line in out.splitlines():
        line = line.strip()
        if "." in line and ("Detached" in line or "Attached" in line):
            name = line.split(".")[1].split("\t")[0]
            state = "Attivo" if "Detached" in line or "Attached" in line else "Fermo"
            sessions.append((name, state))
    return sessions


def llama_status() -> tuple[str, str]:
    active = sh("systemctl is-active argos-llama")
    model  = sh("readlink -f /opt/argos/models/argos-current.gguf")
    model  = Path(model).name if model else "unknown"
    return active, model


def gen_last_activity() -> str:
    try:
        lines = GEN_LOG.read_text().splitlines()
        for line in reversed(lines):
            if "esempi" in line or "Avvio" in line or "DONE" in line or "Round" in line:
                return line.strip()
        return lines[-1].strip() if lines else "—"
    except Exception:
        return "—"


def download_progress() -> dict:
    """Returns per-category: saved (on disk), total (catalog), pending."""
    result = {}
    mapping = {
        "code":          ("code",          DATASETS_DIR / "code"),
        "agent":         ("agent",         DATASETS_DIR / "agent"),
        "opus":          ("opus",          DATASETS_DIR / "opus"),
        "cybersecurity": ("cybersecurity", DATASETS_DIR / "foundational"),
    }
    for cat, (key, path) in mapping.items():
        saved = count_files(path)
        total = CATALOG_TOTALS.get(key, 0)
        result[cat] = {"saved": saved, "total": total, "pending": max(0, total - saved)}
    return result


def count_generated_examples() -> int:
    total = 0
    try:
        for f in DATASETS_DIR.glob("foundational/prof_*.jsonl"):
            total += sum(1 for _ in f.open())
    except Exception:
        pass
    return total


def build_html() -> str:
    stats       = load_stats()
    disk        = disk_info()
    llama_act, llama_model = llama_status()
    sessions    = screen_sessions()
    gen_last    = gen_last_activity()
    gen_count   = count_generated_examples()

    n_found     = count_files(DATASETS_DIR / "foundational")
    n_code      = count_files(DATASETS_DIR / "code")
    n_agent     = count_files(DATASETS_DIR / "agent")
    n_weekly    = count_files(DATASETS_DIR / "weekly")
    dl_progress = download_progress()

    disk_pct    = int(disk["pct"].replace("%", "")) if "%" in disk["pct"] else 0
    disk_color  = "#e74c3c" if disk_pct > 85 else "#f39c12" if disk_pct > 70 else "#27ae60"

    llama_color = "#27ae60" if llama_act == "active" else "#e74c3c"

    now = datetime.now(ZoneInfo("Europe/Rome")).strftime("%d/%m/%Y %H:%M:%S")

    sessions_html = ""
    for name, state in sessions:
        color = "#27ae60" if state == "Attivo" else "#e74c3c"
        sessions_html += f'<div class="session"><span class="dot" style="background:{color}"></span>{name}</div>'

    professors_html = ""
    try:
        for f in sorted(PROF_DIR.glob("*.gguf")):
            size = f.stat().st_size / 1e9
            professors_html += f'<tr><td>{f.name}</td><td>{size:.1f} GB</td></tr>'
    except Exception:
        professors_html = '<tr><td colspan="2">—</td></tr>'

    log_gen   = read_tail(GEN_LOG, 6)
    log_code  = read_tail(CODE_LOG, 4)
    log_agent = read_tail(AGENT_LOG, 4)

    return f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>ARGOS — Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; font-size: 14px; }}
  header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ font-size: 18px; font-weight: 600; color: #f0f6fc; letter-spacing: 0.5px; }}
  header .timestamp {{ font-size: 12px; color: #8b949e; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; padding: 24px 32px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
  .card h2 {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-bottom: 16px; }}
  .stat {{ display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #21262d; }}
  .stat:last-child {{ border-bottom: none; }}
  .stat-label {{ color: #8b949e; }}
  .stat-value {{ font-weight: 600; color: #f0f6fc; font-variant-numeric: tabular-nums; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-green {{ background: #1a3a2a; color: #3fb950; border: 1px solid #2ea043; }}
  .badge-red {{ background: #3a1a1a; color: #f85149; border: 1px solid #da3633; }}
  .badge-yellow {{ background: #3a2a00; color: #d29922; border: 1px solid #9e6a03; }}
  .progress-bar {{ background: #21262d; border-radius: 4px; height: 6px; margin-top: 6px; }}
  .progress-fill {{ height: 6px; border-radius: 4px; }}
  .sessions {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .session {{ display: flex; align-items: center; gap: 6px; background: #21262d; border-radius: 4px; padding: 4px 10px; font-size: 12px; }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
  .log {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px; padding: 12px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 11px; color: #8b949e; white-space: pre-wrap; word-break: break-all; line-height: 1.6; margin-top: 8px; max-height: 140px; overflow-y: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 6px 0; border-bottom: 1px solid #21262d; color: #8b949e; font-size: 12px; }}
  td:last-child {{ text-align: right; color: #f0f6fc; font-weight: 500; }}
  tr:last-child td {{ border-bottom: none; }}
  .model-name {{ font-family: monospace; font-size: 12px; color: #79c0ff; }}
  .footer {{ text-align: center; padding: 16px; color: #484f58; font-size: 11px; border-top: 1px solid #21262d; }}
  .big-number {{ font-size: 28px; font-weight: 700; color: #f0f6fc; }}
  .big-label {{ font-size: 11px; color: #8b949e; margin-top: 2px; }}
  .numbers-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 8px; }}
  .number-box {{ background: #21262d; border-radius: 6px; padding: 12px; text-align: center; }}
</style>
</head>
<body>
<header>
  <h1>ARGOS — Training Dashboard</h1>
  <span class="timestamp">Aggiornamento automatico ogni 30s &nbsp;|&nbsp; {now}</span>
</header>

<div class="grid">

  <!-- Modello Attivo -->
  <div class="card">
    <h2>Modello Attivo</h2>
    <div class="stat">
      <span class="stat-label">Servizio llama.cpp</span>
      <span class="badge {'badge-green' if llama_act == 'active' else 'badge-red'}">{llama_act.upper()}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Modello</span>
      <span class="model-name">{llama_model[:40]}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Porta</span>
      <span class="stat-value">8080</span>
    </div>
    <div class="stat">
      <span class="stat-label">Server</span>
      <span class="stat-value"><SERVER_IP></span>
    </div>
  </div>

  <!-- Disco -->
  <div class="card">
    <h2>Disco</h2>
    <div class="stat">
      <span class="stat-label">Usato</span>
      <span class="stat-value">{disk['used']} / {disk['size']}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Disponibile</span>
      <span class="stat-value" style="color:{disk_color}">{disk['avail']}</span>
    </div>
    <div style="margin-top:12px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:11px;color:#8b949e">Utilizzo disco</span>
        <span style="font-size:11px;color:{disk_color}">{disk['pct']}</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="width:{disk_pct}%;background:{disk_color}"></div>
      </div>
    </div>
    <div class="stat" style="margin-top:12px">
      <span class="stat-label">Professori</span>
      <span class="stat-value">{dir_size(PROF_DIR)}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Dataset totali</span>
      <span class="stat-value">{dir_size(DATASETS_DIR)}</span>
    </div>
  </div>

  <!-- Download Dataset -->
  <div class="card">
    <h2>Download Dataset HuggingFace</h2>
    {''.join(f"""
    <div style="margin-bottom:14px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:12px;color:#c9d1d9;font-weight:600">{cat}</span>
        <span style="font-size:12px;color:#8b949e">{v['saved']} / {v['total']} &nbsp;<span style="color:#484f58">({v['pending']} mancanti)</span></span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="width:{min(100, round(v['saved']/v['total']*100)) if v['total'] else 0}%;background:{'#27ae60' if v['pending']==0 else '#2ea043'}"></div>
      </div>
    </div>""" for cat, v in dl_progress.items())}
    <div class="stat" style="margin-top:4px">
      <span class="stat-label">Totale mancanti</span>
      <span class="stat-value" style="color:#f39c12">{sum(v['pending'] for v in dl_progress.values())}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Falliti / Skippati</span>
      <span class="stat-value">{len(stats.get('failed', []))} / {len(stats.get('skipped', []))}</span>
    </div>
    <div class="log">{log_code}</div>
  </div>

  <!-- Generazione Professori -->
  <div class="card">
    <h2>Generazione Training Data (Professori)</h2>
    <div class="stat">
      <span class="stat-label">Esempi generati (sessione)</span>
      <span class="stat-value" style="color:#3fb950">{gen_count:,}</span>
    </div>
    <div class="stat">
      <span class="stat-label">Ultima attivita</span>
      <span style="font-size:11px;color:#8b949e;text-align:right;max-width:220px">{gen_last[-80:]}</span>
    </div>
    <div class="log">{log_gen}</div>
  </div>

  <!-- Processi Attivi -->
  <div class="card">
    <h2>Processi Attivi (screen)</h2>
    <div class="sessions">{sessions_html if sessions_html else '<span style="color:#484f58">Nessuna sessione attiva</span>'}</div>
  </div>

  <!-- Professori -->
  <div class="card">
    <h2>Modelli Professori ({len(list(PROF_DIR.glob('*.gguf') if PROF_DIR.exists() else []))} disponibili)</h2>
    <table>
      {professors_html}
    </table>
  </div>

</div>

<div class="footer">
  ARGOS Training Dashboard — NRC Company &nbsp;|&nbsp; Auto-refresh 30s
</div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        html = build_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, fmt, *args):
        pass  # silenzia i log HTTP


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Dashboard avviata: http://<SERVER_IP>:{PORT}")
    server.serve_forever()
