"""
ARGOS — Mass download: tutti i dataset code + agent + cybersecurity da HuggingFace.
Usa worker paralleli, skip automatico per dataset troppo grandi, resume-safe.

Usage:
    python download_all.py                          # scarica tutto (filtro 300MB)
    python download_all.py --max-size-mb 500        # aumenta limite
    python download_all.py --workers 4              # più worker paralleli
    python download_all.py --dry-run                # mostra solo cosa scaricherebbe
    python download_all.py --categories code agent  # solo certe categorie
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("argos.download_all")

OUTPUT_BASE   = Path(os.getenv("DATASETS_BASE_DIR", "/opt/argos/training/datasets"))
CATALOG_FILE  = Path("/opt/argos/scripts/all_datasets_found.json")
STATS_FILE    = Path("/opt/argos/training/download_stats.json")
_stats_lock   = Lock()


# ── Converters (identici a download_datasets.py) ──────────────────────────────

def to_alpaca(example: dict) -> dict | None:
    if "instruction" in example and "output" in example:
        return {
            "instruction": str(example.get("instruction", "")),
            "input":       str(example.get("input", "") or ""),
            "output":      str(example.get("output", "")),
        }
    if "question" in example and "answer" in example:
        return {"instruction": str(example["question"]), "input": "", "output": str(example["answer"])}
    if "prompt" in example and "response" in example:
        return {"instruction": str(example["prompt"]), "input": "", "output": str(example["response"])}
    if "user" in example and "assistant" in example:
        system = str(example.get("system", "") or "")
        instr  = str(example["user"])[:2000]
        if system:
            instr = f"[System: {system[:300]}]\n\n{instr}"
        return {"instruction": instr, "input": "", "output": str(example["assistant"])[:4000]}
    if "text" in example and "label" in example:
        return {"instruction": "Classify this input.", "input": str(example["text"])[:2000], "output": str(example["label"])}
    if "conversations" in example:
        convs = example["conversations"]
        if len(convs) >= 2:
            human = next((c.get("value", "") for c in convs if c.get("from") in ("human", "user")), "")
            asst  = next((c.get("value", "") for c in convs if c.get("from") in ("gpt", "assistant")), "")
            if human and asst:
                return {"instruction": str(human)[:2000], "input": "", "output": str(asst)[:4000]}
    if "messages" in example:
        msgs    = example["messages"]
        user_m  = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        asst_m  = next((m.get("content", "") for m in msgs if m.get("role") == "assistant"), "")
        if user_m and asst_m:
            return {"instruction": str(user_m)[:2000], "input": "", "output": str(asst_m)[:4000]}
    # Tool/function calling: extract as instruction-following
    if "tools" in example and "conversations" in example:
        convs = example.get("conversations", [])
        human = next((c.get("value", "") for c in convs if c.get("from") in ("human", "user")), "")
        asst  = next((c.get("value", "") for c in convs if c.get("from") in ("gpt", "assistant")), "")
        tools = json.dumps(example.get("tools", []))[:1000]
        if human and asst:
            return {
                "instruction": f"Usa i seguenti tool disponibili:\n{tools}\n\nRichiesta: {human[:1500]}",
                "input": "",
                "output": str(asst)[:4000],
            }
    # Code: src_content + tgt_content or code + docstring
    if "src_content" in example and "tgt_content" in example:
        return {"instruction": str(example["src_content"])[:2000], "input": "", "output": str(example["tgt_content"])[:4000]}
    if "code" in example and "docstring" in example:
        return {"instruction": "Explain this code.", "input": str(example["code"])[:2000], "output": str(example["docstring"])[:2000]}
    if "func_code_string" in example and "func_documentation_string" in example:
        return {"instruction": "Document this function.", "input": str(example["func_code_string"])[:2000], "output": str(example["func_documentation_string"])[:2000]}
    # BigCodeBench style: instruct_prompt + canonical_solution
    if "instruct_prompt" in example and "canonical_solution" in example:
        return {
            "instruction": str(example["instruct_prompt"])[:2000],
            "input":       str(example.get("code_prompt", ""))[:500],
            "output":      str(example["canonical_solution"])[:4000],
        }
    # CodeAlpaca / code instruction style
    if "output" in example and ("instruction" in example or "prompt" in example):
        return {
            "instruction": str(example.get("instruction", example.get("prompt", "")))[:2000],
            "input":       str(example.get("input", example.get("context", "")) or "")[:500],
            "output":      str(example["output"])[:4000],
        }
    # Parallel translation (opus-style): src + trg
    if "translation" in example:
        trans = example["translation"]
        if isinstance(trans, dict) and len(trans) == 2:
            langs = list(trans.keys())
            return {
                "instruction": f"Translate from {langs[0]} to {langs[1]}.",
                "input":       str(trans[langs[0]])[:2000],
                "output":      str(trans[langs[1]])[:2000],
            }
    # Simple text pairs: src + tgt
    if "src" in example and "tgt" in example:
        return {"instruction": "Translate.", "input": str(example["src"])[:2000], "output": str(example["tgt"])[:2000]}
    return None


# ── Stats tracking ─────────────────────────────────────────────────────────────

def load_stats() -> dict:
    if STATS_FILE.exists():
        try:
            return json.loads(STATS_FILE.read_text())
        except Exception:
            pass
    return {"done": [], "failed": [], "skipped": [], "total_examples": 0}


def save_stats(stats: dict) -> None:
    with _stats_lock:
        STATS_FILE.write_text(json.dumps(stats, indent=2))


def update_stats(stats: dict, key: str, ds_id: str, examples: int = 0) -> None:
    with _stats_lock:
        if ds_id not in stats[key]:
            stats[key].append(ds_id)
        stats["total_examples"] += examples
    save_stats(stats)


# ── Single dataset download ────────────────────────────────────────────────────

def download_one(ds_id: str, category: str, max_size_mb: int, dry_run: bool,
                 stats: dict, output_dir: Path) -> str:
    name     = ds_id.replace("/", "_")
    out_path = output_dir / f"{name}.jsonl"

    # Skip if already done
    if out_path.exists() or ds_id in stats.get("done", []):
        return f"SKIP(exists) {ds_id}"

    if dry_run:
        return f"DRY-RUN {ds_id}"

    try:
        from datasets import load_dataset
    except ImportError:
        return f"FAIL(no datasets lib) {ds_id}"

    try:
        try:
            ds = load_dataset(ds_id, split="train")
        except Exception:
            try:
                raw = load_dataset(ds_id)
                split = list(raw.keys())[0]
                ds = raw[split]
            except Exception as e:
                update_stats(stats, "failed", ds_id)
                return f"FAIL {ds_id}: {e}"

        # Size guard
        approx_mb = len(ds) * 0.003
        if approx_mb > max_size_mb:
            update_stats(stats, "skipped", ds_id)
            return f"SKIP(~{int(approx_mb)}MB>{max_size_mb}MB) {ds_id}"

        written = 0
        with open(out_path, "w") as f:
            for example in ds:
                converted = to_alpaca(example)
                if converted and converted.get("output", "").strip():
                    f.write(json.dumps(converted, ensure_ascii=False) + "\n")
                    written += 1

        if written == 0:
            out_path.unlink(missing_ok=True)
            update_stats(stats, "failed", ds_id)
            return f"EMPTY {ds_id}"

        update_stats(stats, "done", ds_id, written)
        return f"OK({written} ex) {ds_id}"

    except Exception as e:
        out_path.unlink(missing_ok=True)
        update_stats(stats, "failed", ds_id)
        return f"FAIL {ds_id}: {str(e)[:100]}"


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="ARGOS mass dataset download")
    p.add_argument("--max-size-mb", type=int, default=300)
    p.add_argument("--workers",     type=int, default=3,
                   help="Parallel download workers")
    p.add_argument("--dry-run",     action="store_true")
    p.add_argument("--categories",  nargs="+", default=["code", "agent", "cybersecurity"],
                   help="Categories to download (code, agent, cybersecurity)")
    p.add_argument("--min-downloads", type=int, default=5,
                   help="Skip datasets with fewer downloads (quality filter)")
    args = p.parse_args()

    # Load catalog
    if not CATALOG_FILE.exists():
        log.error("Catalog not found: %s — run search_all_code_agents.py first", CATALOG_FILE)
        raise SystemExit(1)

    all_datasets = json.loads(CATALOG_FILE.read_text())
    log.info("Catalog: %d total datasets", len(all_datasets))

    # Filter by category and min downloads
    to_download = [
        d for d in all_datasets
        if d.get("cat", "code") in args.categories
        and (d.get("dl", 0) or 0) >= args.min_downloads
    ]
    # Sort by downloads descending (quality first)
    to_download.sort(key=lambda x: x.get("dl", 0) or 0, reverse=True)
    log.info("To download: %d (cat=%s, min_dl=%d)", len(to_download), args.categories, args.min_downloads)

    # Setup output dirs
    output_dirs = {
        "code":          OUTPUT_BASE / "code",
        "agent":         OUTPUT_BASE / "agent",
        "cybersecurity": OUTPUT_BASE / "foundational",
        "opus":          OUTPUT_BASE / "opus",
    }
    for d in output_dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    # Load/init stats
    stats = load_stats()
    already_done = set(stats.get("done", [])) | set(stats.get("skipped", []))
    remaining = [d for d in to_download if d["id"] not in already_done]
    log.info("Remaining after skip: %d datasets", len(remaining))

    if args.dry_run:
        log.info("DRY RUN — first 20:")
        for d in remaining[:20]:
            log.info("  %s (dl=%d)", d["id"], d.get("dl", 0))
        return

    # Download with thread pool
    completed = 0
    total = len(remaining)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {}
        for d in remaining:
            cat = d.get("cat", "code")
            out_dir = output_dirs.get(cat, output_dirs["code"])
            fut = executor.submit(
                download_one,
                d["id"], cat, args.max_size_mb, args.dry_run, stats, out_dir
            )
            futures[fut] = d["id"]

        for fut in as_completed(futures):
            completed += 1
            result = fut.result()
            status = result.split()[0]
            if "OK" in status:
                log.info("[%d/%d] %s", completed, total, result)
            elif "FAIL" in status or "EMPTY" in status:
                log.warning("[%d/%d] %s", completed, total, result)
            else:
                log.debug("[%d/%d] %s", completed, total, result)

            # Progress every 50
            if completed % 50 == 0:
                s = load_stats()
                log.info(
                    "=== PROGRESS: %d/%d | done=%d, failed=%d, skipped=%d, examples=%d ===",
                    completed, total, len(s["done"]), len(s["failed"]), len(s["skipped"]), s["total_examples"]
                )

    # Final merge
    log.info("Merging all JSONL files into base_dataset.jsonl...")
    merge_all(OUTPUT_BASE)

    s = load_stats()
    log.info("=" * 60)
    log.info("FINAL: done=%d, failed=%d, skipped=%d, total_examples=%d",
             len(s["done"]), len(s["failed"]), len(s["skipped"]), s["total_examples"])


def merge_all(base_dir: Path) -> None:
    """Merge all JSONL files from all subdirs into one base_dataset.jsonl."""
    out_path = base_dir / "base_dataset.jsonl"
    total = 0
    with open(out_path, "w") as out:
        for subdir in ["foundational", "code", "agent"]:
            d = base_dir / subdir
            if not d.exists():
                continue
            for f in sorted(d.glob("*.jsonl")):
                try:
                    with open(f) as inp:
                        for line in inp:
                            out.write(line)
                            total += 1
                except Exception:
                    pass
    log.info("Merged %d examples → %s", total, out_path)


if __name__ == "__main__":
    main()
