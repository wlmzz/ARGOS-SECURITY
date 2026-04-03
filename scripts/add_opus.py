from huggingface_hub import list_datasets
import json

results = []
seen = set()
for d in list_datasets(search="opus", limit=700):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "opus"})

catalog_path = "/opt/argos/scripts/all_datasets_found.json"
with open(catalog_path) as f:
    catalog = json.load(f)
existing_ids = {d["id"] for d in catalog}

new_added = 0
for r in results:
    if r["id"] not in existing_ids:
        catalog.append(r)
        new_added += 1

with open(catalog_path, "w") as f:
    json.dump(catalog, f)

print(f"Opus trovati: {len(results)}")
print(f"Nuovi aggiunti: {new_added}")
print(f"Totale catalogo: {len(catalog)}")
# Stima: quanti claude/reasoning opus
claude_opus = [r for r in results if any(k in r["id"].lower() for k in ["claude", "reasoning", "4.5", "4.6", "4-5", "4-6"])]
print(f"Claude/Reasoning opus: {len(claude_opus)}")
helsinki = [r for r in results if "helsinki" in r["id"].lower() or "opus-100" in r["id"].lower()]
print(f"Helsinki-NLP (translation, da skippare): {len(helsinki)}")
