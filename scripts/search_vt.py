from huggingface_hub import list_datasets
import json

results = []
seen = set()
for d in list_datasets(search="virustotal", limit=50):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "cybersecurity"})

results.sort(key=lambda x: x["dl"], reverse=True)
print(f"Trovati: {len(results)}")
for r in results:
    print(f"  {r['dl']:6d}  {r['id']}")

# Aggiorna catalogo
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
print(f"\nAggiunti al catalogo: {new_added}, Totale: {len(catalog)}")
