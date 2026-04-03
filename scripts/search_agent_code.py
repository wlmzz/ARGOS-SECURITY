from huggingface_hub import list_datasets
import json

# Cerca con tag "agent" + keyword "code"
seen = set()
results = []
for d in list_datasets(filter="agent", search="code", limit=100):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "agent"})

results.sort(key=lambda x: x["dl"], reverse=True)
print(f"Trovati: {len(results)}")
for r in results[:20]:
    print(f"  {r['dl']:8d}  {r['id']}")

# Aggiorna il catalogo esistente
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

print(f"\nAggiunti al catalogo: {new_added} nuovi dataset")
print(f"Totale catalogo: {len(catalog)}")
