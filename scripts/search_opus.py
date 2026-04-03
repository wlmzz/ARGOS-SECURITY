from huggingface_hub import list_datasets
import json

results = []
seen = set()
for d in list_datasets(search="opus", limit=700):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "opus"})

results.sort(key=lambda x: x["dl"], reverse=True)
print(f"Trovati: {len(results)}")
print("\nTop 30:")
for r in results[:30]:
    print(f"  {r['dl']:8d}  {r['id']}")
print(f"\nEsempi per categoria nome:")
for r in results[:5]:
    print(f"  {r['id']}")
