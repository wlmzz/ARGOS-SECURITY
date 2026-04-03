from huggingface_hub import list_datasets

seen = set()
results = []

# Cerca tutti i coding datasets con tag "code"
print("Searching code datasets...")
for d in list_datasets(filter="code", limit=3000):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "code"})

print(f"Code datasets: {len(results)}")

# Cerca tutti gli agent datasets con tag "agent"
print("Searching agent datasets...")
agent_count = 0
for d in list_datasets(filter="agent", limit=1000):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl, "cat": "agent"})
        agent_count += 1

print(f"Agent datasets: {agent_count}")
print(f"Totale unici: {len(results)}")

# Salva tutto
import json
with open("/opt/argos/scripts/all_datasets_found.json", "w") as f:
    json.dump(sorted(results, key=lambda x: x["dl"], reverse=True), f, indent=2)

print("Saved to /opt/argos/scripts/all_datasets_found.json")

# Top 30 per categoria
results_sorted = sorted(results, key=lambda x: x["dl"], reverse=True)
print("\nTop 50 per downloads:")
for r in results_sorted[:50]:
    print(f"  {r['dl']:8d}  [{r['cat']:6s}]  {r['id']}")
