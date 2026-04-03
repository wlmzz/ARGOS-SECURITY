from huggingface_hub import list_datasets

# Cerca con tag "agent"
results = []
seen = set()
for d in list_datasets(filter="agent", limit=200):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        # Filtra per keyword security/cyber rilevante
        name_lower = d.id.lower()
        relevant_keywords = ["security", "cyber", "hack", "pentest", "malware", "exploit", "vuln", "threat", "attack", "ctf", "agent_skill", "tool_call", "function_call", "tool_use"]
        if any(k in name_lower for k in relevant_keywords):
            results.append({"id": d.id, "dl": dl})

# Anche cerca genericamente tool use agents (utili per ARGOS action calling)
for d in list_datasets(search="tool use agent cybersecurity", limit=50):
    if d.id not in seen:
        seen.add(d.id)
        dl = getattr(d, "downloads", 0) or 0
        results.append({"id": d.id, "dl": dl})

results.sort(key=lambda x: x["dl"], reverse=True)
print(f"Security-relevant agent datasets: {len(results)}")
for r in results[:25]:
    print(str(r["dl"]).rjust(6) + "  " + r["id"])
