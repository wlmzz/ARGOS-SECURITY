from huggingface_hub import list_datasets

terms = [
    "security agent tool use",
    "cybersecurity agent",
    "agent tool calling security",
    "agentic security",
]
seen = set()
results = []
for term in terms:
    for d in list_datasets(search=term, limit=30):
        if d.id not in seen:
            seen.add(d.id)
            dl = getattr(d, "downloads", 0) or 0
            results.append({"id": d.id, "dl": dl, "term": term})

results.sort(key=lambda x: x["dl"], reverse=True)
print(f"Trovati: {len(results)}")
for r in results[:30]:
    print(str(r["dl"]).rjust(6) + "  " + r["id"] + "  [" + r["term"] + "]")
