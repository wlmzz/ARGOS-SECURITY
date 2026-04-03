from huggingface_hub import list_datasets

terms = ["cybersecurity", "malware", "intrusion detection", "network attack", "cve", "threat intel", "MITRE", "pentest", "CTF", "security incidents"]
seen = set()
all_datasets = []
for term in terms:
    for d in list_datasets(search=term, limit=50):
        if d.id not in seen:
            seen.add(d.id)
            dl = getattr(d, "downloads", 0) or 0
            all_datasets.append({"id": d.id, "downloads": dl})

all_datasets.sort(key=lambda x: x["downloads"], reverse=True)
print("Totale unici:", len(all_datasets))
for d in all_datasets[:80]:
    print(str(d["downloads"]).rjust(7) + "  " + d["id"])
