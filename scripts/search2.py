from huggingface_hub import list_datasets

categories = {
    "pentesting": 50,
    "malware analysis": 50,
    "exploit code": 30,
    "reverse engineering": 30,
    "vulnerability detection": 30,
    "security vulnerabilities code": 30,
}

seen = set([
    "clydeiii/cybersecurity", "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0",
    "Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset",
    "Canstralian/pentesting_dataset", "preemware/pentesting-eval",
    "unileon-robotics/malware-samples", "PatoFlamejanteTV/MalwareSource",
    "53845714nF/malware_family_opcodes", "rr4433/Powershell_Malware_Detection_Dataset",
    "PurCL/malware-top-100", "naorm/malware-text-db",
])

results = []
for term, limit in categories.items():
    for d in list_datasets(search=term, limit=limit):
        if d.id not in seen:
            seen.add(d.id)
            dl = getattr(d, "downloads", 0) or 0
            results.append(d.id + "  dl=" + str(dl) + "  [" + term + "]")

results.sort()
print("Nuovi:", len(results))
for r in results:
    print(" ", r)
