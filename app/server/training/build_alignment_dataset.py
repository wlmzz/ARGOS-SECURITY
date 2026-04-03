"""
ARGOS — Build Alignment Dataset
Assembla tutti i file jsonl di alignment in un unico file pronto per il training.
I file di capabilities e refusals vengono oversampleati (ripetuti) per pesare
di più rispetto ai dataset generici durante il fine-tuning.

Usage:
    python build_alignment_dataset.py
    python build_alignment_dataset.py --oversample 5  # ripete ogni esempio 5 volte
    python build_alignment_dataset.py --validate       # solo validazione, non scrive
"""

import json
import argparse
import sys
from pathlib import Path

ALIGNMENT_DIR = Path(__file__).parent / "alignment"
OUTPUT_FILE   = Path(__file__).parent / "alignment_final.jsonl"

# Peso di ogni file (quante volte viene ripetuto nel dataset finale)
# File con peso maggiore influenzano di più il comportamento del modello
FILE_WEIGHTS = {
    "01_identita.jsonl":                        10,  # identità, 10x
    "02_capabilities_PREFILLED.jsonl":           5,  # esempi tecnici, 5x
    "03_refusals_COMPILA_TU.jsonl":             10,  # rifiuti (TUO), 10x
    "04_refusal_style_COMPILA_TU.jsonl":         8,  # stile rifiuto (TUO), 8x
    "05_uncensored_base_DOWNLOADED.jsonl":        1,  # base uncensored, 1x (è già enorme)
}
DEFAULT_WEIGHT = 3


def validate_line(line: str, filename: str, lineno: int) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        print(f"  ERRORE JSON in {filename} riga {lineno}: {e}")
        print(f"  Contenuto: {line[:100]}")
        return None

    if "instruction" not in obj:
        print(f"  ERRORE in {filename} riga {lineno}: manca 'instruction'")
        return None
    if "output" not in obj:
        print(f"  ERRORE in {filename} riga {lineno}: manca 'output'")
        return None
    if not obj.get("output", "").strip():
        print(f"  ATTENZIONE in {filename} riga {lineno}: 'output' è vuoto")
        return None

    # Normalizza
    return {
        "instruction": str(obj["instruction"]).strip(),
        "input":       str(obj.get("input", "")).strip(),
        "output":      str(obj["output"]).strip(),
    }


def load_file(path: Path) -> list[dict]:
    examples = []
    errors = 0
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            result = validate_line(line, path.name, i)
            if result:
                examples.append(result)
            elif line.strip() and not line.strip().startswith("#"):
                errors += 1
    return examples, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oversample", type=int, default=None,
                        help="Override weight per tutti i file")
    parser.add_argument("--validate", action="store_true",
                        help="Solo validazione, non scrive output")
    args = parser.parse_args()

    if not ALIGNMENT_DIR.exists():
        print(f"Cartella alignment non trovata: {ALIGNMENT_DIR}")
        sys.exit(1)

    files = sorted(ALIGNMENT_DIR.glob("*.jsonl"))
    if not files:
        print("Nessun file .jsonl trovato in alignment/")
        sys.exit(1)

    print(f"=== ARGOS Alignment Dataset Builder ===\n")

    all_examples = []
    total_errors = 0

    for path in files:
        examples, errors = load_file(path)
        total_errors += errors

        weight = args.oversample or FILE_WEIGHTS.get(path.name, DEFAULT_WEIGHT)
        repeated = examples * weight

        status = "OK" if examples else "VUOTO"
        print(f"  {path.name}: {len(examples)} esempi x{weight} = {len(repeated)} righe  [{status}]")

        if not examples and "COMPILA_TU" in path.name:
            print(f"    --> DA COMPILARE: apri questo file e aggiungi i tuoi esempi")

        all_examples.extend(repeated)

    print(f"\nTotale esempi nel dataset finale: {len(all_examples)}")
    print(f"Errori di formato trovati: {total_errors}")

    if total_errors > 0:
        print("\nCorreggi gli errori prima di procedere con il training.")
        sys.exit(1)

    if args.validate:
        print("\nValidazione completata (--validate: nessun file scritto).")
        return

    empty_required = [
        f for f in ["03_refusals_COMPILA_TU.jsonl", "04_refusal_style_COMPILA_TU.jsonl"]
        if not any(e for e in all_examples)
    ]

    # Controlla se i file obbligatori sono stati compilati
    for fname in ["03_refusals_COMPILA_TU.jsonl", "04_refusal_style_COMPILA_TU.jsonl"]:
        fpath = ALIGNMENT_DIR / fname
        examples, _ = load_file(fpath)
        if not examples:
            print(f"\nATTENZIONE: {fname} è ancora vuoto.")
            print("Compilalo prima di eseguire il training.")
            ans = input("Vuoi comunque generare il dataset senza di esso? [s/N]: ")
            if ans.lower() != "s":
                sys.exit(0)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nDataset scritto in: {OUTPUT_FILE}")
    print(f"Dimensione: {OUTPUT_FILE.stat().st_size / 1024:.1f} KB")
    print(f"\nProssimo step: usa questo file nel training con peso elevato.")
    print(f"In train_gpu.py imposta: ALIGNMENT_FILE = '{OUTPUT_FILE}'")


if __name__ == "__main__":
    main()
