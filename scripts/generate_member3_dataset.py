import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "scenarios" / "attack_scenarios.csv"
OUTPUT_FILE = BASE_DIR / "data" / "datasets" / "nexus_attack_dataset.csv"

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with open(INPUT_FILE, "r", encoding="utf-8") as infile:
    reader = csv.DictReader(infile)
    rows = list(reader)

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:
    writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("NEXUS DATASET GENERATED")
print("------------------------")
print(f"Input rows  : {len(rows)}")
print(f"Output file : {OUTPUT_FILE}")