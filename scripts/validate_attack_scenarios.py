import csv
from pathlib import Path
path = Path("data/scenarios/attack_scenarios.csv")
required = [
    "scenario_id",
    "stage",
    "event_type",
    "source_ip",
    "ioc",
    "severity",
    "next_stage"
]
rows = list(csv.DictReader(path.open(encoding="utf-8")))
errors = []
for i, row in enumerate(rows, start=2):
    for field in required:
        if not row[field].strip():
            errors.append(f"Row {i}: missing {field}")
    event_type = row["event_type"].strip()
    if event_type == "PROCESS_EXECUTION" and not row["process"].strip():
        errors.append(f"Row {i}: PROCESS_EXECUTION requires process")
    if event_type == "NETWORK_CONNECTION" and not row["destination_ip"].strip():
        errors.append(f"Row {i}: NETWORK_CONNECTION requires destination_ip")
    if event_type == "RESOURCE_ACCESS" and not row["resource"].strip():
        errors.append(f"Row {i}: RESOURCE_ACCESS requires resource")
print("=" * 70)
print("NEXUS INTELLIGENCE")
print("MEMBER 3 - ATTACK SCENARIO VALIDATOR")
print("=" * 70)
print(f"Total scenarios/events : {len(rows)}")
print(f"Validation errors      : {len(errors)}")
if errors:
    print("\nSTATUS: REVIEW")
    for error in errors:
        print("[ERROR]", error)
else:
    print("\nSTATUS: PASS")
    print("All scenario records passed validation.")
