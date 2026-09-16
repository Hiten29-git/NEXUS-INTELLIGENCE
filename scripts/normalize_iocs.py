import csv
from pathlib import Path
from datetime import datetime, timezone
INPUT = Path("data/iocs/ioc_database.csv")
OUTPUT = Path("data/iocs/ioc_database_normalized.csv")
SOURCE = "NEXUS-SYNTHETIC"
confidence_by_severity = {
    "CRITICAL": "0.95",
    "HIGH": "0.90",
    "MEDIUM": "0.80",
    "LOW": "0.70",
}
with INPUT.open("r", encoding="utf-8", newline="") as infile:
    reader = csv.DictReader(infile)
    rows = list(reader)
now = datetime.now(timezone.utc).isoformat()
fields = [
    "ioc_id",
    "type",
    "value",
    "source",
    "confidence",
    "first_seen",
    "last_seen",
    "threat_name",
    "severity",
    "description",
]
with OUTPUT.open("w", encoding="utf-8", newline="") as outfile:
    writer = csv.DictWriter(outfile, fieldnames=fields)
    writer.writeheader()
    for index, row in enumerate(rows, start=1):
        severity = row["severity"].strip().upper()
        writer.writerow({
            "ioc_id": f"IOC-{index:03d}",
            "type": row["ioc_type"].strip().lower(),
            "value": row["ioc_value"].strip(),
            "source": SOURCE,
            "confidence": confidence_by_severity.get(severity, "0.70"),
            "first_seen": now,
            "last_seen": now,
            "threat_name": row["threat_name"].strip(),
            "severity": severity,
            "description": row["description"].strip(),
        })
print()
print("=" * 70)
print("NEXUS IoC NORMALIZATION")
print("=" * 70)
print(f"Input IoCs      : {len(rows)}")
print(f"Normalized IoCs : {len(rows)}")
print(f"Output          : {OUTPUT}")
print(f"Source          : {SOURCE}")
print("=" * 70)
