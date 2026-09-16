import csv
from pathlib import Path
EVENTS = Path("data/normalized/realtime_security_events.csv")
IOCS = Path("data/iocs/ioc_database_normalized.csv")
OUTPUT = Path("data/final/enriched_security_events.csv")
with IOCS.open("r", encoding="utf-8", newline="") as f:
    ioc_rows = list(csv.DictReader(f))
ioc_lookup = {}
for ioc in ioc_rows:
    key = (ioc["type"].strip().lower(), ioc["value"].strip().lower())
    ioc_lookup[key] = ioc
event_fields = [
    "event_id",
    "timestamp",
    "user_id",
    "device_id",
    "event_type",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "process",
    "parent_process",
    "resource",
    "ioc_match",
    "matched_ioc_id",
    "matched_ioc_type",
    "matched_ioc_value",
    "threat_name",
    "ioc_severity",
    "ioc_confidence",
    "ioc_source",
]
count = 0
matches = 0
with EVENTS.open("r", encoding="utf-8", newline="") as infile, \
     OUTPUT.open("w", encoding="utf-8", newline="") as outfile:
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=event_fields)
    writer.writeheader()
    for event in reader:
        matched = None
        candidates = [
            ("ip", event.get("source_ip", "")),
            ("ip", event.get("destination_ip", "")),
            ("process", event.get("process", "")),
            ("hash", event.get("resource", "")),
            ("domain", event.get("destination_ip", "")),
            ("domain", event.get("resource", "")),
        ]
        for ioc_type, value in candidates:
            value = value.strip().lower()
            if not value:
                continue
            key = (ioc_type, value)
            if key in ioc_lookup:
                matched = ioc_lookup[key]
                break
        row = {field: event.get(field, "") for field in event_fields}
        if matched:
            row["ioc_match"] = "True"
            row["matched_ioc_id"] = matched["ioc_id"]
            row["matched_ioc_type"] = matched["type"]
            row["matched_ioc_value"] = matched["value"]
            row["threat_name"] = matched["threat_name"]
            row["ioc_severity"] = matched["severity"]
            row["ioc_confidence"] = matched["confidence"]
            row["ioc_source"] = matched["source"]
            matches += 1
        writer.writerow(row)
        count += 1
print()
print("=" * 70)
print("NEXUS IoC ENRICHMENT")
print("=" * 70)
print(f"Events processed : {count}")
print(f"IoC matches      : {matches}")
print(f"Output           : {OUTPUT}")
print("=" * 70)
