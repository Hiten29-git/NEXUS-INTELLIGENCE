from pathlib import Path
import csv
EVENTS = Path("data/scenarios/ioc_test_events.csv")
IOCS = Path("data/iocs/ioc_database_normalized.csv")
OUTPUT = Path("data/final/ioc_test_enriched.csv")
with IOCS.open("r", encoding="utf-8", newline="") as f:
    iocs = list(csv.DictReader(f))
lookup = {
    (x["type"].strip().lower(), x["value"].strip().lower()): x
    for x in iocs
}
with EVENTS.open("r", encoding="utf-8", newline="") as f:
    events = list(csv.DictReader(f))
fields = list(events[0].keys()) + [
    "matched_ioc_id",
    "matched_ioc_type",
    "matched_ioc_value",
    "threat_name",
    "ioc_severity",
    "ioc_confidence",
    "ioc_source",
]
matches = 0
with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for event in events:
        matched = None
        candidates = [
            ("ip", event.get("source_ip", "")),
            ("ip", event.get("destination_ip", "")),
            ("process", event.get("process", "")),
            ("hash", event.get("resource", "")),
            ("domain", event.get("resource", "")),
        ]
        for ioc_type, value in candidates:
            key = (ioc_type, value.strip().lower())
            if key in lookup:
                matched = lookup[key]
                break
        row = dict(event)
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
        else:
            for field in fields[len(events[0].keys()):]:
                row[field] = ""
        writer.writerow(row)
print()
print("=" * 70)
print("NEXUS IoC TEST ENRICHMENT")
print("=" * 70)
print(f"Test events : {len(events)}")
print(f"IoC matches : {matches}")
print(f"Output      : {OUTPUT}")
print("=" * 70)
