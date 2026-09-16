import json
import csv
from pathlib import Path
RAW = Path("data/raw/realtime_security_events.jsonl")
OUT = Path("data/normalized/realtime_security_events.csv")
FIELDS = [
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
]
count = 0
errors = 0
with RAW.open("r", encoding="utf-8") as infile, OUT.open(
    "w", newline="", encoding="utf-8"
) as outfile:
    writer = csv.DictWriter(outfile, fieldnames=FIELDS)
    writer.writeheader()
    for line_number, line in enumerate(infile, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            row = {
                "event_id": event.get("event_id", ""),
                "timestamp": event.get("timestamp", ""),
                "user_id": event.get("user_id", ""),
                "device_id": event.get("device_id", ""),
                "event_type": event.get("event_type", ""),
                "source_ip": event.get("source_ip", ""),
                "source_port": event.get("source_port", ""),
                "destination_ip": event.get("destination_ip", ""),
                "destination_port": event.get("destination_port", ""),
                "process": event.get("process", ""),
                "parent_process": event.get("parent_process", ""),
                "resource": event.get("resource", ""),
                "ioc_match": event.get("ioc_match", False),
            }
            writer.writerow(row)
            count += 1
        except Exception as e:
            errors += 1
            print(f"ERROR line {line_number}: {e}")
print()
print("=" * 60)
print("NEXUS NORMALIZED DATA MIGRATION")
print("=" * 60)
print(f"Events written : {count}")
print(f"Errors         : {errors}")
print(f"Output         : {OUT}")
print("=" * 60)
