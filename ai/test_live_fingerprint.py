import json
from datetime import datetime, timedelta

from ai.activity_fingerprint import (
    build_fingerprint,
    load_fingerprint,
    compare_fingerprint,
)

LIVE_FILE = "data/live/live_events.jsonl"
WINDOW_SECONDS = 60


def load_events():
    events = []

    with open(LIVE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
                datetime.fromisoformat(event["timestamp"])
                events.append(event)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue

    return events


events = load_events()

if not events:
    raise SystemExit("No telemetry found.")

events.sort(
    key=lambda e: datetime.fromisoformat(e["timestamp"])
)

latest = datetime.fromisoformat(events[-1]["timestamp"])

start = latest - timedelta(seconds=WINDOW_SECONDS)

current_events = [
    e for e in events
    if start <= datetime.fromisoformat(e["timestamp"]) <= latest
]

baseline = load_fingerprint("ai/models/nexus_activity_fingerprint_baseline.json")

current = build_fingerprint(
    current_events,
    WINDOW_SECONDS
)

result = compare_fingerprint(
    current,
    baseline
)

print("=" * 60)
print("NEXUS LIVE ACTIVITY FINGERPRINT TEST")
print("=" * 60)

print(f"Latest event      : {latest.isoformat()}")
print(f"Window start      : {start.isoformat()}")
print(f"Events in window  : {len(current_events)}")

print()
print(
    f"Fingerprint drift : "
    f"{result['drift_score']}/100"
)

print(
    f"Status            : "
    f"{result['status']}"
)

print()
print("NEW PROCESSES")

for item in result["new_processes"][:10]:
    print(f"  - {item}")

print()
print("NEW DESTINATIONS")

for item in result["new_destinations"][:10]:
    print(f"  - {item}")

print()
print("NEW RESOURCES")

for item in result["new_resources"][:10]:
    print(f"  - {item}")

print()
print("CATEGORICAL SIMILARITY")

for key, value in result["categorical_similarity"].items():
    print(f"  {key}: {value}")

print()
print("NUMERIC DEVIATION")

for key, value in result["numeric_deviation"].items():
    print(f"  {key}: {value}")
