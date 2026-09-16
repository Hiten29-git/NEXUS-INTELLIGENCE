import json
from datetime import datetime, timedelta

from ai.activity_fingerprint import (
    build_fingerprint,
    build_baseline,
    save_baseline,
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


def make_windows(events):
    events.sort(
        key=lambda e: datetime.fromisoformat(e["timestamp"])
    )

    if not events:
        return []

    windows = []

    start = datetime.fromisoformat(events[0]["timestamp"])
    end = datetime.fromisoformat(events[-1]["timestamp"])

    while start <= end:
        stop = start + timedelta(seconds=WINDOW_SECONDS)

        window = [
            e for e in events
            if start <= datetime.fromisoformat(e["timestamp"]) < stop
        ]

        if window:
            windows.append(window)

        start = stop

    return windows


events = load_events()
windows = make_windows(events)

if not windows:
    raise SystemExit("No usable telemetry windows found.")

fingerprints = [
    build_fingerprint(window, WINDOW_SECONDS)
    for window in windows
]

baseline = build_baseline(fingerprints)

save_baseline(baseline)

print("=" * 60)
print("NEXUS BEHAVIORAL ACTIVITY FINGERPRINT BASELINE")
print("=" * 60)
print(f"Events         : {len(events)}")
print(f"60-sec windows : {len(windows)}")
print(f"Processes      : {len(baseline['processes'])}")
print(f"Destinations   : {len(baseline['destinations'])}")
print(f"Ports          : {len(baseline['destination_ports'])}")
print(f"Resources      : {len(baseline['resources'])}")
print(f"Active hours   : {baseline['active_hours']}")
print(f"Fingerprint ID : {baseline['fingerprint_hash']}")
print()
print("Saved:")
print("ai/models/nexus_activity_fingerprint_baseline.json")
