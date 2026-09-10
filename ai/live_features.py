import json
from collections import Counter
from datetime import datetime, timedelta


LIVE_FILE = "data/live/live_events.jsonl"


def load_recent_events(window_seconds=60):
    events = []

    try:
        with open(LIVE_FILE, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []

    if not events:
        return []

    now = datetime.fromisoformat(events[-1]["timestamp"])
    cutoff = now - timedelta(seconds=window_seconds)

    recent = []

    for event in events:
        try:
            event_time = datetime.fromisoformat(event["timestamp"])

            if event_time >= cutoff:
                recent.append(event)

        except (KeyError, ValueError):
            continue

    return recent


def build_features(events):
    if not events:
        return {
            "login_frequency": 0,
            "file_access_frequency": 0,
            "process_execution_frequency": 0,
            "network_connection_frequency": 0,
            "ioc_matches": 0
        }

    counts = Counter(
        event.get("event_type")
        for event in events
    )

    ioc_matches = sum(
        1
        for event in events
        if event.get("ioc_match") is True
    )

    return {
        "login_frequency": counts["LOGIN"],
        "file_access_frequency": counts["FILE_ACCESS"],
        "process_execution_frequency": counts["PROCESS_EXECUTION"],
        "network_connection_frequency": counts["NETWORK_CONNECTION"],
        "ioc_matches": ioc_matches
    }


if __name__ == "__main__":

    events = load_recent_events(60)

    features = build_features(events)

    print("=" * 50)
    print("NEXUS LIVE FEATURE ENGINE")
    print("=" * 50)

    print(f"Events in window: {len(events)}")

    print("\nLIVE FEATURES:")

    for key, value in features.items():
        print(f"{key}: {value}")
