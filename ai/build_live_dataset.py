import json
import os
import pandas as pd
from datetime import datetime, timedelta


INPUT_FILE = "data/live/live_events.jsonl"
OUTPUT_FILE = "datasets/security_events/live_training_windows.csv"

WINDOW_SECONDS = 60


def load_events():

    events = []

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return events

    with open(INPUT_FILE, "r") as f:

        for line in f:

            try:
                event = json.loads(line)
                events.append(event)

            except json.JSONDecodeError:
                continue

    return events


def build_windows(events):

    if not events:
        return []

    parsed_events = []

    for event in events:

        try:
            event_time = datetime.fromisoformat(
                event["timestamp"]
            )

            event["_time"] = event_time
            parsed_events.append(event)

        except (KeyError, ValueError):
            continue

    if not parsed_events:
        return []

    parsed_events.sort(key=lambda x: x["_time"])

    start_time = parsed_events[0]["_time"]
    end_time = parsed_events[-1]["_time"]

    windows = []

    current = start_time

    while current < end_time:

        window_end = current + timedelta(
            seconds=WINDOW_SECONDS
        )

        window_events = [
            event
            for event in parsed_events
            if current <= event["_time"] < window_end
        ]

        if window_events:

            processes = {
                event.get("process")
                for event in window_events
                if event.get("process")
            }

            destinations = {
                event.get("destination_ip")
                for event in window_events
                if event.get("destination_ip")
            }

            process_count = sum(
                event.get("event_type") == "PROCESS_EXECUTION"
                for event in window_events
            )

            network_count = sum(
                event.get("event_type") == "NETWORK_CONNECTION"
                for event in window_events
            )

            ioc_count = sum(
                bool(event.get("ioc_match"))
                for event in window_events
            )

            windows.append({
                "window_start": current.isoformat(),
                "process_execution_frequency": process_count,
                "network_connection_frequency": network_count,
                "unique_processes": len(processes),
                "unique_destinations": len(destinations),
                "ioc_matches": ioc_count
            })

        current = window_end

    return windows


def main():

    events = load_events()

    windows = build_windows(events)

    if not windows:
        print("No usable windows were created.")
        return

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    df = pd.DataFrame(windows)

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("=" * 60)
    print("NEXUS LIVE TRAINING DATASET")
    print("=" * 60)

    print(f"Raw events : {len(events)}")
    print(f"Windows    : {len(df)}")

    print("\nFEATURES:")
    print(df.to_string(index=False))

    print("\nSaved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()
