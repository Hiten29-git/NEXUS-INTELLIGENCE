import json
import os
from collections import Counter
from datetime import datetime, timedelta

import pandas as pd
import numpy as np

INPUT = "data/live/live_events.jsonl"
OUTPUT = "datasets/security_events/live_training_windows_v25.csv"

WINDOW_SECONDS = 60


def parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def safe_number(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def load_events():
    events = []

    if not os.path.exists(INPUT):
        raise FileNotFoundError(INPUT)

    with open(INPUT, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
                ts = parse_time(event.get("timestamp", ""))
                if ts is not None:
                    event["_time"] = ts
                    events.append(event)
            except Exception:
                continue

    events.sort(key=lambda x: x["_time"])
    return events


def build_window(events, start, end):
    rows = [
        e for e in events
        if start <= e["_time"] < end
    ]

    processes = [
        e.get("process")
        for e in rows
        if e.get("process")
    ]

    destinations = []
    ports = []

    for e in rows:
        destination = e.get("destination_ip")

        if destination:
            destinations.append(str(destination))

        port = e.get("destination_port")

        if port not in (None, "", "null"):
            ports.append(str(port))

    process_events = [
        e for e in rows
        if e.get("event_type") == "PROCESS_EXECUTION"
    ]

    network_events = [
        e for e in rows
        if e.get("event_type") == "NETWORK_CONNECTION"
    ]

    file_events = [
        e for e in rows
        if e.get("event_type") == "FILE_ACTIVITY"
    ]

    session_events = [
        e for e in rows
        if e.get("event_type") == "USER_SESSION"
    ]

    system_events = [
        e for e in rows
        if e.get("event_type") == "SYSTEM_ACTIVITY"
    ]

    ioc_matches = sum(
        1 for e in rows
        if bool(e.get("ioc_match", False))
    )

    # Activity burst: maximum number of events in any 10-second interval
    times = [e["_time"] for e in rows]

    process_times = [e["_time"] for e in process_events]
    network_times = [e["_time"] for e in network_events]

    def burst(times, seconds=10):
        if not times:
            return 0

        maximum = 0

        for t in times:
            count = sum(
                1 for x in times
                if t <= x < t + timedelta(seconds=seconds)
            )
            maximum = max(maximum, count)

        return maximum

    process_burst = burst(process_times)
    network_burst = burst(network_times)

    process_count = len(process_events)
    network_count = len(network_events)

    unique_processes = len(set(processes))
    unique_destinations = len(set(destinations))
    unique_ports = len(set(ports))

    process_diversity = (
        unique_processes / process_count * 100
        if process_count else 0
    )

    destination_diversity = (
        unique_destinations / network_count * 100
        if network_count else 0
    )

    process_network_ratio = (
        process_count / max(network_count, 1)
    )

    # New-process ratio
    process_counter = Counter(processes)

    new_process_count = sum(
        1 for p, c in process_counter.items()
        if c == 1
    )

    new_process_ratio = (
        new_process_count / unique_processes
        if unique_processes else 0
    )

    cpu_values = [
        safe_number(e.get("cpu_percent"))
        for e in system_events
        if e.get("cpu_percent") is not None
    ]

    memory_values = [
        safe_number(e.get("memory_percent"))
        for e in system_events
        if e.get("memory_percent") is not None
    ]

    avg_cpu = np.mean(cpu_values) if cpu_values else 0
    max_cpu = np.max(cpu_values) if cpu_values else 0

    avg_memory = np.mean(memory_values) if memory_values else 0
    max_memory = np.max(memory_values) if memory_values else 0

    return {
        "window_start": start.isoformat(),

        "total_events": len(rows),

        "process_execution_frequency": process_count,
        "network_connection_frequency": network_count,
        "file_activity_frequency": len(file_events),
        "session_activity_frequency": len(session_events),
        "system_activity_frequency": len(system_events),

        "unique_processes": unique_processes,
        "unique_destinations": unique_destinations,
        "unique_destination_ports": unique_ports,

        "process_burst_rate": process_burst,
        "network_burst_rate": network_burst,

        "process_diversity": round(process_diversity, 4),
        "destination_diversity": round(destination_diversity, 4),

        "process_network_ratio": round(process_network_ratio, 4),
        "new_process_ratio": round(new_process_ratio, 4),

        "ioc_matches": ioc_matches,

        "avg_cpu_percent": round(float(avg_cpu), 4),
        "max_cpu_percent": round(float(max_cpu), 4),

        "avg_memory_percent": round(float(avg_memory), 4),
        "max_memory_percent": round(float(max_memory), 4),
    }


def main():
    events = load_events()

    if not events:
        print("No valid events found.")
        return

    start = events[0]["_time"]
    last = events[-1]["_time"]

    rows = []

    current = start

    while current <= last:
        end = current + timedelta(seconds=WINDOW_SECONDS)

        row = build_window(events, current, end)

        if row["total_events"] > 0:
            rows.append(row)

        current = end

    df = pd.DataFrame(rows)

    os.makedirs(
        os.path.dirname(OUTPUT),
        exist_ok=True
    )

    df.to_csv(
        OUTPUT,
        index=False
    )

    print()
    print("=" * 60)
    print("NEXUS V5.25 LIVE FEATURE ENGINE")
    print("=" * 60)
    print(f"Raw events       : {len(events)}")
    print(f"Training windows : {len(df)}")
    print(f"Features         : {len(df.columns) - 1}")
    print()
    print("FEATURES")
    print("-" * 60)

    for column in df.columns:
        if column != "window_start":
            print(f"- {column}")

    print()
    print(f"Saved: {OUTPUT}")
    print("=" * 60)


if __name__ == "__main__":
    main()
