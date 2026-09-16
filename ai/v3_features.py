import json
import os
from collections import Counter
import numpy as np
import pandas as pd


INPUT = "data/live/live_events.jsonl"
OUTPUT = "datasets/security_events/v3_live_training_windows.csv"

WINDOW_SECONDS = 60


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_port(value):
    if value is None:
        return 0

    text = str(value)

    # Handles values such as:
    # 443
    # 10.20.30.40:443
    # [IPv6]:443
    if ":" in text:
        try:
            return int(text.rsplit(":", 1)[1])
        except ValueError:
            return 0

    return safe_int(text)


def load_events():
    events = []

    if not os.path.exists(INPUT):
        raise FileNotFoundError(f"Input file not found: {INPUT}")

    with open(INPUT, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                ts = pd.to_datetime(
                    event.get("timestamp"),
                    utc=True,
                    errors="coerce"
                )

                if pd.isna(ts):
                    continue

                event["_timestamp"] = ts
                events.append(event)

            except json.JSONDecodeError:
                continue

    return events


def calculate_features(window_events, previous_processes, previous_destinations):
    process_events = [
        e for e in window_events
        if e.get("event_type") == "PROCESS_EXECUTION"
    ]

    network_events = [
        e for e in window_events
        if e.get("event_type") == "NETWORK_CONNECTION"
    ]

    processes = [
        str(e.get("process"))
        for e in process_events
        if e.get("process")
    ]

    destinations = [
        str(e.get("destination_ip"))
        for e in network_events
        if e.get("destination_ip")
    ]

    ports = []

    for e in network_events:
        port = e.get("destination_port")

        if not port:
            port = parse_port(e.get("destination"))

        if port:
            ports.append(port)

    states = [
        str(e.get("status"))
        for e in network_events
        if e.get("status")
    ]

    # Basic counts
    process_count = len(process_events)
    network_count = len(network_events)

    # Diversity
    unique_processes = len(set(processes))
    unique_destinations = len(set(destinations))
    unique_ports = len(set(ports))

    process_diversity = (
        unique_processes / process_count
        if process_count else 0.0
    )

    destination_diversity = (
        unique_destinations / network_count
        if network_count else 0.0
    )

    # Burst behavior
    process_times = [
        e["_timestamp"].timestamp()
        for e in process_events
    ]

    network_times = [
        e["_timestamp"].timestamp()
        for e in network_events
    ]

    process_burst = 0

    if process_times:
        counts = Counter(
            int((t - min(process_times)) // 10)
            for t in process_times
        )
        process_burst = max(counts.values())

    network_burst = 0

    if network_times:
        counts = Counter(
            int((t - min(network_times)) // 10)
            for t in network_times
        )
        network_burst = max(counts.values())

    # New process / destination behavior
    current_processes = set(processes)
    current_destinations = set(destinations)

    new_processes = current_processes - previous_processes
    new_destinations = current_destinations - previous_destinations

    new_processes_ratio = (
        len(new_processes) / unique_processes
        if unique_processes else 0.0
    )

    new_destination_ratio = (
        len(new_destinations) / unique_destinations
        if unique_destinations else 0.0
    )

    # Process/network relationship
    process_network_ratio = (
        process_count / network_count
        if network_count else float(process_count)
    )

    # Connection-state features
    established_count = states.count("ESTABLISHED")
    syn_sent_count = states.count("SYN_SENT")
    closed_count = states.count("CLOSED")

    established_ratio = (
        established_count / network_count
        if network_count else 0.0
    )

    syn_ratio = (
        syn_sent_count / network_count
        if network_count else 0.0
    )

    closed_ratio = (
        closed_count / network_count
        if network_count else 0.0
    )

    # IoC count
    ioc_matches = sum(
        1 for e in window_events
        if bool(e.get("ioc_match"))
    )

    # Time-of-day features
    if window_events:
        first_time = min(e["_timestamp"] for e in window_events)
        hour = first_time.hour
        weekday = first_time.weekday()
    else:
        hour = 0
        weekday = 0

    return {
        "process_execution_frequency": process_count,
        "network_connection_frequency": network_count,
        "unique_processes": unique_processes,
        "unique_destinations": unique_destinations,
        "unique_destination_ports": unique_ports,

        "process_burst": process_burst,
        "network_burst": network_burst,

        "process_diversity": process_diversity,
        "destination_diversity": destination_diversity,

        "process_network_ratio": process_network_ratio,

        "new_processes_ratio": new_processes_ratio,
        "new_destination_ratio": new_destination_ratio,

        "established_ratio": established_ratio,
        "syn_sent_ratio": syn_ratio,
        "closed_ratio": closed_ratio,

        "ioc_matches": ioc_matches,

        "hour": hour,
        "weekday": weekday,
    }, current_processes, current_destinations


def build_dataset(events):
    if not events:
        raise RuntimeError("No valid events found.")

    events.sort(key=lambda x: x["_timestamp"])

    df = pd.DataFrame(events)

    start = df["_timestamp"].min()
    end = df["_timestamp"].max()

    print("=" * 70)
    print("NEXUS INTELLIGENCE - V3 FEATURE ENGINE")
    print("=" * 70)
    print(f"Raw events       : {len(events)}")
    print(f"Start             : {start}")
    print(f"End               : {end}")

    # Floor timestamps into one-minute windows
    df["window_start"] = df["_timestamp"].dt.floor("min")

    rows = []

    previous_processes = set()
    previous_destinations = set()

    for window_start, group in df.groupby("window_start", sort=True):

        features, current_processes, current_destinations = calculate_features(
            group.to_dict("records"),
            previous_processes,
            previous_destinations
        )

        row = {
            "window_start": window_start.isoformat()
        }

        row.update(features)

        rows.append(row)

        previous_processes = current_processes
        previous_destinations = current_destinations

    result = pd.DataFrame(rows)

    # Replace invalid numeric values
    numeric_columns = result.select_dtypes(
        include=[np.number]
    ).columns

    result[numeric_columns] = (
        result[numeric_columns]
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
    )

    os.makedirs(
        os.path.dirname(OUTPUT),
        exist_ok=True
    )

    result.to_csv(
        OUTPUT,
        index=False
    )

    return result


def main():
    events = load_events()

    result = build_dataset(events)

    print("\n" + "=" * 70)
    print("V3 DATASET CREATED")
    print("=" * 70)

    print(f"Windows          : {len(result)}")
    print(f"Features         : {len(result.columns) - 1}")

    print("\nFEATURE COLUMNS:")
    for column in result.columns:
        if column != "window_start":
            print(f"  - {column}")

    print("\nNETWORK SUMMARY:")
    print(
        result["network_connection_frequency"]
        .describe()
        .round(3)
        .to_string()
    )

    print(
        "\nWindows with network activity :",
        int(
            (
                result["network_connection_frequency"] > 0
            ).sum()
        )
    )

    print(
        "Windows with IoC matches       :",
        int(
            (
                result["ioc_matches"] > 0
            ).sum()
        )
    )

    print("\nSaved to:")
    print(OUTPUT)

    print("\nV3 FEATURE ENGINEERING COMPLETE")


if __name__ == "__main__":
    main()
