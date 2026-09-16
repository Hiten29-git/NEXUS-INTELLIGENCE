import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta


EVENT_FILE = "data/live/live_events.jsonl"

MODEL_FILE = "ai/models/nexus_v25_live_isolation_forest.joblib"
SCALER_FILE = "ai/models/nexus_v25_live_scaler.joblib"
SCHEMA_FILE = "ai/models/nexus_v25_live_feature_schema.json"
BASELINE_FILE = "ai/models/nexus_v25_live_baseline.json"

WINDOW_SECONDS = 60


def parse_time(value):
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except Exception:
        return None


def load_recent_events():
    if not os.path.exists(EVENT_FILE):
        return []

    events = []

    with open(EVENT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
                ts = parse_time(event.get("timestamp", ""))

                if ts:
                    event["_time"] = ts
                    events.append(event)

            except Exception:
                continue

    if not events:
        return []

    latest = max(
        e["_time"] for e in events
    )

    cutoff = latest - timedelta(
        seconds=WINDOW_SECONDS
    )

    return [
        e for e in events
        if e["_time"] >= cutoff
    ]


def burst(times, seconds=10):
    if not times:
        return 0

    maximum = 0

    for t in times:
        count = sum(
            1
            for x in times
            if t <= x < t + timedelta(seconds=seconds)
        )

        maximum = max(
            maximum,
            count
        )

    return maximum


def build_features(events):

    process_events = [
        e for e in events
        if e.get("event_type") == "PROCESS_EXECUTION"
    ]

    network_events = [
        e for e in events
        if e.get("event_type") == "NETWORK_CONNECTION"
    ]

    file_events = [
        e for e in events
        if e.get("event_type") == "FILE_ACTIVITY"
    ]

    session_events = [
        e for e in events
        if e.get("event_type") == "USER_SESSION"
    ]

    system_events = [
        e for e in events
        if e.get("event_type") == "SYSTEM_ACTIVITY"
    ]

    processes = [
        str(e.get("process"))
        for e in events
        if e.get("process")
    ]

    destinations = [
        str(e.get("destination_ip"))
        for e in events
        if e.get("destination_ip")
    ]

    ports = [
        str(e.get("destination_port"))
        for e in events
        if e.get("destination_port")
        not in (None, "", "null")
    ]

    process_times = [
        e["_time"]
        for e in process_events
    ]

    network_times = [
        e["_time"]
        for e in network_events
    ]

    process_count = len(process_events)
    network_count = len(network_events)

    unique_processes = len(
        set(processes)
    )

    unique_destinations = len(
        set(destinations)
    )

    unique_ports = len(
        set(ports)
    )

    process_diversity = (
        unique_processes /
        process_count * 100
        if process_count else 0
    )

    destination_diversity = (
        unique_destinations /
        network_count * 100
        if network_count else 0
    )

    process_counter = {}

    for p in processes:
        process_counter[p] = (
            process_counter.get(p, 0) + 1
        )

    new_process_count = sum(
        1
        for count in process_counter.values()
        if count == 1
    )

    new_process_ratio = (
        new_process_count /
        unique_processes
        if unique_processes else 0
    )

    cpu_values = []

    memory_values = []

    for e in system_events:

        try:
            if e.get("cpu_percent") is not None:
                cpu_values.append(
                    float(e["cpu_percent"])
                )
        except Exception:
            pass

        try:
            if e.get("memory_percent") is not None:
                memory_values.append(
                    float(e["memory_percent"])
                )
        except Exception:
            pass

    ioc_matches = sum(
        1
        for e in events
        if bool(e.get("ioc_match", False))
    )

    features = {
        "total_events": len(events),

        "process_execution_frequency":
            process_count,

        "network_connection_frequency":
            network_count,

        "file_activity_frequency":
            len(file_events),

        "session_activity_frequency":
            len(session_events),

        "system_activity_frequency":
            len(system_events),

        "unique_processes":
            unique_processes,

        "unique_destinations":
            unique_destinations,

        "unique_destination_ports":
            unique_ports,

        "process_burst_rate":
            burst(process_times),

        "network_burst_rate":
            burst(network_times),

        "process_diversity":
            process_diversity,

        "destination_diversity":
            destination_diversity,

        "process_network_ratio":
            process_count /
            max(network_count, 1),

        "new_process_ratio":
            new_process_ratio,

        "ioc_matches":
            ioc_matches,

        "avg_cpu_percent":
            np.mean(cpu_values)
            if cpu_values else 0,

        "max_cpu_percent":
            np.max(cpu_values)
            if cpu_values else 0,

        "avg_memory_percent":
            np.mean(memory_values)
            if memory_values else 0,

        "max_memory_percent":
            np.max(memory_values)
            if memory_values else 0,
    }

    return features


def calculate_behavior_score(
    features,
    baseline
):

    scores = []

    for name, value in features.items():

        if name not in baseline:
            continue

        stats = baseline[name]

        mean = stats["mean"]
        std = max(
            stats["std"],
            0.0001
        )

        z = abs(
            value - mean
        ) / std

        scores.append(
            min(z, 5.0)
        )

    if not scores:
        return 0.0

    average = np.mean(scores)

    return min(
        average / 5.0 * 100,
        100
    )


def threat_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


def main():

    print()
    print("=" * 65)
    print("NEXUS INTELLIGENCE - V5.25 LIVE AI")
    print("=" * 65)

    events = load_recent_events()

    if not events:
        print()
        print("No live telemetry available.")
        return

    model = joblib.load(
        MODEL_FILE
    )

    scaler = joblib.load(
        SCALER_FILE
    )

    with open(
        SCHEMA_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        schema = json.load(f)

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        baseline_data = json.load(f)

    feature_columns = schema["features"]

    features = build_features(
        events
    )

    row = pd.DataFrame(
        [[
            features.get(
                column,
                0
            )
            for column in feature_columns
        ]],
        columns=feature_columns
    )

    row = row.replace(
        [np.inf, -np.inf],
        np.nan
    ).fillna(0)

    scaled = scaler.transform(
        row
    )

    prediction = model.predict(
        scaled
    )[0]

    model_score = model.decision_function(
        scaled
    )[0]

    baseline_score = calculate_behavior_score(
        features,
        baseline_data["features"]
    )

    # Convert Isolation Forest score
    # into a simple 0-100 anomaly indicator.
    model_anomaly_score = max(
        0,
        min(
            100,
            50 - (model_score * 100)
        )
    )

    # Ensemble:
    # 60% ML + 40% behavioral deviation
    combined_score = (
        model_anomaly_score * 0.60
        +
        baseline_score * 0.40
    )

    if features["ioc_matches"] > 0:
        combined_score = min(
            100,
            combined_score + 20
        )

    level = threat_level(
        combined_score
    )

    if prediction == -1:
        ml_status = "ANOMALY"
    else:
        ml_status = "NORMAL"

    print()
    print("LIVE WINDOW")
    print("-" * 65)

    print(
        f"Events analyzed     : {len(events)}"
    )

    print(
        f"Window               : {WINDOW_SECONDS} seconds"
    )

    print()
    print("AI DETECTION")
    print("-" * 65)

    print(
        f"ML status            : {ml_status}"
    )

    print(
        f"Isolation score      : {model_score:.4f}"
    )

    print(
        f"ML anomaly score     : "
        f"{model_anomaly_score:.2f}/100"
    )

    print(
        f"Behavior score       : "
        f"{baseline_score:.2f}/100"
    )

    print(
        f"Combined threat      : "
        f"{combined_score:.2f}/100"
    )

    print(
        f"Threat level         : {level}"
    )

    print()
    print("LIVE FEATURES")
    print("-" * 65)

    for name in feature_columns:

        print(
            f"{name:35s}: "
            f"{features.get(name, 0):.2f}"
        )

    print()
    print("DECISION")
    print("-" * 65)

    if level in ("CRITICAL", "HIGH"):

        print("Action               : INVESTIGATE")
        print("Priority             : HIGH")
        print("Human approval       : REQUIRED")

    elif level == "MEDIUM":

        print("Action               : INVESTIGATE")
        print("Priority             : MEDIUM")
        print("Human approval       : REQUIRED")

    else:

        print("Action               : ALLOW")
        print("Priority             : NORMAL")
        print("Human approval       : NOT REQUIRED")

    print()
    print("=" * 65)
    print("V5.25 LIVE AI ANALYSIS COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()
