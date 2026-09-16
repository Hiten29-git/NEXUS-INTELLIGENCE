import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pandas as pd
import joblib


BASE = Path(__file__).resolve().parent.parent

EVENT_FILE = BASE / "data/live/live_events_v4.jsonl"
MODEL_FILE = BASE / "ai/models/v5_13_live_isolation_forest.joblib"
SCALER_FILE = BASE / "ai/models/v5_13_live_scaler.joblib"
SCHEMA_FILE = BASE / "ai/models/v5_13_live_schema.json"

OUTPUT_FILE = BASE / "data/v5_13/latest_live_monitor.json"

WINDOW_SECONDS = 60
REFRESH_SECONDS = 10


def load_events():
    events = []

    if not EVENT_FILE.exists():
        return events

    with EVENT_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                ts = event.get("timestamp")

                if not ts:
                    continue

                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))

                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)

                event["_dt"] = dt
                events.append(event)

            except Exception:
                continue

    return events


def build_features(events):
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=WINDOW_SECONDS)

    recent = [
        e for e in events
        if start <= e["_dt"] <= now
    ]

    process_events = []
    network_events = []
    ioc_events = []
    processes = set()
    destinations = set()

    for e in recent:

        event_type = str(e.get("event_type", "")).upper()

        process = e.get("process")

        destination = (
            e.get("destination_ip")
            or e.get("destination")
            or e.get("remote_address")
        )

        # Process telemetry
        if (
            "PROCESS" in event_type
            or process
        ):
            if process:
                process_events.append(e)
                processes.add(str(process))

        # Network telemetry
        if (
            "NETWORK" in event_type
            or e.get("destination_ip")
            or e.get("destination_port")
            or e.get("remote_address")
        ):
            network_events.append(e)

            if destination:
                destinations.add(str(destination))

        # IoC telemetry
        if bool(e.get("ioc_match", False)):
            ioc_events.append(e)

    features = {
        "process_execution_frequency": len(process_events),
        "network_connection_frequency": len(network_events),
        "unique_processes": len(processes),
        "unique_destinations": len(destinations),
        "ioc_matches": len(ioc_events),
    }

    return features, len(recent)


def severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def main():

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.13 REAL-TIME MONITOR")
    print("=" * 64)
    print()
    print("Event stream :", EVENT_FILE)
    print("Window       :", f"{WINDOW_SECONDS} seconds")
    print("Refresh      :", f"{REFRESH_SECONDS} seconds")
    print()
    print("Monitoring authorized local telemetry...")
    print("Press Ctrl+C to stop.")
    print()

    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    schema = None

    if SCHEMA_FILE.exists():
        try:
            schema_data = json.loads(SCHEMA_FILE.read_text())

            if isinstance(schema_data, list):
                schema = schema_data

            elif isinstance(schema_data, dict):
                schema = (
                    schema_data.get("features")
                    or schema_data.get("feature_names")
                    or schema_data.get("columns")
                )

        except Exception:
            schema = None

    if not schema:
        schema = [
            "process_execution_frequency",
            "network_connection_frequency",
            "unique_processes",
            "unique_destinations",
            "ioc_matches",
        ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    last_signature = None

    try:

        while True:

            events = load_events()

            features, event_count = build_features(events)

            row = {
                feature: float(features.get(feature, 0))
                for feature in schema
            }

            X = pd.DataFrame([row], columns=schema)

            X_scaled = scaler.transform(X)

            prediction = int(model.predict(X_scaled)[0])
            raw_score = float(model.decision_function(X_scaled)[0])

            # Convert Isolation Forest score into an easy-to-read
            # 0-100 anomaly score. Higher = more anomalous.
            anomaly_score = max(
                0.0,
                min(
                    100.0,
                    (0.20 - raw_score) * 100.0
                )
            )

            if prediction == -1:
                status = "ANOMALY"
            else:
                status = "NORMAL"

            sev = severity(anomaly_score)

            result = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "window_seconds": WINDOW_SECONDS,
                "events_in_window": event_count,
                "features": features,
                "status": status,
                "raw_isolation_score": round(raw_score, 6),
                "anomaly_score": round(anomaly_score, 2),
                "severity": sev,
                "model": "V5.13_LIVE_ISOLATION_FOREST",
            }

            OUTPUT_FILE.write_text(
                json.dumps(result, indent=2),
                encoding="utf-8"
            )

            signature = (
                status,
                sev,
                event_count,
                tuple(features.items()),
            )

            if signature != last_signature:

                print("\033[2J\033[H", end="")

                print("=" * 64)
                print("NEXUS INTELLIGENCE - V5.13 REAL-TIME MONITOR")
                print("=" * 64)

                print()
                print("LIVE STATUS")
                print("-" * 64)

                print(f"Events in 60s       : {event_count}")
                print(
                    f"Process executions  : "
                    f"{features['process_execution_frequency']}"
                )
                print(
                    f"Network connections : "
                    f"{features['network_connection_frequency']}"
                )
                print(
                    f"Unique processes    : "
                    f"{features['unique_processes']}"
                )
                print(
                    f"Unique destinations : "
                    f"{features['unique_destinations']}"
                )
                print(
                    f"IoC matches         : "
                    f"{features['ioc_matches']}"
                )

                print()
                print("AI DECISION")
                print("-" * 64)

                print(f"Status              : {status}")
                print(f"Raw Isolation score : {raw_score:.6f}")
                print(f"Anomaly score       : {anomaly_score:.2f}/100")
                print(f"Severity            : {sev}")

                print()
                print("Output")
                print("-" * 64)
                print(OUTPUT_FILE)

                last_signature = signature

            time.sleep(REFRESH_SECONDS)

    except KeyboardInterrupt:

        print()
        print()
        print("V5.13 LIVE MONITOR STOPPED.")


if __name__ == "__main__":
    main()
