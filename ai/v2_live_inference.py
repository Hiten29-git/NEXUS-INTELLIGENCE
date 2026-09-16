import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from collections import Counter
from datetime import datetime, timezone


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EVENT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "live",
    "live_events.jsonl"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ai",
    "models",
    "v2"
)

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "process_burst",
    "network_burst",
    "process_diversity",
    "destination_diversity",
    "process_network_ratio",
    "log_process",
    "log_network",
]

WINDOW_SECONDS = 60
POLL_SECONDS = 5


def load_models():
    isolation = joblib.load(
        os.path.join(MODEL_DIR, "isolation_forest_v2.joblib")
    )

    lof = joblib.load(
        os.path.join(MODEL_DIR, "lof_v2.joblib")
    )

    ocsvm = joblib.load(
        os.path.join(MODEL_DIR, "one_class_svm_v2.joblib")
    )

    scaler = joblib.load(
        os.path.join(MODEL_DIR, "robust_scaler_v2.joblib")
    )

    return isolation, lof, ocsvm, scaler


def read_recent_events():
    if not os.path.exists(EVENT_FILE):
        return []

    cutoff = time.time() - WINDOW_SECONDS
    events = []

    with open(EVENT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)

                timestamp = event.get("timestamp")

                if timestamp:
                    dt = datetime.fromisoformat(
                        timestamp.replace("Z", "+00:00")
                    )

                    event_time = dt.timestamp()

                    if event_time >= cutoff:
                        events.append(event)

            except Exception:
                continue

    return events


def calculate_features(events):
    processes = []
    destinations = []

    process_count = 0
    network_count = 0
    ioc_count = 0

    for event in events:

        event_type = event.get("event_type")

        if event_type == "PROCESS_EXECUTION":
            process_count += 1

            process = event.get("process")

            if process:
                processes.append(process)

        elif event_type == "NETWORK_CONNECTION":
            network_count += 1

            destination = event.get("destination_ip")

            if destination:
                destinations.append(destination)

        if event.get("ioc_match") is True:
            ioc_count += 1

    unique_processes = len(set(processes))
    unique_destinations = len(set(destinations))

    process_diversity = (
        unique_processes / process_count
        if process_count > 0
        else 0
    )

    destination_diversity = (
        unique_destinations / network_count
        if network_count > 0
        else 0
    )

    process_network_ratio = (
        process_count / network_count
        if network_count > 0
        else process_count
    )

    features = {
        "process_execution_frequency": process_count,
        "network_connection_frequency": network_count,
        "unique_processes": unique_processes,
        "unique_destinations": unique_destinations,

        "process_burst": process_count / WINDOW_SECONDS,
        "network_burst": network_count / WINDOW_SECONDS,

        "process_diversity": process_diversity,
        "destination_diversity": destination_diversity,

        "process_network_ratio": process_network_ratio,

        "log_process": np.log1p(process_count),
        "log_network": np.log1p(network_count),
    }

    return pd.DataFrame(
        [[features[x] for x in FEATURES]],
        columns=FEATURES
    ), features, ioc_count


def model_predictions(X, isolation, lof, ocsvm, scaler):

    X_scaled = scaler.transform(X)

    if_anomaly = isolation.predict(X_scaled)[0] == -1
    lof_anomaly = lof.predict(X_scaled)[0] == -1
    svm_anomaly = ocsvm.predict(X_scaled)[0] == -1

    votes = int(if_anomaly) + int(lof_anomaly) + int(svm_anomaly)

    ensemble_anomaly = votes >= 2

    return (
        if_anomaly,
        lof_anomaly,
        svm_anomaly,
        ensemble_anomaly,
        votes
    )


def calculate_risk(features, ensemble_anomaly, ioc_count):

    risk = 0.0
    reasons = []

    process_count = features["process_execution_frequency"]
    network_count = features["network_connection_frequency"]
    unique_processes = features["unique_processes"]
    unique_destinations = features["unique_destinations"]

    if ensemble_anomaly:
        risk += 45
        reasons.append("AI ensemble anomaly")

    if process_count >= 10:
        risk += 15
        reasons.append("high process activity")

    if network_count >= 5:
        risk += 15
        reasons.append("high network activity")

    if unique_processes >= 5:
        risk += 10
        reasons.append("high process diversity")

    if unique_destinations >= 5:
        risk += 10
        reasons.append("multiple destinations")

    if ioc_count > 0:
        risk += min(ioc_count * 20, 40)
        reasons.append("IOC match detected")

    risk = min(risk, 100)

    if risk >= 80:
        level = "CRITICAL"
    elif risk >= 60:
        level = "HIGH"
    elif risk >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return risk, level, reasons


def main():

    print("=" * 60)
    print("NEXUS INTELLIGENCE - V2 LIVE AI")
    print("=" * 60)

    isolation, lof, ocsvm, scaler = load_models()

    print("Models loaded successfully")
    print("Mode   : REAL-TIME")
    print("Window : 60 seconds")
    print("Press Ctrl+C to stop")
    print()

    last_signature = None

    try:

        while True:

            events = read_recent_events()

            X, features, ioc_count = calculate_features(events)

            signature = tuple(X.iloc[0].tolist())

            if signature != last_signature:

                (
                    if_anomaly,
                    lof_anomaly,
                    svm_anomaly,
                    ensemble_anomaly,
                    votes
                ) = model_predictions(
                    X,
                    isolation,
                    lof,
                    ocsvm,
                    scaler
                )

                risk, level, reasons = calculate_risk(
                    features,
                    ensemble_anomaly,
                    ioc_count
                )

                print("=" * 60)
                print(
                    datetime.now(timezone.utc)
                    .astimezone()
                    .strftime("%Y-%m-%d %H:%M:%S")
                )

                print(f"Events              : {len(events)}")
                print(
                    f"Processes           : "
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

                print(f"IOC matches         : {ioc_count}")

                print()
                print("MODEL RESULTS")
                print(
                    f"Isolation Forest : "
                    f"{'ANOMALY' if if_anomaly else 'NORMAL'}"
                )

                print(
                    f"LOF              : "
                    f"{'ANOMALY' if lof_anomaly else 'NORMAL'}"
                )

                print(
                    f"One-Class SVM     : "
                    f"{'ANOMALY' if svm_anomaly else 'NORMAL'}"
                )

                print(
                    f"Ensemble          : "
                    f"{'ANOMALY' if ensemble_anomaly else 'NORMAL'} "
                    f"({votes}/3 votes)"
                )

                print()
                print(f"RISK SCORE        : {risk:.1f}/100")
                print(f"RISK LEVEL        : {level}")

                if reasons:
                    print("Reasons            : " + ", ".join(reasons))
                else:
                    print("Reasons            : normal baseline")

                last_signature = signature

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:

        print()
        print("=" * 60)
        print("NEXUS V2 LIVE AI STOPPED")
        print("=" * 60)


if __name__ == "__main__":
    main()
