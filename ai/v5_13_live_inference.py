import os
import json
import joblib
import numpy as np
import pandas as pd


DATASET = "datasets/security_events/live_training_windows.csv"

MODEL = "ai/models/v5_13_live_isolation_forest.joblib"
SCALER = "ai/models/v5_13_live_scaler.joblib"

OUTPUT_DIR = "data/v5_13"

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "ioc_matches",
]


def main():

    print("=" * 65)
    print("NEXUS INTELLIGENCE - V5.13 LIVE INFERENCE")
    print("=" * 65)

    if not os.path.exists(DATASET):
        print("ERROR: Live dataset not found.")
        return

    if not os.path.exists(MODEL):
        print("ERROR: V5.13 model not found.")
        return

    df = pd.read_csv(DATASET)

    if len(df) == 0:
        print("ERROR: No telemetry windows available.")
        return

    latest = df.iloc[-1]

    X = pd.DataFrame(
        [[latest[f] for f in FEATURES]],
        columns=FEATURES
    ).astype(float)

    model = joblib.load(MODEL)
    scaler = joblib.load(SCALER)

    X_scaled = scaler.transform(X)

    prediction = int(model.predict(X_scaled)[0])
    raw_score = float(model.decision_function(X_scaled)[0])

    status = (
        "ANOMALY"
        if prediction == -1
        else "NORMAL"
    )

    # Convert Isolation Forest score into a readable
    # relative anomaly indicator.
    anomaly_score = float(
        np.clip(50 - (raw_score * 100), 0, 100)
    )

    if anomaly_score >= 80:
        severity = "CRITICAL"
    elif anomaly_score >= 60:
        severity = "HIGH"
    elif anomaly_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    result = {
        "version": "V5.13",
        "window_start": str(latest["window_start"]),
        "status": status,
        "severity": severity,
        "raw_isolation_score": round(raw_score, 4),
        "anomaly_score": round(anomaly_score, 2),
        "features": {
            f: float(latest[f])
            for f in FEATURES
        }
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output = os.path.join(
        OUTPUT_DIR,
        "latest_live_inference.json"
    )

    with open(output, "w") as f:
        json.dump(result, f, indent=2)

    print()
    print("LATEST LIVE WINDOW")
    print("-" * 65)
    print("Window:", latest["window_start"])

    print()
    print("LIVE FEATURES")
    print("-" * 65)

    for f in FEATURES:
        print(f"{f:<32}: {latest[f]}")

    print()
    print("AI RESULT")
    print("-" * 65)
    print(f"Status             : {status}")
    print(f"Raw Isolation score: {raw_score:.4f}")
    print(f"Anomaly score      : {anomaly_score:.2f}/100")
    print(f"Severity           : {severity}")

    print()
    print("Saved:", output)

    print()
    print("=" * 65)
    print("V5.13 LIVE INFERENCE COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()
