import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler


DATASET = "datasets/security_events/live_training_windows.csv"
MODEL_DIR = "ai/models"

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "ioc_matches",
]


def main():

    print("=" * 65)
    print("NEXUS INTELLIGENCE - V5.13 LIVE AI MODEL")
    print("=" * 65)

    if not os.path.exists(DATASET):
        print("ERROR: Live training dataset not found.")
        return

    df = pd.read_csv(DATASET)

    print()
    print("TRAINING DATA")
    print("-" * 65)
    print(f"Windows available : {len(df)}")

    missing = [f for f in FEATURES if f not in df.columns]

    if missing:
        print("ERROR: Missing features:", missing)
        return

    X = df[FEATURES].fillna(0).astype(float)

    print("Features          :", len(FEATURES))
    print()

    print("FEATURE SUMMARY")
    print("-" * 65)

    for feature in FEATURES:
        print(
            f"{feature:<32} "
            f"min={X[feature].min():.2f} "
            f"median={X[feature].median():.2f} "
            f"max={X[feature].max():.2f}"
        )

    # Robust scaling is less sensitive to unusual windows.
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # Unsupervised model:
    # The collected telemetry is treated as predominantly normal behavior.
    model = IsolationForest(
        n_estimators=300,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)

    anomaly_count = int(np.sum(predictions == -1))
    normal_count = int(np.sum(predictions == 1))

    os.makedirs(MODEL_DIR, exist_ok=True)

    model_path = os.path.join(
        MODEL_DIR,
        "v5_13_live_isolation_forest.joblib"
    )

    scaler_path = os.path.join(
        MODEL_DIR,
        "v5_13_live_scaler.joblib"
    )

    schema_path = os.path.join(
        MODEL_DIR,
        "v5_13_live_schema.json"
    )

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    with open(schema_path, "w") as f:
        json.dump(
            {
                "version": "V5.13",
                "features": FEATURES,
                "training_windows": len(df),
                "contamination": 0.05,
                "model": "IsolationForest",
                "scaler": "RobustScaler"
            },
            f,
            indent=2
        )

    print()
    print("MODEL RESULT")
    print("-" * 65)
    print(f"Normal windows    : {normal_count}")
    print(f"Anomalous windows : {anomaly_count}")
    print(
        f"Anomaly rate      : "
        f"{anomaly_count / len(df) * 100:.2f}%"
    )

    print()
    print("MODEL FILES")
    print("-" * 65)
    print(model_path)
    print(scaler_path)
    print(schema_path)

    print()
    print("=" * 65)
    print("V5.13 LIVE AI MODEL TRAINING COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()
