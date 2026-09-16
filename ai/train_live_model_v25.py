import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


INPUT = "datasets/security_events/live_training_windows_v25.csv"
MODEL_DIR = "ai/models"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "nexus_v25_live_isolation_forest.joblib"
)

SCALER_FILE = os.path.join(
    MODEL_DIR,
    "nexus_v25_live_scaler.joblib"
)

SCHEMA_FILE = os.path.join(
    MODEL_DIR,
    "nexus_v25_live_feature_schema.json"
)

STATS_FILE = os.path.join(
    MODEL_DIR,
    "nexus_v25_live_baseline.json"
)


def main():

    print()
    print("=" * 65)
    print("NEXUS INTELLIGENCE - V5.25 AI TRAINING")
    print("=" * 65)

    if not os.path.exists(INPUT):
        print()
        print("ERROR: Training dataset not found:")
        print(INPUT)
        return

    df = pd.read_csv(INPUT)

    if len(df) < 50:
        print()
        print("ERROR: Not enough training windows.")
        print(f"Found: {len(df)}")
        print("Need at least 50.")
        return

    # Timestamp is metadata, not an ML feature
    excluded = ["window_start"]

    feature_columns = [
        column
        for column in df.columns
        if column not in excluded
    ]

    # Keep only numeric features
    feature_columns = [
        column
        for column in feature_columns
        if pd.api.types.is_numeric_dtype(df[column])
    ]

    X = df[feature_columns].copy()

    # Replace invalid values
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    # ---------------------------------------------------------
    # Remove completely constant features
    # ---------------------------------------------------------

    useful_features = []

    for column in X.columns:

        if X[column].nunique() > 1:
            useful_features.append(column)

    X = X[useful_features]

    feature_columns = useful_features

    print()
    print(f"Training windows : {len(X)}")
    print(f"ML features      : {len(feature_columns)}")

    # ---------------------------------------------------------
    # Feature statistics
    # ---------------------------------------------------------

    means = X.mean()
    stds = X.std().replace(0, 1)

    medians = X.median()
    q25 = X.quantile(0.25)
    q75 = X.quantile(0.75)

    # ---------------------------------------------------------
    # Scaling
    # ---------------------------------------------------------

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    # ---------------------------------------------------------
    # Isolation Forest
    # ---------------------------------------------------------

    model = IsolationForest(
        n_estimators=400,
        max_samples="auto",
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    # ---------------------------------------------------------
    # Training statistics
    # ---------------------------------------------------------

    raw_scores = model.decision_function(X_scaled)

    anomaly_labels = model.predict(X_scaled)

    anomaly_count = int(
        np.sum(anomaly_labels == -1)
    )

    normal_count = int(
        np.sum(anomaly_labels == 1)
    )

    # ---------------------------------------------------------
    # Save models
    # ---------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    joblib.dump(
        scaler,
        SCALER_FILE
    )

    # ---------------------------------------------------------
    # Save feature schema
    # ---------------------------------------------------------

    schema = {
        "version": "V5.25",
        "model_type": "IsolationForest",
        "window_seconds": 60,
        "feature_count": len(feature_columns),
        "features": feature_columns
    }

    with open(
        SCHEMA_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            schema,
            f,
            indent=2
        )

    # ---------------------------------------------------------
    # Save behavioral baseline
    # ---------------------------------------------------------

    baseline = {
        "version": "V5.25",
        "windows": int(len(X)),
        "features": {},

        "model": {
            "n_estimators": 400,
            "contamination": 0.05,
            "random_state": 42
        },

        "training_result": {
            "normal_windows": normal_count,
            "anomaly_windows": anomaly_count,
            "score_min": float(np.min(raw_scores)),
            "score_max": float(np.max(raw_scores)),
            "score_mean": float(np.mean(raw_scores))
        }
    }

    for column in feature_columns:

        baseline["features"][column] = {
            "mean": float(means[column]),
            "std": float(stds[column]),
            "median": float(medians[column]),
            "q25": float(q25[column]),
            "q75": float(q75[column])
        }

    with open(
        STATS_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            baseline,
            f,
            indent=2
        )

    # ---------------------------------------------------------
    # Display
    # ---------------------------------------------------------

    print()
    print("=" * 65)
    print("TRAINING COMPLETE")
    print("=" * 65)

    print()
    print("MODEL")
    print("-" * 65)

    print("Algorithm         : Isolation Forest")
    print("Estimators        : 400")
    print("Contamination     : 5%")
    print("Window            : 60 seconds")
    print(f"Training windows  : {len(X)}")
    print(f"Features          : {len(feature_columns)}")

    print()
    print("TRAINING DISTRIBUTION")
    print("-" * 65)

    print(f"Normal windows    : {normal_count}")
    print(f"Anomaly windows   : {anomaly_count}")

    print()
    print("FEATURES")
    print("-" * 65)

    for index, feature in enumerate(
        feature_columns,
        start=1
    ):
        print(f"{index:02d}. {feature}")

    print()
    print("SAVED FILES")
    print("-" * 65)

    print(MODEL_FILE)
    print(SCALER_FILE)
    print(SCHEMA_FILE)
    print(STATS_FILE)

    print()
    print("=" * 65)
    print("NEXUS V5.25 AI MODEL READY")
    print("=" * 65)


if __name__ == "__main__":
    main()
