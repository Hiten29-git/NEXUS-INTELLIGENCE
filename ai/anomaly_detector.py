import os
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_engineering import (
    load_events,
    build_features,
    FEATURE_COLUMNS,
)


DATASET = "datasets/security_events/security_events.csv"
MODEL_DIR = "ai/models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "isolation_forest.joblib"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "feature_scaler.joblib"
)


def train_model(features: pd.DataFrame):

    X = features[FEATURE_COLUMNS]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.10,
        random_state=42
    )

    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    anomaly_scores = model.decision_function(X_scaled)

    results = features.copy()

    results["anomaly_label"] = predictions
    results["anomaly_score"] = anomaly_scores

    return model, scaler, results


def main():

    print("\n===== NEXUS ANOMALY DETECTOR =====")

    events = load_events(DATASET)

    features = build_features(events)

    print(f"Loaded events: {len(events)}")
    print(f"User profiles: {len(features)}")

    model, scaler, results = train_model(features)

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    results.to_csv(
        "datasets/security_events/anomaly_results.csv",
        index=False
    )

    normal_count = (
        results["anomaly_label"] == 1
    ).sum()

    anomaly_count = (
        results["anomaly_label"] == -1
    ).sum()

    print("\n===== DETECTION RESULTS =====")

    print(f"Normal profiles: {normal_count}")
    print(f"Anomalous profiles: {anomaly_count}")

    print("\n===== TOP 10 ANOMALOUS USERS =====")

    suspicious = results.sort_values(
        "anomaly_score"
    ).head(10)

    print(
        suspicious[
            [
                "user_id",
                "login_frequency",
                "file_access_frequency",
                "process_execution_frequency",
                "network_connection_frequency",
                "ioc_matches",
                "anomaly_score",
                "anomaly_label"
            ]
        ].to_string(index=False)
    )

    print("\n===== MODEL FILES =====")
    print(MODEL_PATH)
    print(SCALER_PATH)

    print("\nAnomaly detection completed successfully.")


if __name__ == "__main__":
    main()
