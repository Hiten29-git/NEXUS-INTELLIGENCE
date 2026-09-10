import os
import sys
import joblib
import numpy as np

from live_features import load_recent_events, build_features


MODEL_PATH = "ai/models/isolation_forest.joblib"
SCALER_PATH = "ai/models/feature_scaler.joblib"

WINDOW_SECONDS = 60


def load_models():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"Scaler not found: {SCALER_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    return model, scaler


def run_inference():

    model, scaler = load_models()

    events = load_recent_events(WINDOW_SECONDS)

    features = build_features(events)

    feature_order = [
        "login_frequency",
        "file_access_frequency",
        "process_execution_frequency",
        "network_connection_frequency",
        "ioc_matches"
    ]

    X = np.array([
        [features[name] for name in feature_order]
    ], dtype=float)

    X_scaled = scaler.transform(X)

    prediction = model.predict(X_scaled)[0]

    anomaly_score = model.decision_function(X_scaled)[0]

    is_anomaly = prediction == -1

    return {
        "events": len(events),
        "features": features,
        "prediction": prediction,
        "anomaly": is_anomaly,
        "anomaly_score": float(anomaly_score)
    }


if __name__ == "__main__":

    print("=" * 60)
    print("NEXUS INTELLIGENCE - LIVE AI INFERENCE")
    print("=" * 60)

    try:

        result = run_inference()

        print(f"\nWindow: {WINDOW_SECONDS} seconds")
        print(f"Events: {result['events']}")

        print("\nLIVE FEATURES")

        for key, value in result["features"].items():
            print(f"{key}: {value}")

        print("\nAI RESULT")
        print("-" * 40)

        if result["anomaly"]:
            print("STATUS: ANOMALY DETECTED")
        else:
            print("STATUS: NORMAL BEHAVIOR")

        print(
            f"Isolation Forest score: "
            f"{result['anomaly_score']:.4f}"
        )

        print("=" * 60)

    except Exception as e:

        print("\nERROR:")
        print(e)
        sys.exit(1)
